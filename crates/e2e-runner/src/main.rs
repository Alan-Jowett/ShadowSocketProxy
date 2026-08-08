// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Runs the shared Windows/WSL TCP deployment validation against the control API.

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
/// Reports that the deployment driver requires its Windows TLS-PSK build.
fn main() {
    eprintln!("shadow-socket-proxy-e2e-runner requires Windows and the tls-psk feature");
    std::process::exit(1);
}

#[cfg(all(target_os = "windows", feature = "tls-psk"))]
/// Contains the Windows implementation that configures and exercises WSL.
mod windows {
    use std::{
        net::{IpAddr, SocketAddr},
        pin::Pin,
        process::Stdio,
        sync::Arc,
        time::Duration,
    };

    use clap::Parser;
    use hyper_util::rt::TokioIo;
    use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion};
    use tokio::{
        net::TcpStream,
        process::Command,
        time::{sleep, timeout},
    };
    use tokio_openssl::SslStream;
    use tonic::transport::Endpoint;
    use tower::service_fn;

    /// Generated control-service protobuf client bindings.
    pub mod proto {
        tonic::include_proto!("shadow_socket_proxy.control.v1");
    }

    #[derive(Debug, Parser)]
    /// CLI inputs describing the deployed service, proxy, and TCP target.
    struct Args {
        #[arg(long)]
        /// TLS endpoint exposed by the WSL control service.
        control_endpoint: String,
        #[arg(long)]
        /// Ephemeral TLS-PSK identity.
        psk_identity: String,
        #[arg(long)]
        /// Ephemeral TLS-PSK secret.
        psk_secret: String,
        #[arg(long)]
        /// Deployed BPF ELF path as visible inside WSL.
        elf_path: String,
        #[arg(long)]
        /// WSL interface receiving the TC classifiers.
        interface: String,
        #[arg(long)]
        /// Windows test-server address that BPF should preserve as original.
        target: SocketAddr,
        #[arg(long)]
        /// Windows host-proxy address that BPF should use as synthetic target.
        proxy: SocketAddr,
        #[arg(long)]
        /// WSL distribution used for the generated TCP client.
        wsl_distribution: String,
        #[arg(long)]
        /// Marker returned by the Windows test server.
        marker: String,
    }

    /// Tonic client type used for authenticated control RPCs.
    type Client = proto::control_client::ControlClient<tonic::transport::Channel>;

    /// Attaches the deployed BPF program, configures its target, generates a
    /// WSL TCP flow, and verifies marker, mapping, readiness, and counter state.
    pub async fn run() -> Result<(), String> {
        let args = Args::parse();
        let mut client =
            connect(&args.control_endpoint, &args.psk_identity, &args.psk_secret).await?;

        let attach = client
            .attach(proto::InterfaceRequest {
                elf_path: args.elf_path.clone(),
                interfaces: vec![args.interface.clone()],
            })
            .await
            .map_err(|error| format!("attach failed: {error}"))?
            .into_inner();
        if !attach.success {
            return Err(format!("attach rejected: {}", attach.message));
        }

        let mut config = client
            .get_config(proto::Empty {})
            .await
            .map_err(|error| format!("get config failed: {error}"))?
            .into_inner()
            .config
            .ok_or_else(|| "get config returned no configuration".to_string())?;
        config.ipv4_target_address = match args.proxy.ip() {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(_) => return Err("E2E proxy must be IPv4".into()),
        };
        config.ipv4_target_port = args.proxy.port() as u32;
        client
            .set_config(proto::SetConfigRequest {
                config: Some(config),
            })
            .await
            .map_err(|error| format!("set config failed: {error}"))?;

        let before = client
            .get_status(proto::Empty {})
            .await
            .map_err(|error| format!("initial status failed: {error}"))?
            .into_inner();
        if !before.ready {
            return Err("control service is not ready after attach".into());
        }

        let output = Command::new("wsl.exe")
            .args([
                "-d",
                &args.wsl_distribution,
                "--",
                "python3",
                "-c",
                &format!(
                    concat!(
                        "import socket\n",
                        "s=socket.create_connection(('{}', {}), 10)\n",
                        "print('TUPLE=' + s.getsockname()[0] + ':' + str(s.getsockname()[1]))\n",
                        "s.sendall(b'{}\\n')\n",
                        "response=b''\n",
                        "while b'\\n' not in response:\n",
                        "    chunk=s.recv(4096)\n",
                        "    assert chunk, 'marker server closed before newline'\n",
                        "    response+=chunk\n",
                        "print('RESPONSE=' + response.split(b'\\n', 1)[0].decode())\n",
                        "s.close()",
                    ),
                    args.target.ip(),
                    args.target.port(),
                    args.marker
                ),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|error| format!("start WSL TCP client failed: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "WSL TCP client failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let response = String::from_utf8_lossy(&output.stdout);
        let client_tuple = response
            .lines()
            .find_map(|line| line.strip_prefix("TUPLE="))
            .ok_or_else(|| "WSL client did not report its synthetic source tuple".to_string())?
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid WSL client tuple: {error}"))?;
        let returned_marker = response
            .lines()
            .find_map(|line| line.strip_prefix("RESPONSE="))
            .ok_or_else(|| "WSL client did not report a marker response".to_string())?;
        if returned_marker != args.marker {
            return Err(format!("unexpected marker response: {returned_marker}"));
        }

        let mut mapping = None;
        for _ in 0..50 {
            let status = client
                .get_status(proto::Empty {})
                .await
                .map_err(|error| format!("status after traffic failed: {error}"))?
                .into_inner();
            if status.flow_insert_failures != before.flow_insert_failures {
                return Err("flow insertion failure counter increased".into());
            }
            let page = client
                .list_mappings(proto::ListMappingsRequest {
                    limit: 256,
                    page_token: Vec::new(),
                })
                .await
                .map_err(|error| format!("list mappings failed: {error}"))?
                .into_inner();
            mapping = page.mappings.into_iter().find(|entry| {
                let original_matches = entry.original.as_ref().is_some_and(|tuple| {
                    tuple.family == 4
                        && tuple.destination_address
                            == match args.target.ip() {
                                IpAddr::V4(address) => address.octets().to_vec(),
                                IpAddr::V6(_) => Vec::new(),
                            }
                        && tuple.destination_port == args.target.port() as u32
                });
                let synthetic_matches = entry.synthetic.as_ref().is_some_and(|tuple| {
                    tuple.family == 4
                        && tuple.source_address
                            == match client_tuple.ip() {
                                IpAddr::V4(address) => address.octets().to_vec(),
                                IpAddr::V6(_) => Vec::new(),
                            }
                        && tuple.source_port == client_tuple.port() as u32
                        && tuple.destination_address
                            == match args.proxy.ip() {
                                IpAddr::V4(address) => address.octets().to_vec(),
                                IpAddr::V6(_) => Vec::new(),
                            }
                        && tuple.destination_port == args.proxy.port() as u32
                });
                original_matches && synthetic_matches
            });
            if mapping.is_some() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        let mapping = mapping.ok_or_else(|| "expected TCP mapping was not observed".to_string())?;
        let original = mapping
            .original
            .ok_or_else(|| "mapping has no original tuple".to_string())?;
        let target_address = match args.target.ip() {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(_) => return Err("E2E target must be IPv4".into()),
        };
        if original.family != 4
            || original.destination_address != target_address
            || original.destination_port != args.target.port() as u32
        {
            return Err("mapping original destination mismatch".into());
        }
        let synthetic = mapping
            .synthetic
            .ok_or_else(|| "mapping has no synthetic tuple".to_string())?;
        let proxy_address = match args.proxy.ip() {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(_) => return Err("E2E proxy must be IPv4".into()),
        };
        if synthetic.family != 4
            || synthetic.destination_address != proxy_address
            || synthetic.destination_port != args.proxy.port() as u32
        {
            return Err("mapping synthetic proxy destination mismatch".into());
        }
        Ok(())
    }

    /// Connects to the control service through a TLS 1.2 PSK HTTP/2 channel.
    async fn connect(endpoint: &str, identity: &str, secret: &str) -> Result<Client, String> {
        if identity.is_empty() || secret.is_empty() || identity.as_bytes().contains(&0) {
            return Err("invalid TLS-PSK credentials".into());
        }
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|error| format!("invalid endpoint: {error}"))?;
        let context = build_context(identity, secret.as_bytes())?;
        let connector = service_fn(move |uri: http::Uri| {
            let context = context.clone();
            async move { connect_tls(uri, context).await }
        });
        let channel = Endpoint::from(uri)
            .connect_with_connector(connector)
            .await
            .map_err(|error| format!("control connection failed: {error:?}"))?;
        Ok(proto::control_client::ControlClient::new(channel))
    }

    /// Builds the OpenSSL context used for the authenticated control channel.
    fn build_context(identity: &str, secret: &[u8]) -> Result<Arc<SslContext>, String> {
        let mut builder =
            SslContextBuilder::new(SslMethod::tls_client()).map_err(|error| error.to_string())?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|error| error.to_string())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|error| error.to_string())?;
        builder
            .set_cipher_list("PSK-AES256-GCM-SHA384")
            .map_err(|error| error.to_string())?;
        builder
            .set_alpn_protos(b"\x02h2")
            .map_err(|error| error.to_string())?;
        let identity = identity.as_bytes().to_vec();
        let secret = secret.to_vec();
        builder.set_psk_client_callback(move |_, _, identity_out, key_out| {
            if identity_out.len() < identity.len() + 1 || key_out.len() < secret.len() {
                return Err(openssl::error::ErrorStack::get());
            }
            identity_out[..identity.len()].copy_from_slice(&identity);
            identity_out[identity.len()] = 0;
            key_out[..secret.len()].copy_from_slice(&secret);
            Ok(secret.len())
        });
        Ok(Arc::new(builder.build()))
    }

    /// Opens and handshakes the TLS stream used by tonic's connector.
    async fn connect_tls(
        uri: http::Uri,
        context: Arc<SslContext>,
    ) -> Result<TokioIo<SslStream<TcpStream>>, std::io::Error> {
        let authority = uri.authority().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing authority")
        })?;
        let stream = timeout(
            Duration::from_secs(10),
            TcpStream::connect(authority.as_str()),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "control connect timeout")
        })??;
        let mut ssl =
            Ssl::new(&context).map_err(|error| std::io::Error::other(error.to_string()))?;
        ssl.set_hostname(authority.host())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut stream = SslStream::new(ssl, stream)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(TokioIo::new(stream))
    }
}

#[cfg(all(target_os = "windows", feature = "tls-psk"))]
/// Runs the Windows/WSL deployment driver and returns a failing process status
/// when any prerequisite, RPC, packet, mapping, or marker assertion fails.
#[tokio::main]
async fn main() {
    if let Err(error) = windows::run().await {
        eprintln!("shadow-socket-proxy-e2e-runner failed: {error}");
        std::process::exit(1);
    }
}
