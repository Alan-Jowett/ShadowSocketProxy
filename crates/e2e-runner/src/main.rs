// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Runs the shared Windows/WSL TCP deployment validation against the control API.

#[cfg(all(feature = "tls-psk", feature = "tls-rustls"))]
compile_error!("tls-psk and tls-rustls are mutually exclusive");

#[cfg(not(all(
    target_os = "windows",
    any(feature = "tls-psk", feature = "tls-rustls")
)))]
/// Prints a Windows/TLS feature requirement diagnostic and exits
/// unsuccessfully when this test driver is built on an unsupported platform
/// or without a selected transport.
fn main() {
    eprintln!(
        "shadow-socket-proxy-e2e-runner requires exactly one of the tls-psk or tls-rustls features and Windows"
    );
    std::process::exit(1);
}

#[cfg(all(
    target_os = "windows",
    any(feature = "tls-psk", feature = "tls-rustls")
))]
/// Authenticates to the WSL control service, attaches/configures BPF, creates
/// the TCP probe, and verifies the returned marker and exact flow mapping.
mod windows {
    #[cfg(feature = "tls-psk")]
    use std::pin::Pin;
    use std::{
        net::{IpAddr, SocketAddr},
        process::Stdio,
        sync::Arc,
        time::Duration,
    };

    use clap::Parser;
    use hyper_util::rt::TokioIo;
    #[cfg(feature = "tls-psk")]
    use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion};
    #[cfg(feature = "tls-rustls")]
    use shadow_socket_proxy_tls_rustls::RustlsConfig;
    use tokio::{
        net::TcpStream,
        process::Command,
        time::{sleep, timeout},
    };
    #[cfg(feature = "tls-psk")]
    use tokio_openssl::SslStream;
    #[cfg(feature = "tls-rustls")]
    use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName, TlsConnector};
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
        psk_identity: Option<String>,
        #[arg(long)]
        /// Ephemeral TLS-PSK secret.
        psk_secret: Option<String>,
        #[arg(long)]
        /// PEM certificate chain used by the rustls control client.
        tls_cert_file: Option<std::path::PathBuf>,
        #[arg(long)]
        /// PEM private key used by the rustls control client.
        tls_key_file: Option<std::path::PathBuf>,
        #[arg(long)]
        /// SHA-256 pin for the control service's leaf certificate.
        tls_peer_cert_sha256: Option<String>,
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

    /// Selects a setting from either the command line or its environment variable.
    fn select_value<T>(
        cli: Option<T>,
        env_name: &str,
        value: impl FnOnce(String) -> T,
    ) -> Result<Option<T>, String> {
        let environment = match std::env::var_os(env_name) {
            None => None,
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|_| format!("{env_name} is not valid UTF-8"))?,
            ),
        };
        if cli.is_some() && environment.is_some() {
            return Err(format!(
                "{env_name} must not be combined with its command-line option"
            ));
        }
        if cli.is_some() {
            return Ok(cli);
        }
        Ok(environment.filter(|value| !value.is_empty()).map(value))
    }

    /// Runtime certificate and peer-pin settings for rustls mode.
    type RustlsOptions = (
        Option<std::path::PathBuf>,
        Option<std::path::PathBuf>,
        Option<String>,
    );

    /// Resolves rustls certificate and peer-pin settings.
    fn resolve_rustls_options(args: &Args) -> Result<RustlsOptions, String> {
        Ok((
            select_value(
                args.tls_cert_file.clone(),
                "SSP_TLS_CERT_FILE",
                std::path::PathBuf::from,
            )?,
            select_value(
                args.tls_key_file.clone(),
                "SSP_TLS_KEY_FILE",
                std::path::PathBuf::from,
            )?,
            select_value(
                args.tls_peer_cert_sha256.clone(),
                "SSP_TLS_PEER_CERT_SHA256",
                |value| value,
            )?,
        ))
    }

    /// Tonic client type used for authenticated control RPCs.
    type Client = proto::control_client::ControlClient<tonic::transport::Channel>;

    /// Verifies the proxy-owned BPF activation with a WSL TCP flow, exact
    /// marker response, mapping state, readiness, and counter checks.
    pub async fn run() -> Result<(), String> {
        let args = Args::parse();
        let (tls_cert_file, tls_key_file, tls_peer_cert_sha256) = resolve_rustls_options(&args)?;
        #[cfg(feature = "tls-psk")]
        if tls_cert_file.is_some() || tls_key_file.is_some() || tls_peer_cert_sha256.is_some() {
            return Err("rustls TLS settings require building with the tls-rustls feature".into());
        }
        #[cfg(feature = "tls-psk")]
        let mut client = connect(
            &args.control_endpoint,
            args.psk_identity
                .as_deref()
                .ok_or("PSK identity is required")?,
            args.psk_secret.as_deref().ok_or("PSK secret is required")?,
        )
        .await?;
        #[cfg(feature = "tls-rustls")]
        if args.psk_identity.is_some()
            || args.psk_secret.is_some()
            || std::env::var_os("SSP_TLS_PSK_IDENTITY").is_some()
            || std::env::var_os("SSP_TLS_PSK_SECRET").is_some()
        {
            return Err("PSK settings cannot be combined with the tls-rustls feature".into());
        }
        #[cfg(feature = "tls-rustls")]
        let mut client = {
            let certificate_file = tls_cert_file.ok_or("TLS certificate file is required")?;
            let key_file = tls_key_file.ok_or("TLS private key file is required")?;
            let peer_pin =
                tls_peer_cert_sha256.ok_or("TLS peer certificate SHA-256 pin is required")?;
            connect(
                &args.control_endpoint,
                &certificate_file,
                &key_file,
                &peer_pin,
            )
            .await?
        };

        let before = client
            .get_status(proto::Empty {})
            .await
            .map_err(|error| format!("initial status failed: {error}"))?
            .into_inner();
        if !before.ready {
            return Err("control service is not ready after proxy activation".into());
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
        let (marker, peer) = returned_marker
            .split_once('|')
            .ok_or_else(|| "marker response omitted its observed peer".to_string())?;
        if marker != args.marker {
            return Err(format!("unexpected marker response: {returned_marker}"));
        }
        let peer = peer
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid marker peer: {error}"))?;
        if peer.ip() != args.proxy.ip() {
            return Err(format!(
                "marker was reached directly by {peer} instead of through proxy {}",
                args.proxy.ip()
            ));
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
            let mut page_token = Vec::new();
            loop {
                let page = client
                    .list_mappings(proto::ListMappingsRequest {
                        limit: 256,
                        page_token,
                    })
                    .await
                    .map_err(|error| format!("list mappings failed: {error}"))?
                    .into_inner();
                mapping = page.mappings.into_iter().find(|entry| {
                    let original_matches = entry.original.as_ref().is_some_and(|tuple| {
                        tuple.family == 4
                            && tuple.protocol == 6
                            && tuple.source_address
                                == match client_tuple.ip() {
                                    IpAddr::V4(address) => address.octets().to_vec(),
                                    IpAddr::V6(_) => Vec::new(),
                                }
                            && tuple.source_port == client_tuple.port() as u32
                            && tuple.destination_address
                                == match args.target.ip() {
                                    IpAddr::V4(address) => address.octets().to_vec(),
                                    IpAddr::V6(_) => Vec::new(),
                                }
                            && tuple.destination_port == args.target.port() as u32
                    });
                    let synthetic_matches = entry.synthetic.as_ref().is_some_and(|tuple| {
                        tuple.family == 4
                            && tuple.protocol == 6
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
                if mapping.is_some() || page.next_page_token.is_empty() {
                    break;
                }
                page_token = page.next_page_token;
            }
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

    #[cfg(feature = "tls-psk")]
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

    #[cfg(feature = "tls-psk")]
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

    #[cfg(feature = "tls-psk")]
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
        timeout(Duration::from_secs(10), Pin::new(&mut stream).connect())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "control TLS handshake timeout",
                )
            })?
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(TokioIo::new(stream))
    }

    #[cfg(feature = "tls-rustls")]
    /// Connects to the control service through a pinned rustls mutual-TLS
    /// HTTP/2 channel.
    async fn connect(
        endpoint: &str,
        certificate_file: &std::path::Path,
        key_file: &std::path::Path,
        peer_cert_sha256: &str,
    ) -> Result<Client, String> {
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|error| format!("invalid endpoint: {error}"))?;
        let config = RustlsConfig::load(certificate_file, key_file, peer_cert_sha256)
            .map_err(|error| error.to_string())?
            .client_config()
            .map_err(|error| error.to_string())?;
        let connector = service_fn(move |uri: http::Uri| {
            let config = config.clone();
            async move { connect_tls(uri, config).await }
        });
        let channel = Endpoint::from(uri)
            .connect_with_connector(connector)
            .await
            .map_err(|error| format!("control connection failed: {error:?}"))?;
        Ok(proto::control_client::ControlClient::new(channel))
    }

    #[cfg(feature = "tls-rustls")]
    /// Opens and handshakes the rustls stream used by tonic's connector.
    async fn connect_tls(
        uri: http::Uri,
        config: Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> Result<TokioIo<TlsStream<TcpStream>>, std::io::Error> {
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
        let server_name = ServerName::try_from("ssp.invalid".to_owned())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let stream = timeout(
            Duration::from_secs(10),
            TlsConnector::from(config).connect(server_name, stream),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "control TLS handshake timeout",
            )
        })?
        .map_err(|error| std::io::Error::other(format!("control TLS handshake failed: {error}")))?;
        if stream
            .get_ref()
            .1
            .alpn_protocol()
            .is_none_or(|protocol| protocol != b"h2")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLS connection did not negotiate h2",
            ));
        }
        Ok(TokioIo::new(stream))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn duplicate_cli_and_environment_tls_values_are_rejected() {
            let env_name = "SSP_TEST_E2E_TLS_DUPLICATE";
            std::env::set_var(env_name, "environment");
            let result = select_value(Some("command-line".to_owned()), env_name, |value| value);
            std::env::remove_var(env_name);
            assert!(result.is_err());
        }
    }
}

#[cfg(all(
    target_os = "windows",
    any(feature = "tls-psk", feature = "tls-rustls")
))]
/// Runs the Windows/WSL deployment driver and returns a failing process status
/// when any prerequisite, RPC, packet, mapping, or marker assertion fails.
#[tokio::main]
async fn main() {
    if let Err(error) = windows::run().await {
        eprintln!("shadow-socket-proxy-e2e-runner failed: {error}");
        std::process::exit(1);
    }
}
