// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Windows rustls mutual-certificate gRPC client for the control service.

use super::*;
use hyper_util::rt::TokioIo;
use shadow_socket_proxy_tls_rustls::RustlsConfig;
use std::path::Path;
use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName, TlsConnector};
use tonic::transport::Endpoint;
use tower::service_fn;

/// Adds a gRPC deadline and enforces the same deadline locally.
async fn bounded_rpc<T>(
    operation: impl Future<Output = Result<T, tonic::Status>>,
) -> Result<T, ProxyError> {
    time::timeout(CONTROL_RPC_TIMEOUT, operation)
        .await
        .map_err(|_| ProxyError::Control("control RPC timed out".into()))?
        .map_err(|error| ProxyError::Control(error.to_string()))
}

/// Builds a tonic request carrying the server-visible deadline.
fn rpc_request<T>(message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.set_timeout(CONTROL_RPC_TIMEOUT);
    request
}

#[derive(Clone)]
/// Reusable rustls mutual-certificate gRPC channel for mapping lookups.
pub struct TlsRustlsMappingClient {
    /// Serialized access to the tonic client because lookups are concurrent.
    client: Arc<Mutex<proto::control_client::ControlClient<tonic::transport::Channel>>>,
}

impl TlsRustlsMappingClient {
    /// Loads the PEM identity, validates the peer pin, and connects the tonic
    /// channel to `endpoint` without hostname certificate validation.
    pub async fn connect(
        endpoint: &str,
        certificate_file: &Path,
        key_file: &Path,
        peer_cert_sha256: &str,
    ) -> Result<Self, ProxyError> {
        let config = RustlsConfig::load(certificate_file, key_file, peer_cert_sha256)
            .map_err(|error| ProxyError::InvalidConfiguration(error.to_string()))?;
        Self::connect_with_config(endpoint, config).await
    }

    /// Connects using an already loaded rustls identity; used by the
    /// executable integration test to avoid filesystem credentials.
    async fn connect_with_config(endpoint: &str, config: RustlsConfig) -> Result<Self, ProxyError> {
        let uri: http::Uri = endpoint.parse().map_err(|error| {
            ProxyError::InvalidConfiguration(format!("invalid endpoint: {error}"))
        })?;
        let config = config
            .client_config()
            .map_err(|error| ProxyError::InvalidConfiguration(error.to_string()))?;
        let connector = service_fn(move |uri: http::Uri| {
            let config = config.clone();
            async move { connect_tls(uri, config).await }
        });
        let channel = Endpoint::from(uri)
            .connect_with_connector(connector)
            .await
            .map_err(|error| ProxyError::Control(error.to_string()))?;
        Ok(Self {
            client: Arc::new(Mutex::new(proto::control_client::ControlClient::new(
                channel,
            ))),
        })
    }

    /// Attaches the WSL BPF ELF and sets this proxy listener as its family
    /// target before the proxy begins accepting redirected traffic.
    pub async fn activate(
        &self,
        elf_path: &str,
        interface: &str,
        proxy: SocketAddr,
    ) -> Result<(), ProxyError> {
        if elf_path.is_empty() || interface.is_empty() {
            return Err(ProxyError::InvalidConfiguration(
                "BPF ELF path and interface are required".into(),
            ));
        }
        let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
        let attached = bounded_rpc(client.attach(rpc_request(proto::InterfaceRequest {
            elf_path: elf_path.into(),
            interfaces: vec![interface.into()],
        })))
        .await?
        .into_inner();
        if !attached.success {
            return Err(ProxyError::Control(attached.message));
        }
        let configured = async {
            let mut config = bounded_rpc(client.get_config(rpc_request(proto::Empty {})))
                .await?
                .into_inner()
                .config
                .ok_or_else(|| ProxyError::Control("control service returned no config".into()))?;
            match proxy.ip() {
                IpAddr::V4(address) => {
                    config.ipv4_target_address = address.octets().to_vec();
                    config.ipv4_target_port = proxy.port() as u32;
                }
                IpAddr::V6(address) => {
                    config.ipv6_target_address = address.octets().to_vec();
                    config.ipv6_target_port = proxy.port() as u32;
                }
            }
            bounded_rpc(client.set_config(rpc_request(proto::SetConfigRequest {
                config: Some(config),
            })))
            .await?;
            Ok(())
        }
        .await;
        if let Err(error) = configured {
            let rollback = bounded_rpc(client.detach(rpc_request(proto::DetachRequest {
                interfaces: vec![interface.into()],
                all: false,
            })))
            .await;
            return match rollback {
                Ok(_) => Err(error),
                Err(rollback_error) => Err(ProxyError::Control(format!(
                    "{error}; attach rollback failed: {rollback_error}"
                ))),
            };
        }
        Ok(())
    }

    /// Detaches BPF classifiers associated with one interface.
    pub async fn detach(&self, interface: &str) -> Result<(), ProxyError> {
        let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
        bounded_rpc(client.detach(rpc_request(proto::DetachRequest {
            interfaces: vec![interface.into()],
            all: false,
        })))
        .await?;
        Ok(())
    }

    /// Enumerates one bounded page of typed flow records.
    pub async fn enumerate_flows(
        &self,
        page_token: Vec<u8>,
        limit: u32,
    ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
        let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
        let reply = bounded_rpc(client.enumerate_flows(rpc_request(
            proto::EnumerateFlowsRequest { limit, page_token },
        )))
        .await?
        .into_inner();
        let mut flows = Vec::with_capacity(reply.flows.len());
        for flow in reply.flows {
            let synthetic = tuple_from_proto(flow.synthetic.ok_or_else(|| {
                ProxyError::InvalidMapping("flow synthetic tuple missing".into())
            })?)?;
            let original = tuple_from_proto(flow.original.ok_or_else(|| {
                ProxyError::InvalidMapping("flow original tuple missing".into())
            })?)?;
            let protocol = checked_flow_protocol(flow.protocol)?;
            if synthetic.protocol != protocol || original.protocol != protocol {
                return Err(ProxyError::InvalidMapping(
                    "flow protocol does not match tuples".into(),
                ));
            }
            flows.push(FlowRecord {
                flow_id: flow.flow_id,
                generation: flow.generation,
                synthetic,
                original,
                last_used_ns: flow.last_used_ns,
                protocol_flags: flow.protocol_flags,
                tcp_state_flags: flow.tcp_state_flags,
                observed_now_ns: flow.observed_now_ns,
                fin_seen_mask: flow.fin_seen_mask,
                fin_ack_seen_mask: flow.fin_ack_seen_mask,
            });
        }
        Ok((flows, reply.next_page_token))
    }

    /// Deletes one generation-checked flow and converts its typed outcome.
    pub async fn delete_flow(
        &self,
        flow_id: u64,
        generation: u32,
        observed_last_used_ns: u64,
    ) -> Result<FlowDeleteReport, ProxyError> {
        let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
        let reply = bounded_rpc(client.delete_flow(rpc_request(proto::DeleteFlowRequest {
            flow_id,
            generation,
            observed_last_used_ns,
        })))
        .await?
        .into_inner();
        let outcome = match proto::delete_flow_reply::Outcome::try_from(reply.outcome)
            .map_err(|_| ProxyError::Control("unknown flow deletion outcome".into()))?
        {
            proto::delete_flow_reply::Outcome::Complete => FlowDeleteOutcome::Complete,
            proto::delete_flow_reply::Outcome::AlreadyAbsent => FlowDeleteOutcome::AlreadyAbsent,
            proto::delete_flow_reply::Outcome::StaleGeneration => {
                FlowDeleteOutcome::StaleGeneration
            }
            proto::delete_flow_reply::Outcome::Partial => FlowDeleteOutcome::Partial,
            proto::delete_flow_reply::Outcome::ObservationMismatch => {
                FlowDeleteOutcome::ObservationMismatch
            }
        };
        Ok(FlowDeleteReport {
            flow_id: reply.flow_id,
            generation: reply.generation,
            outcome,
            indexes_deleted: reply.indexes_deleted,
            state_deleted: reply.state_deleted,
            retryable: reply.retryable,
        })
    }
}

#[async_trait]
impl MappingClient for TlsRustlsMappingClient {
    /// Converts the socket tuple to protobuf, performs the RPC, and validates
    /// the returned original tuple and protocol.
    async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
        let request = proto::GetMappingRequest {
            synthetic: Some(proto::Tuple {
                family: if tuple.source.is_ipv4() { 4 } else { 6 },
                source_address: ip_bytes(&tuple.source.ip()),
                destination_address: ip_bytes(&tuple.destination.ip()),
                protocol: tuple.protocol as u32,
                source_port: tuple.source.port() as u32,
                destination_port: tuple.destination.port() as u32,
            }),
        };
        let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
        let mapping = time::timeout(
            CONTROL_RPC_TIMEOUT,
            client.get_mapping(rpc_request(request)),
        )
        .await
        .map_err(|_| ProxyError::Control("control RPC timed out".into()))?
        .map_err(|error| {
            if error.code() == tonic::Code::NotFound {
                ProxyError::MappingNotFound
            } else {
                ProxyError::Control(error.to_string())
            }
        })?
        .into_inner();
        let synthetic = mapping
            .synthetic
            .ok_or_else(|| ProxyError::InvalidMapping("missing synthetic tuple".into()))?;
        if tuple_from_proto(synthetic)? != *tuple {
            return Err(ProxyError::InvalidMapping(
                "mapping synthetic tuple does not match lookup".into(),
            ));
        }
        let original = mapping
            .original
            .ok_or_else(|| ProxyError::InvalidMapping("missing original tuple".into()))?;
        let address = tuple_from_proto(original)?;
        if address.protocol != tuple.protocol {
            return Err(ProxyError::InvalidMapping(
                "mapping protocol does not match lookup".into(),
            ));
        }
        if address.destination.ip().is_unspecified()
            || address.destination.port() == 0
            || address.destination.is_ipv4() != tuple.destination.is_ipv4()
        {
            return Err(ProxyError::InvalidMapping(
                "mapping destination has an invalid address or port".into(),
            ));
        }
        Ok(OriginalDestination {
            address: address.destination,
            protocol: address.protocol,
        })
    }
}

#[async_trait]
impl FlowClient for TlsRustlsMappingClient {
    /// Delegates typed flow enumeration to the authenticated channel.
    async fn enumerate_flows(
        &self,
        page_token: Vec<u8>,
        limit: u32,
    ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
        self.enumerate_flows(page_token, limit).await
    }

    /// Delegates generation-checked flow deletion to the authenticated channel.
    async fn delete_flow(
        &self,
        flow_id: u64,
        generation: u32,
        observed_last_used_ns: u64,
    ) -> Result<FlowDeleteReport, ProxyError> {
        self.delete_flow(flow_id, generation, observed_last_used_ns)
            .await
    }
}

/// Converts a protobuf tuple to a socket tuple, rejecting family/width and
/// protocol-field violations.
fn tuple_from_proto(tuple: proto::Tuple) -> Result<Tuple, ProxyError> {
    let source = ip_from_bytes(tuple.family, &tuple.source_address)?;
    let destination = ip_from_bytes(tuple.family, &tuple.destination_address)?;
    if tuple.protocol > u8::MAX as u32
        || tuple.source_port > u16::MAX as u32
        || tuple.destination_port > u16::MAX as u32
    {
        return Err(ProxyError::InvalidMapping(
            "tuple field out of range".into(),
        ));
    }

    Ok(Tuple {
        source: SocketAddr::new(source, tuple.source_port as u16),
        destination: SocketAddr::new(destination, tuple.destination_port as u16),
        protocol: tuple.protocol as u8,
    })
}

/// Encodes an IP address as its native 4- or 16-byte representation.
fn ip_bytes(address: &IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

/// Decodes a family-tagged address and rejects incorrect byte lengths.
fn ip_from_bytes(family: u32, bytes: &[u8]) -> Result<IpAddr, ProxyError> {
    match family {
        4 if bytes.len() == 4 => Ok(IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        6 if bytes.len() == 16 => Ok(IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap(),
        ))),
        _ => Err(ProxyError::InvalidMapping("invalid address family".into())),
    }
}

/// Opens and handshakes a rustls stream for the URI. Certificate hostname
/// matching is intentionally not used; the pinned leaf verifier remains the
/// trust anchor.
async fn connect_tls(
    uri: http::Uri,
    config: Arc<tokio_rustls::rustls::ClientConfig>,
) -> Result<TokioIo<TlsStream<TcpStream>>, io::Error> {
    let authority = uri
        .authority()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint authority missing"))?;
    let stream = time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(authority.as_str()),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control connect timeout"))??;
    let server_name = ServerName::try_from("ssp.invalid".to_owned())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let stream = time::timeout(
        Duration::from_secs(5),
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control TLS handshake timeout"))?
    .map_err(|error| io::Error::other(format!("control TLS handshake failed: {error}")))?;
    if stream
        .get_ref()
        .1
        .alpn_protocol()
        .is_none_or(|protocol| protocol != b"h2")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS connection did not negotiate h2",
        ));
    }
    Ok(TokioIo::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use rcgen::generate_simple_self_signed;
    use sha2::{Digest, Sha256};
    use shadow_socket_proxy_control::{
        bpf::InMemoryBackend,
        config::{ConfigStore, RuntimeConfig},
        logs::LogRing,
        mapping::{Mapping as ControlMapping, Tuple as ControlTuple},
        proto::control_server::ControlServer,
        service::ControlService,
    };
    use tokio::{net::TcpListener, sync::oneshot};
    use tokio_rustls::{
        rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        server::TlsStream,
        TlsAcceptor,
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::server::Connected;
    use tonic::transport::Server;

    struct TestTlsConnection {
        stream: TlsStream<tokio::net::TcpStream>,
        peer_addr: SocketAddr,
    }

    impl Connected for TestTlsConnection {
        type ConnectInfo = SocketAddr;

        fn connect_info(&self) -> Self::ConnectInfo {
            self.peer_addr
        }
    }

    impl tokio::io::AsyncRead for TestTlsConnection {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::pin::Pin::new(&mut self.stream).poll_read(context, buffer)
        }
    }

    impl tokio::io::AsyncWrite for TestTlsConnection {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            std::pin::Pin::new(&mut self.stream).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::pin::Pin::new(&mut self.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::pin::Pin::new(&mut self.stream).poll_shutdown(context)
        }
    }

    fn identity(name: &str) -> shadow_socket_proxy_tls_rustls::RustlsIdentity {
        let generated = generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        shadow_socket_proxy_tls_rustls::RustlsIdentity {
            cert_chain: vec![CertificateDer::from(generated.cert.der().to_vec())],
            private_key: PrivateKeyDer::from_pem_slice(
                generated.signing_key.serialize_pem().as_bytes(),
            )
            .unwrap(),
        }
    }

    fn pin(identity: &shadow_socket_proxy_tls_rustls::RustlsIdentity) -> [u8; 32] {
        Sha256::digest(identity.cert_chain[0].as_ref()).into()
    }

    #[tokio::test]
    async fn rustls_client_authenticates_tonic_h2_rpc() {
        let server_identity = identity("server.invalid");
        let client_identity = identity("client.invalid");
        let server_config = shadow_socket_proxy_tls_rustls::RustlsConfig {
            identity: server_identity.clone(),
            peer_cert_sha256: pin(&client_identity),
        };
        let client_config = shadow_socket_proxy_tls_rustls::RustlsConfig {
            identity: client_identity,
            peer_cert_sha256: pin(&server_identity),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_config.server_config().unwrap());
        let incoming = TcpListenerStream::new(listener)
            .map(move |accepted| {
                let acceptor = acceptor.clone();
                async move {
                    let stream = accepted?;
                    let peer_addr = stream.peer_addr()?;
                    let stream = acceptor
                        .accept(stream)
                        .await
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "TLS connection did not negotiate h2",
                        ));
                    }
                    Ok(TestTlsConnection { stream, peer_addr })
                }
            })
            .buffer_unordered(16);
        let backend = Arc::new(InMemoryBackend::default());
        backend.insert_mapping(ControlMapping {
            synthetic: ControlTuple {
                source: "127.0.0.1".parse().unwrap(),
                destination: address.ip(),
                protocol: 6,
                source_port: 40000,
                destination_port: address.port(),
            },
            original: ControlTuple {
                source: "127.0.0.1".parse().unwrap(),
                destination: "127.0.0.1".parse().unwrap(),
                protocol: 6,
                source_port: 40000,
                destination_port: 41000,
            },
            last_seen_ns: 1,
            protocol_flags: 1,
            tcp_state_flags: 0,
        });
        let service = ControlService::new(
            backend,
            Arc::new(ConfigStore::new(RuntimeConfig::default()).unwrap()),
            Arc::new(LogRing::new(8)),
        );
        let (shutdown, shutdown_signal) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            Server::builder()
                .add_service(ControlServer::new(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_signal.await;
                })
                .await
                .unwrap();
        });

        let client = TlsRustlsMappingClient::connect_with_config(
            &format!("http://{address}"),
            client_config,
        )
        .await
        .unwrap();
        let mapping = client
            .get_mapping(&Tuple {
                source: "127.0.0.1:40000".parse().unwrap(),
                destination: address,
                protocol: 6,
            })
            .await
            .unwrap();
        assert_eq!(mapping.address, "127.0.0.1:41000".parse().unwrap());

        let _ = shutdown.send(());
        server_task.await.unwrap();
    }
}
