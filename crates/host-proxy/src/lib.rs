// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use thiserror::Error;
use tokio::{
    io,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{watch, Mutex},
    task::JoinSet,
    time,
};

pub mod proto {
    tonic::include_proto!("shadow_socket_proxy.control.v1");
}

const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalDestination {
    pub address: SocketAddr,
    pub protocol: u8,
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("mapping not found")]
    MappingNotFound,
    #[error("mapping response is invalid: {0}")]
    InvalidMapping(String),
    #[error("control service error: {0}")]
    Control(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("proxy is unsupported on this platform")]
    UnsupportedPlatform,
}

#[async_trait]
pub trait MappingClient: Send + Sync {
    async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError>;
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub control_endpoint: String,
    pub psk_identity: String,
    pub psk_secret: Vec<u8>,
    pub udp_idle_timeout: Duration,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), ProxyError> {
        if self.listen.ip().is_unspecified() {
            return Err(ProxyError::InvalidConfiguration(
                "listen address must be specific so UDP tuples identify the local destination"
                    .into(),
            ));
        }
        if self.control_endpoint.is_empty() {
            return Err(ProxyError::InvalidConfiguration(
                "control endpoint is required".into(),
            ));
        }
        if self.psk_identity.is_empty() || self.psk_secret.is_empty() {
            return Err(ProxyError::InvalidConfiguration(
                "PSK identity and secret are required".into(),
            ));
        }
        if self.udp_idle_timeout.is_zero() {
            return Err(ProxyError::InvalidConfiguration(
                "UDP idle timeout must be nonzero".into(),
            ));
        }
        Ok(())
    }
}

pub struct Proxy<C> {
    config: ProxyConfig,
    client: Arc<C>,
}

impl<C: MappingClient + 'static> Proxy<C> {
    pub fn new(config: ProxyConfig, client: Arc<C>) -> Result<Self, ProxyError> {
        config.validate()?;
        Ok(Self { config, client })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), ProxyError> {
        let tcp_listener = TcpListener::bind(self.config.listen).await?;
        let actual_listen = tcp_listener.local_addr()?;
        let udp_socket = Arc::new(UdpSocket::bind(actual_listen).await?);
        let udp = Arc::new(UdpAssociations::new(
            udp_socket.clone(),
            self.client.clone(),
            self.config.udp_idle_timeout,
            shutdown.clone(),
        ));
        let mut tcp_task =
            tokio::spawn(run_tcp(tcp_listener, self.client.clone(), shutdown.clone()));
        let mut udp_task = tokio::spawn(run_udp(udp.clone(), shutdown.clone()));
        let result = tokio::select! {
            _ = shutdown.changed() => {
                let _ = tcp_task.await;
                let _ = udp_task.await;
                Ok(())
            },
            result = &mut tcp_task => {
                udp_task.abort();
                let _ = udp_task.await;
                result.map_err(|error| ProxyError::Control(error.to_string()))
            },
            result = &mut udp_task => {
                tcp_task.abort();
                let _ = tcp_task.await;
                result.map_err(|error| ProxyError::Control(error.to_string()))
            },
        };
        udp.shutdown().await;
        result
    }
}

async fn run_tcp<C: MappingClient + 'static>(
    listener: TcpListener,
    client: Arc<C>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(%error, "TCP accept failed");
                        continue;
                    }
                };
                let client = client.clone();
                sessions.spawn(async move {
                    if let Err(error) = bridge_tcp(stream, client).await {
                        tracing::warn!(%error, "TCP forwarding session failed");
                    }
                });
            }
        }
    }
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
}

async fn bridge_tcp<C: MappingClient + 'static>(
    mut accepted: TcpStream,
    client: Arc<C>,
) -> Result<(), ProxyError> {
    let tuple = Tuple {
        source: accepted.peer_addr()?,
        destination: accepted.local_addr()?,
        protocol: TCP_PROTOCOL,
    };
    let original = client.get_mapping(&tuple).await?;
    if original.protocol != TCP_PROTOCOL {
        return Err(ProxyError::InvalidMapping(
            "TCP lookup returned a non-TCP mapping".into(),
        ));
    }
    let mut outbound = TcpStream::connect(original.address).await?;
    let _ = io::copy_bidirectional(&mut accepted, &mut outbound).await?;
    Ok(())
}

async fn run_udp<C: MappingClient + 'static>(
    associations: Arc<UdpAssociations<C>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buffer = vec![0_u8; 65_535];
    let mut reap = time::interval(associations.idle_timeout);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = reap.tick() => {
                associations.reap().await;
            }
            received = associations.socket.recv_from(&mut buffer) => {
                let (length, client_address) = match received {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(%error, "UDP receive failed");
                        continue;
                    }
                };
                if let Err(error) = associations.forward(client_address, &buffer[..length]).await {
                    associations.report_failure(&error).await;
                }
            }
        }
    }
}

struct UdpAssociations<C> {
    socket: Arc<UdpSocket>,
    client: Arc<C>,
    entries: Mutex<HashMap<Tuple, Arc<UdpAssociation>>>,
    idle_timeout: Duration,
    shutdown: watch::Receiver<bool>,
    last_failure_log: Mutex<Option<std::time::Instant>>,
}

struct UdpAssociation {
    client_address: SocketAddr,
    destination: SocketAddr,
    outbound: Arc<UdpSocket>,
    last_seen: Mutex<std::time::Instant>,
}

impl<C: MappingClient + 'static> UdpAssociations<C> {
    fn new(
        socket: Arc<UdpSocket>,
        client: Arc<C>,
        idle_timeout: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            socket,
            client,
            entries: Mutex::new(HashMap::new()),
            idle_timeout,
            shutdown,
            last_failure_log: Mutex::new(None),
        }
    }

    async fn forward(&self, client_address: SocketAddr, payload: &[u8]) -> Result<(), ProxyError> {
        let tuple = Tuple {
            source: client_address,
            destination: self.socket.local_addr()?,
            protocol: UDP_PROTOCOL,
        };
        let mapping = self.client.get_mapping(&tuple).await?;
        if mapping.protocol != UDP_PROTOCOL {
            return Err(ProxyError::InvalidMapping(
                "UDP lookup returned a non-UDP mapping".into(),
            ));
        }
        let existing = self.entries.lock().await.get(&tuple).cloned();
        let association = if let Some(existing) = existing {
            if existing.destination == mapping.address {
                existing
            } else {
                self.replace_association(tuple, client_address, mapping)
                    .await?
            }
        } else {
            self.insert_association(tuple, client_address, mapping)
                .await?
        };
        association.outbound.send(payload).await?;
        *association.last_seen.lock().await = std::time::Instant::now();
        Ok(())
    }

    async fn insert_association(
        &self,
        tuple: Tuple,
        client_address: SocketAddr,
        mapping: OriginalDestination,
    ) -> Result<Arc<UdpAssociation>, ProxyError> {
        let outbound = Arc::new(UdpSocket::bind(unspecified_for(mapping.address)).await?);
        outbound.connect(mapping.address).await?;
        let candidate = Arc::new(UdpAssociation {
            client_address,
            destination: mapping.address,
            outbound,
            last_seen: Mutex::new(std::time::Instant::now()),
        });
        let mut entries = self.entries.lock().await;
        if let Some(existing) = entries.get(&tuple) {
            if existing.destination == mapping.address {
                return Ok(existing.clone());
            }
        }
        entries.insert(tuple, candidate.clone());
        spawn_udp_relay(
            candidate.clone(),
            self.socket.clone(),
            self.idle_timeout,
            self.shutdown.clone(),
        );
        Ok(candidate)
    }

    async fn replace_association(
        &self,
        tuple: Tuple,
        client_address: SocketAddr,
        mapping: OriginalDestination,
    ) -> Result<Arc<UdpAssociation>, ProxyError> {
        self.insert_association(tuple, client_address, mapping)
            .await
    }

    async fn report_failure(&self, error: &ProxyError) {
        let now = std::time::Instant::now();
        let mut last_failure_log = self.last_failure_log.lock().await;
        if last_failure_log
            .map(|last| now.duration_since(last) >= Duration::from_secs(1))
            .unwrap_or(true)
        {
            *last_failure_log = Some(now);
            tracing::warn!(%error, "UDP forwarding failed");
        }
    }

    async fn shutdown(&self) {
        self.entries.lock().await.clear();
    }

    async fn reap(&self) {
        let mut entries = self.entries.lock().await;
        let idle_timeout = self.idle_timeout;
        entries.retain(|_, association| {
            association
                .last_seen
                .try_lock()
                .map(|last_seen| last_seen.elapsed() < idle_timeout)
                .unwrap_or(true)
        });
    }
}

fn spawn_udp_relay(
    association: Arc<UdpAssociation>,
    client_socket: Arc<UdpSocket>,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let result = {
                let receive = time::timeout(idle_timeout, association.outbound.recv(&mut buffer));
                tokio::pin!(receive);
                tokio::select! {
                    _ = shutdown.changed() => return,
                    result = &mut receive => result,
                }
            };
            match result {
                Ok(Ok(length)) => {
                    if client_socket
                        .send_to(&buffer[..length], association.client_address)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    *association.last_seen.lock().await = std::time::Instant::now();
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
    });
}

fn unspecified_for(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0; 16], 0)),
    }
}

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
#[derive(Clone)]
pub struct TlsPskMappingClient;

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
impl TlsPskMappingClient {
    pub async fn connect(
        _endpoint: &str,
        _identity: &str,
        _secret: &[u8],
    ) -> Result<Self, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }
}

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
#[async_trait]
impl MappingClient for TlsPskMappingClient {
    async fn get_mapping(&self, _tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }
}

#[cfg(all(target_os = "windows", feature = "tls-psk"))]
mod windows_client {
    use super::*;
    use openssl::{
        error::ErrorStack,
        ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion},
    };
    use std::pin::Pin;
    use tokio_openssl::SslStream;
    use tonic::transport::Endpoint;
    use tower::service_fn;

    #[derive(Clone)]
    pub struct TlsPskMappingClient {
        client: Arc<Mutex<proto::control_client::ControlClient<tonic::transport::Channel>>>,
    }

    impl TlsPskMappingClient {
        pub async fn connect(
            endpoint: &str,
            identity: &str,
            secret: &[u8],
        ) -> Result<Self, ProxyError> {
            if identity.as_bytes().contains(&0) || identity.is_empty() || secret.is_empty() {
                return Err(ProxyError::InvalidConfiguration(
                    "invalid TLS-PSK credentials".into(),
                ));
            }
            let uri = endpoint.parse().map_err(|error| {
                ProxyError::InvalidConfiguration(format!("invalid endpoint: {error}"))
            })?;
            let context = build_context(identity, secret)?;
            let connector = service_fn(move |uri: http::Uri| {
                let context = context.clone();
                async move { connect_tls(uri, context).await }
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
    }

    #[async_trait]
    impl MappingClient for TlsPskMappingClient {
        async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            let request = proto::GetMappingRequest {
                synthetic: Some(proto::Tuple {
                    family: if tuple.source.is_ipv4() { 4 } else { 6 },
                    source_address: ip_bytes(tuple.source.ip()),
                    destination_address: ip_bytes(tuple.destination.ip()),
                    protocol: tuple.protocol as u32,
                    source_port: tuple.source.port() as u32,
                    destination_port: tuple.destination.port() as u32,
                }),
            };
            let mapping = self
                .client
                .lock()
                .await
                .get_mapping(request)
                .await
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
            if address.destination.is_unspecified()
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

    fn ip_bytes(address: &IpAddr) -> Vec<u8> {
        match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        }
    }

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

    fn build_context(identity: &str, secret: &[u8]) -> Result<Arc<SslContext>, ProxyError> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).map_err(openssl_error)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(openssl_error)?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(openssl_error)?;
        builder
            .set_cipher_list("PSK-AES256-GCM-SHA384")
            .map_err(openssl_error)?;
        builder.set_alpn_protos(b"\x02h2").map_err(openssl_error)?;
        let identity = identity.as_bytes().to_vec();
        let secret = secret.to_vec();
        builder.set_psk_client_callback(move |_, _, identity_out, key_out| {
            if identity_out.len() < identity.len() + 1 || key_out.len() < secret.len() {
                return Err(ErrorStack::get());
            }
            identity_out[..identity.len()].copy_from_slice(&identity);
            identity_out[identity.len()] = 0;
            key_out[..secret.len()].copy_from_slice(&secret);
            Ok(secret.len())
        });
        Ok(Arc::new(builder.build()))
    }

    async fn connect_tls(
        uri: http::Uri,
        context: Arc<SslContext>,
    ) -> Result<SslStream<TcpStream>, io::Error> {
        let authority = uri.authority().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "endpoint authority missing")
        })?;
        let stream = TcpStream::connect(authority.as_str()).await?;
        let host = authority.host();
        let ssl = Ssl::new(&context).map_err(openssl_io_error)?;
        let mut ssl = SslStream::new(ssl, stream).map_err(openssl_io_error)?;
        ssl.ssl_mut().set_hostname(host).map_err(openssl_io_error)?;
        Pin::new(&mut ssl)
            .connect()
            .await
            .map_err(openssl_io_error)?;
        Ok(ssl)
    }

    fn openssl_error(error: ErrorStack) -> ProxyError {
        ProxyError::Control(error.to_string())
    }

    fn openssl_io_error(error: impl std::fmt::Display) -> io::Error {
        io::Error::new(io::ErrorKind::Other, error.to_string())
    }

    pub use TlsPskMappingClient as PublicTlsPskMappingClient;
}

#[cfg(all(target_os = "windows", feature = "tls-psk"))]
pub use windows_client::PublicTlsPskMappingClient as TlsPskMappingClient;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockClient {
        destination: SocketAddr,
        protocol: u8,
    }

    #[async_trait]
    impl MappingClient for MockClient {
        async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            assert_eq!(tuple.protocol, self.protocol);
            Ok(OriginalDestination {
                address: self.destination,
                protocol: tuple.protocol,
            })
        }
    }

    #[test]
    fn configuration_rejects_missing_credentials_and_zero_timeout() {
        let config = ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            control_endpoint: "https://127.0.0.1:50051".into(),
            psk_identity: String::new(),
            psk_secret: Vec::new(),
            udp_idle_timeout: Duration::ZERO,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn configuration_rejects_wildcard_listen_address() {
        let config = ProxyConfig {
            listen: "0.0.0.0:15000".parse().unwrap(),
            control_endpoint: "https://127.0.0.1:50051".into(),
            psk_identity: "identity".into(),
            psk_secret: vec![1],
            udp_idle_timeout: Duration::from_secs(5),
        };
        assert!(matches!(
            config.validate(),
            Err(ProxyError::InvalidConfiguration(message))
                if message.contains("listen address must be specific")
        ));
    }

    #[tokio::test]
    async fn tcp_bridge_copies_data_to_original_destination() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &buffer)
                .await
                .unwrap();
        });
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = client_listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (stream, _) = client_listener.accept().await.unwrap();
            bridge_tcp(
                stream,
                Arc::new(MockClient {
                    destination,
                    protocol: TCP_PROTOCOL,
                }),
            )
            .await
            .unwrap();
        });
        let mut client = TcpStream::connect(client_address).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, b"test")
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut response)
            .await
            .unwrap();
        assert_eq!(&response, b"test");
        drop(client);
        accepted.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_forwarding_relays_response_to_originating_client() {
        let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 4];
            let (length, client_address) = destination.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"ping");
            destination.send_to(b"pong", client_address).await.unwrap();
        });

        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let associations = Arc::new(UdpAssociations::new(
            proxy_socket.clone(),
            Arc::new(MockClient {
                destination: destination_address,
                protocol: UDP_PROTOCOL,
            }),
            Duration::from_secs(5),
            shutdown,
        ));
        let receiver = tokio::spawn(run_udp(associations, shutdown_sender.subscribe()));

        client_socket
            .send_to(b"ping", proxy_socket.local_addr().unwrap())
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        let (length, sender) = time::timeout(
            Duration::from_secs(2),
            client_socket.recv_from(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[..length], b"pong");
        assert_eq!(sender, proxy_socket.local_addr().unwrap());
        shutdown_sender.send(true).unwrap();
        receiver.await.unwrap();
        server.await.unwrap();
    }
}
