// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Feature-selected TLS listeners used by the gRPC control API.

#[cfg(all(target_os = "linux", any(feature = "tls-psk", feature = "tls-rustls")))]
use std::net::SocketAddr;

use thiserror::Error;

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
use futures_util::StreamExt as FuturesStreamExt;
#[cfg(all(target_os = "linux", feature = "tls-psk"))]
use openssl::{
    error::ErrorStack,
    ssl::{select_next_proto, AlpnError, Ssl, SslAcceptor, SslContext, SslMethod, SslVersion},
};
#[cfg(all(target_os = "linux", feature = "tls-psk"))]
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
#[cfg(all(target_os = "linux", feature = "tls-psk"))]
use tokio_openssl::SslStream;
#[cfg(all(target_os = "linux", feature = "tls-psk"))]
use tokio_stream::{wrappers::TcpListenerStream, Stream};
#[cfg(all(target_os = "linux", feature = "tls-psk"))]
use tonic::transport::server::Connected;

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
use futures_util::StreamExt as FuturesStreamExt;
#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
use shadow_socket_proxy_tls_rustls::RustlsConfig;
#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
use tokio_rustls::{server::TlsStream, TlsAcceptor};
#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
use tokio_stream::{wrappers::TcpListenerStream, Stream};
#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
use tonic::transport::server::Connected;

#[derive(Clone)]
/// Credentials used to construct the fixed TLS-PSK control context.
pub struct TlsPskConfig {
    /// Exact client identity accepted by the server callback.
    pub identity: String,
    /// PSK bytes copied into the OpenSSL callback; at most 256 bytes.
    pub secret: Vec<u8>,
}

#[cfg(feature = "tls-rustls")]
pub use shadow_socket_proxy_tls_rustls::RustlsConfig as TlsRustlsConfig;

/// Selected control-service TLS transport configuration.
pub enum TlsConfig {
    #[cfg(feature = "tls-psk")]
    /// OpenSSL TLS-PSK credentials.
    Psk(TlsPskConfig),
    #[cfg(feature = "tls-rustls")]
    /// rustls mutual-certificate credentials.
    Rustls(TlsRustlsConfig),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Errors raised while configuring, binding, or handshaking the selected TLS
/// transport.
pub enum TransportError {
    #[error("TLS-PSK is unavailable in the selected OpenSSL build")]
    /// The platform or OpenSSL build does not expose PSK support.
    UnsupportedTlsPsk,
    #[error("TLS-PSK identity and secret are required")]
    /// Identity or secret was empty.
    InvalidConfig,
    #[error("TLS-PSK identity contains an unsupported NUL byte or is too long")]
    /// Identity contains NUL or exceeds the accepted 128-byte limit.
    InvalidIdentity,
    #[error("TLS-PSK secret is longer than the TLS-PSK limit")]
    /// Secret exceeds the 256-byte PSK limit.
    SecretTooLong,
    #[error("TLS context initialization failed: {0}")]
    /// OpenSSL rejected context or cipher configuration.
    Tls(String),
    #[error("rustls is unavailable in the selected build")]
    /// The rustls transport is not available for this target or feature set.
    UnsupportedTlsRustls,
    #[error("no TLS transport feature was selected")]
    /// A runnable binary was built without a TLS transport feature.
    NoTlsModeSelected,
    #[error("TLS listener bind failed: {0}")]
    /// The TCP listener could not bind to the requested address.
    Bind(String),
}

/// Reusable TLS-PSK acceptor with an HTTP/2 ALPN requirement.
pub struct TlsPskServer {
    #[cfg(all(target_os = "linux", feature = "tls-psk"))]
    /// OpenSSL context shared by accepted connections.
    context: Arc<SslContext>,
}

impl TlsPskServer {
    /// Validates credential bounds and builds a TLS 1.2 PSK context; on
    /// non-Linux or PSK-disabled builds it returns `UnsupportedTlsPsk`.
    pub fn new(config: TlsPskConfig) -> Result<Self, TransportError> {
        #[cfg(any(not(target_os = "linux"), not(feature = "tls-psk")))]
        {
            let _ = config;
            Err(TransportError::UnsupportedTlsPsk)
        }

        #[cfg(all(target_os = "linux", feature = "tls-psk"))]
        {
            if config.identity.is_empty() || config.secret.is_empty() {
                return Err(TransportError::InvalidConfig);
            }
            if config.identity.as_bytes().contains(&0) || config.identity.len() > 128 {
                return Err(TransportError::InvalidIdentity);
            }
            if config.secret.len() > 256 {
                return Err(TransportError::SecretTooLong);
            }

            let context = build_context(&config)?;
            Ok(Self {
                context: Arc::new(context),
            })
        }
    }

    #[cfg(all(target_os = "linux", feature = "tls-psk"))]
    /// Binds a TCP listener and yields up to 64 concurrent TLS handshakes.
    pub async fn incoming(
        &self,
        address: SocketAddr,
    ) -> Result<impl Stream<Item = Result<TlsConnection, std::io::Error>>, TransportError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| TransportError::Bind(error.to_string()))?;
        let context = self.context.clone();
        Ok(TcpListenerStream::new(listener)
            .map(move |accepted| {
                let context = context.clone();
                async move { accept_tls(context, accepted?).await }
            })
            .buffer_unordered(64)
            .filter_map(|result| drop_failed_connection(result, "TLS-PSK")))
    }
}

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
/// Wraps one accepted socket, completes its handshake within five seconds, and
/// preserves the peer address for tonic's `Connected` metadata.
async fn accept_tls(
    context: Arc<SslContext>,
    stream: TcpStream,
) -> Result<TlsConnection, std::io::Error> {
    let peer_addr = stream.peer_addr()?;
    let ssl = Ssl::new(&context)
        .map_err(|_| std::io::Error::other("TLS session initialization failed"))?;
    let mut stream = SslStream::new(ssl, stream)
        .map_err(|_| std::io::Error::other("TLS session initialization failed"))?;
    timeout(Duration::from_secs(5), Pin::new(&mut stream).accept())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out"))?
        .map_err(|_| std::io::Error::other("TLS handshake failed"))?;
    if stream
        .ssl()
        .selected_alpn_protocol()
        .is_none_or(|protocol| protocol != b"h2")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS connection did not negotiate h2",
        ));
    }
    Ok(TlsConnection { stream, peer_addr })
}

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
/// Configures TLS 1.2, `PSK-AES256-GCM-SHA384`, and HTTP/2 ALPN, accepting only
/// the configured identity and secret.
fn build_context(config: &TlsPskConfig) -> Result<SslContext, TransportError> {
    #[cfg(ssp_openssl_no_psk)]
    {
        let _ = config;
        return Err(TransportError::UnsupportedTlsPsk);
    }

    #[cfg(not(ssp_openssl_no_psk))]
    {
        let identity = config.identity.as_bytes().to_vec();
        let secret = config.secret.clone();
        let mut builder =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(openssl_error)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(openssl_error)?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(openssl_error)?;
        builder
            .set_cipher_list("PSK-AES256-GCM-SHA384")
            .map_err(openssl_error)?;
        builder.set_alpn_select_callback(|_, client_protocols| {
            select_next_proto(b"\x02h2", client_protocols).ok_or(AlpnError::NOACK)
        });
        builder.set_psk_server_callback(move |_, client_identity, psk| {
            if client_identity != Some(identity.as_slice()) || psk.len() < secret.len() {
                return Ok(0);
            }
            psk[..secret.len()].copy_from_slice(&secret);
            Ok(secret.len())
        });
        Ok(builder.build().into_context())
    }
}

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
/// Converts an OpenSSL error stack into a transport configuration error.
fn openssl_error(error: ErrorStack) -> TransportError {
    TransportError::Tls(error.to_string())
}

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
/// TLS-wrapped TCP stream implementing tonic's connection traits.
pub struct TlsConnection {
    /// OpenSSL stream used for all async I/O.
    stream: SslStream<TcpStream>,
    /// Remote socket address captured before the handshake.
    peer_addr: SocketAddr,
}

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
impl Connected for TlsConnection {
    /// Tonic connection metadata is the peer socket address.
    type ConnectInfo = SocketAddr;

    /// Returns the peer address captured at accept time.
    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer_addr
    }
}

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
impl AsyncRead for TlsConnection {
    /// Delegates readiness and reads to the TLS stream.
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

#[cfg(all(target_os = "linux", feature = "tls-psk"))]
impl AsyncWrite for TlsConnection {
    /// Delegates writes to the TLS stream.
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    /// Flushes pending encrypted output through OpenSSL.
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    /// Performs an orderly TLS stream shutdown.
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
/// Reusable rustls mutual-certificate acceptor with an HTTP/2 ALPN
/// requirement.
pub struct TlsRustlsServer {
    /// rustls server configuration shared by accepted connections.
    config: Arc<tokio_rustls::rustls::ServerConfig>,
}

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
impl TlsRustlsServer {
    /// Loads the configured PEM identity, builds pinned client validation, and
    /// prepares TLS 1.2/1.3 with h2 ALPN.
    pub fn new(config: RustlsConfig) -> Result<Self, TransportError> {
        let config = config
            .server_config()
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        Ok(Self { config })
    }

    /// Binds a TCP listener and yields up to 64 concurrent rustls
    /// handshakes.
    pub async fn incoming(
        &self,
        address: SocketAddr,
    ) -> Result<impl Stream<Item = Result<TlsRustlsConnection, std::io::Error>>, TransportError>
    {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| TransportError::Bind(error.to_string()))?;
        let acceptor = TlsAcceptor::from(self.config.clone());
        Ok(TcpListenerStream::new(listener)
            .map(move |accepted| {
                let acceptor = acceptor.clone();
                async move { accept_rustls(acceptor, accepted?).await }
            })
            .buffer_unordered(64)
            .filter_map(|result| drop_failed_connection(result, "rustls")))
    }
}

#[cfg(all(target_os = "linux", any(feature = "tls-psk", feature = "tls-rustls")))]
/// Drops one failed accept or TLS handshake without terminating the listener.
async fn drop_failed_connection<T>(
    result: Result<T, std::io::Error>,
    transport: &'static str,
) -> Option<Result<T, std::io::Error>> {
    match result {
        Ok(connection) => Some(Ok(connection)),
        Err(error) => {
            tracing::warn!(transport, %error, "rejecting failed TLS connection");
            None
        }
    }
}

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
/// Wraps one accepted rustls socket and preserves the peer address for
/// tonic's `Connected` metadata.
pub struct TlsRustlsConnection {
    /// rustls stream used for all async I/O.
    stream: TlsStream<TcpStream>,
    /// Remote socket address captured before the handshake.
    peer_addr: SocketAddr,
}

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
async fn accept_rustls(
    acceptor: TlsAcceptor,
    stream: TcpStream,
) -> Result<TlsRustlsConnection, std::io::Error> {
    let peer_addr = stream.peer_addr()?;
    let stream = timeout(Duration::from_secs(5), acceptor.accept(stream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out"))?
        .map_err(|error| std::io::Error::other(format!("TLS handshake failed: {error}")))?;
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
    Ok(TlsRustlsConnection { stream, peer_addr })
}

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
impl Connected for TlsRustlsConnection {
    /// Tonic connection metadata is the peer socket address.
    type ConnectInfo = SocketAddr;

    /// Returns the peer address captured at accept time.
    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer_addr
    }
}

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
impl AsyncRead for TlsRustlsConnection {
    /// Delegates reads to the rustls stream.
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

#[cfg(all(target_os = "linux", feature = "tls-rustls"))]
impl AsyncWrite for TlsRustlsConnection {
    /// Delegates writes to the rustls stream.
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    /// Flushes pending encrypted output through rustls.
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    /// Performs an orderly TLS stream shutdown.
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[cfg(all(
    test,
    any(not(target_os = "linux"), feature = "tls-psk", feature = "tls-rustls")
))]
mod tests {
    use super::*;
    #[cfg(all(target_os = "linux", any(feature = "tls-psk", feature = "tls-rustls")))]
    use crate::bpf::BpfBackend;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_build_reports_unsupported_tls_psk() {
        assert!(matches!(
            TlsPskServer::new(TlsPskConfig {
                identity: "id".into(),
                secret: vec![1],
            }),
            Err(TransportError::UnsupportedTlsPsk)
        ));
    }

    #[cfg(all(target_os = "linux", feature = "tls-psk"))]
    #[test]
    fn invalid_credentials_fail_before_ready_state() {
        assert!(matches!(
            TlsPskServer::new(TlsPskConfig {
                identity: String::new(),
                secret: vec![1],
            }),
            Err(TransportError::InvalidConfig)
        ));
        assert!(matches!(
            TlsPskServer::new(TlsPskConfig {
                identity: "id".into(),
                secret: Vec::new(),
            }),
            Err(TransportError::InvalidConfig)
        ));
    }

    #[cfg(all(target_os = "linux", feature = "tls-psk"))]
    #[test]
    fn openssl_psk_context_is_constructed_without_metadata_auth() {
        let server = TlsPskServer::new(TlsPskConfig {
            identity: "shadow-socket-proxy".into(),
            secret: b"01234567890123456789012345678901".to_vec(),
        });
        assert!(server.is_ok());
    }

    #[cfg(all(target_os = "linux", feature = "tls-psk"))]
    #[tokio::test(start_paused = true)]
    async fn stalled_tls_handshake_times_out() {
        use tokio::net::TcpListener;

        let context = Arc::new(
            build_context(&TlsPskConfig {
                identity: "shadow-socket-proxy".into(),
                secret: b"01234567890123456789012345678901".to_vec(),
            })
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(6), accept_tls(context, server_stream)).await;
        let error = match result {
            Ok(Ok(_)) => panic!("handshake completed unexpectedly"),
            Ok(Err(error)) => error,
            Err(_) => panic!("outer test timeout expired"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(client);
    }

    #[cfg(all(target_os = "linux", feature = "tls-psk"))]
    #[tokio::test]
    async fn psk_invalid_handshake_does_not_stop_full_server() {
        use std::{path::Path, pin::Pin, sync::Arc};

        use hyper_util::rt::TokioIo;
        use openssl::{
            error::ErrorStack,
            ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion},
        };
        use tokio::{
            io::AsyncWriteExt,
            net::{TcpListener, TcpStream},
            sync::oneshot,
            time::{timeout, Duration},
        };
        use tokio_openssl::SslStream;
        use tonic::transport::{Endpoint, Server};
        use tower::service_fn;

        fn client_context(identity: &str, secret: &[u8], negotiate_h2: bool) -> Arc<SslContext> {
            let mut builder =
                SslContextBuilder::new(SslMethod::tls_client()).expect("client TLS context");
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();
            builder.set_cipher_list("PSK-AES256-GCM-SHA384").unwrap();
            if negotiate_h2 {
                builder.set_alpn_protos(b"\x02h2").unwrap();
            }
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
            Arc::new(builder.build())
        }

        async fn connect_psk(
            uri: http::Uri,
            context: Arc<SslContext>,
        ) -> Result<TokioIo<SslStream<TcpStream>>, std::io::Error> {
            let authority = uri.authority().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing authority")
            })?;
            let stream = TcpStream::connect(authority.as_str()).await?;
            let mut ssl =
                Ssl::new(&context).map_err(|error| std::io::Error::other(error.to_string()))?;
            ssl.set_hostname(authority.host())
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let mut stream = SslStream::new(ssl, stream)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            timeout(Duration::from_secs(5), Pin::new(&mut stream).connect())
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
                })?
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            Ok(TokioIo::new(stream))
        }

        let identity = "shadow-socket-proxy";
        let secret = b"01234567890123456789012345678901";
        let transport = TlsPskServer::new(TlsPskConfig {
            identity: identity.into(),
            secret: secret.to_vec(),
        })
        .unwrap();
        let address = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let incoming = transport.incoming(address).await.unwrap();
        let backend = Arc::new(crate::bpf::InMemoryBackend::default());
        backend
            .attach(Path::new("test.bpf.o"), &["test0".to_owned()])
            .await
            .unwrap();
        let service = crate::service::ControlService::new(
            backend.clone(),
            Arc::new(
                crate::config::ConfigStore::new(crate::config::RuntimeConfig::default()).unwrap(),
            ),
            Arc::new(crate::logs::LogRing::new(8)),
        );
        service.set_ready(true);
        let server_service = service.clone();
        let (shutdown, shutdown_signal) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            Server::builder()
                .add_service(crate::proto::control_server::ControlServer::new(
                    server_service,
                ))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_signal.await;
                })
                .await
                .unwrap();
        });

        let stalled = TcpStream::connect(address).await.unwrap();
        let mut malformed = TcpStream::connect(address).await.unwrap();
        malformed.write_all(b"not a TLS handshake").await.unwrap();
        malformed.shutdown().await.unwrap();

        let bad_uri: http::Uri = format!("http://{address}").parse().unwrap();
        let no_h2_context = client_context(identity, secret, false);
        let no_h2_connector = service_fn(move |uri: http::Uri| {
            let context = no_h2_context.clone();
            async move { connect_psk(uri, context).await }
        });
        match timeout(
            Duration::from_secs(5),
            Endpoint::from_shared(format!("http://{address}"))
                .unwrap()
                .connect_with_connector(no_h2_connector),
        )
        .await
        {
            Ok(Err(_)) => {}
            Ok(Ok(channel)) => {
                let mut client = crate::proto::control_client::ControlClient::new(channel);
                assert!(
                    matches!(
                        timeout(
                            Duration::from_secs(5),
                            client.health(crate::proto::Empty {})
                        )
                        .await,
                        Ok(Err(_))
                    ),
                    "non-h2 PSK connection was not rejected"
                );
            }
            Err(_) => panic!("non-h2 PSK connection was not rejected"),
        }
        assert!(service.is_ready());
        assert_eq!(backend.attachments().len(), 2);
        assert_eq!(backend.detach_calls(), 0);

        assert!(connect_psk(
            bad_uri,
            client_context("wrong-identity", b"wrong-secret", true)
        )
        .await
        .is_err());
        assert!(service.is_ready());
        assert_eq!(backend.attachments().len(), 2);
        assert_eq!(backend.detach_calls(), 0);

        let context = client_context(identity, secret, true);
        let connector = service_fn(move |uri: http::Uri| {
            let context = context.clone();
            async move { connect_psk(uri, context).await }
        });
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_with_connector(connector)
            .await
            .unwrap();
        let mut client = crate::proto::control_client::ControlClient::new(channel);
        let health = client
            .health(crate::proto::Empty {})
            .await
            .unwrap()
            .into_inner();
        assert!(health.live);
        assert!(health.ready);
        assert_eq!(backend.attachments().len(), 2);
        assert_eq!(backend.detach_calls(), 0);

        drop(stalled);
        let _ = shutdown.send(());
        server_task.await.unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "tls-rustls"))]
    #[tokio::test]
    async fn rustls_authenticated_tonic_h2_supports_tls12_and_tls13() {
        use std::{path::Path, sync::Arc};

        use hyper_util::rt::TokioIo;
        use rcgen::generate_simple_self_signed;
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        use tokio::{net::TcpListener, sync::oneshot};
        use tokio_rustls::{
            rustls::{
                pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
                version::{TLS12, TLS13},
            },
            TlsConnector,
        };
        use tonic::transport::{Endpoint, Server};
        use tower::service_fn;

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

        async fn run_for_version(version: &'static tokio_rustls::rustls::SupportedProtocolVersion) {
            let server_identity = identity("server.invalid");
            let client_identity = identity("client.invalid");
            let wrong_client_identity = identity("wrong-client.invalid");
            let server_config = shadow_socket_proxy_tls_rustls::RustlsConfig {
                identity: server_identity.clone(),
                peer_cert_sha256: pin(&client_identity),
            };
            let valid_client_config = shadow_socket_proxy_tls_rustls::RustlsConfig {
                identity: client_identity,
                peer_cert_sha256: pin(&server_identity),
            };
            let wrong_client_config = shadow_socket_proxy_tls_rustls::RustlsConfig {
                identity: wrong_client_identity,
                peer_cert_sha256: pin(&server_identity),
            };
            let address = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
                .local_addr()
                .unwrap();
            let transport = TlsRustlsServer::new(server_config).unwrap();
            let incoming = transport.incoming(address).await.unwrap();
            let backend = Arc::new(crate::bpf::InMemoryBackend::default());
            backend
                .attach(Path::new("test.bpf.o"), &["test0".to_owned()])
                .await
                .unwrap();
            let service = crate::service::ControlService::new(
                backend.clone(),
                Arc::new(
                    crate::config::ConfigStore::new(crate::config::RuntimeConfig::default())
                        .unwrap(),
                ),
                Arc::new(crate::logs::LogRing::new(8)),
            );
            service.set_ready(true);
            let server_service = service.clone();
            let (shutdown, shutdown_signal) = oneshot::channel();
            let server_task = tokio::spawn(async move {
                Server::builder()
                    .add_service(crate::proto::control_server::ControlServer::new(
                        server_service,
                    ))
                    .serve_with_incoming_shutdown(incoming, async {
                        let _ = shutdown_signal.await;
                    })
                    .await
                    .unwrap();
            });

            let stalled = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut malformed = tokio::net::TcpStream::connect(address).await.unwrap();
            malformed.write_all(b"not a TLS handshake").await.unwrap();
            malformed.shutdown().await.unwrap();

            let wrong_client_config = wrong_client_config
                .client_config_with_protocol_versions(&[version])
                .unwrap();
            let wrong_connector = service_fn(move |uri: http::Uri| {
                let client_config = wrong_client_config.clone();
                async move {
                    let authority = uri.authority().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing authority")
                    })?;
                    let stream = tokio::net::TcpStream::connect(authority.as_str()).await?;
                    let server_name = ServerName::try_from("not-the-certificate-name".to_owned())
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let stream = TlsConnector::from(client_config)
                        .connect(server_name, stream)
                        .await
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            });
            match Endpoint::from_shared(format!("http://{address}"))
                .unwrap()
                .connect_with_connector(wrong_connector)
                .await
            {
                Err(_) => {}
                Ok(wrong_channel) => {
                    let mut wrong_client =
                        crate::proto::control_client::ControlClient::new(wrong_channel);
                    assert!(wrong_client.health(crate::proto::Empty {}).await.is_err());
                }
            }
            assert!(service.is_ready());
            assert_eq!(backend.attachments().len(), 2);
            assert_eq!(backend.detach_calls(), 0);

            let client_config = valid_client_config
                .client_config_with_protocol_versions(&[version])
                .unwrap();
            let connector = service_fn(move |uri: http::Uri| {
                let client_config = client_config.clone();
                async move {
                    let authority = uri.authority().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing authority")
                    })?;
                    let stream = tokio::net::TcpStream::connect(authority.as_str()).await?;
                    let server_name = ServerName::try_from("not-the-certificate-name".to_owned())
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let stream = TlsConnector::from(client_config)
                        .connect(server_name, stream)
                        .await
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            });
            let channel = Endpoint::from_shared(format!("http://{address}"))
                .unwrap()
                .connect_with_connector(connector)
                .await
                .unwrap();
            let mut client = crate::proto::control_client::ControlClient::new(channel);
            let health = client
                .health(crate::proto::Empty {})
                .await
                .unwrap()
                .into_inner();
            assert!(health.live);
            assert!(health.ready);
            assert_eq!(backend.attachments().len(), 2);
            assert_eq!(backend.detach_calls(), 0);

            drop(stalled);
            let _ = shutdown.send(());
            server_task.await.unwrap();
        }

        run_for_version(&TLS12).await;
        run_for_version(&TLS13).await;
    }
}
