// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Linux-only TLS 1.2 PSK listener used by the gRPC control API.

#[cfg(target_os = "linux")]
use std::net::SocketAddr;

use thiserror::Error;

#[cfg(target_os = "linux")]
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(target_os = "linux")]
use futures_util::StreamExt as FuturesStreamExt;
#[cfg(target_os = "linux")]
use openssl::{
    error::ErrorStack,
    ssl::{select_next_proto, AlpnError, Ssl, SslAcceptor, SslContext, SslMethod, SslVersion},
};
#[cfg(target_os = "linux")]
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
#[cfg(target_os = "linux")]
use tokio_openssl::SslStream;
#[cfg(target_os = "linux")]
use tokio_stream::{wrappers::TcpListenerStream, Stream};
#[cfg(target_os = "linux")]
use tonic::transport::server::Connected;

#[derive(Clone)]
/// Credentials used to construct the fixed TLS-PSK control context.
pub struct TlsPskConfig {
    /// Exact client identity accepted by the server callback.
    pub identity: String,
    /// PSK bytes copied into the OpenSSL callback; at most 256 bytes.
    pub secret: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Errors raised while configuring, binding, or handshaking TLS-PSK.
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
    #[error("TLS listener bind failed: {0}")]
    /// The TCP listener could not bind to the requested address.
    Bind(String),
}

/// Reusable TLS-PSK acceptor with an HTTP/2 ALPN requirement.
pub struct TlsPskServer {
    #[cfg(target_os = "linux")]
    /// OpenSSL context shared by accepted connections.
    context: Arc<SslContext>,
}

impl TlsPskServer {
    /// Validates credential bounds and builds a TLS 1.2 PSK context; on
    /// non-Linux or PSK-disabled builds it returns `UnsupportedTlsPsk`.
    pub fn new(config: TlsPskConfig) -> Result<Self, TransportError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            return Err(TransportError::UnsupportedTlsPsk);
        }

        #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
            .buffer_unordered(64))
    }
}

#[cfg(target_os = "linux")]
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
    Ok(TlsConnection { stream, peer_addr })
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
/// Converts an OpenSSL error stack into a transport configuration error.
fn openssl_error(error: ErrorStack) -> TransportError {
    TransportError::Tls(error.to_string())
}

#[cfg(target_os = "linux")]
/// TLS-wrapped TCP stream implementing tonic's connection traits.
pub struct TlsConnection {
    /// OpenSSL stream used for all async I/O.
    stream: SslStream<TcpStream>,
    /// Remote socket address captured before the handshake.
    peer_addr: SocketAddr,
}

#[cfg(target_os = "linux")]
impl Connected for TlsConnection {
    /// Tonic connection metadata is the peer socket address.
    type ConnectInfo = SocketAddr;

    /// Returns the peer address captured at accept time.
    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer_addr
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
    #[test]
    fn openssl_psk_context_is_constructed_without_metadata_auth() {
        let server = TlsPskServer::new(TlsPskConfig {
            identity: "shadow-socket-proxy".into(),
            secret: b"01234567890123456789012345678901".to_vec(),
        });
        assert!(server.is_ok());
    }

    #[cfg(target_os = "linux")]
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
}
