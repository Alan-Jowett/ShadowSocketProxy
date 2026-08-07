// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

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
use openssl::{
    error::ErrorStack,
    ssl::{select_next_proto, AlpnError, Ssl, SslAcceptor, SslContext, SslMethod, SslVersion},
};
#[cfg(target_os = "linux")]
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
#[cfg(target_os = "linux")]
use tokio_openssl::SslStream;
#[cfg(target_os = "linux")]
use tokio_stream::{wrappers::TcpListenerStream, Stream, StreamExt};
#[cfg(target_os = "linux")]
use tonic::transport::server::Connected;

#[derive(Clone)]
pub struct TlsPskConfig {
    pub identity: String,
    pub secret: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransportError {
    #[error("TLS-PSK is unavailable in the selected OpenSSL build")]
    UnsupportedTlsPsk,
    #[error("TLS-PSK identity and secret are required")]
    InvalidConfig,
    #[error("TLS-PSK identity contains an unsupported NUL byte or is too long")]
    InvalidIdentity,
    #[error("TLS-PSK secret is longer than the TLS-PSK limit")]
    SecretTooLong,
    #[error("TLS context initialization failed: {0}")]
    Tls(String),
    #[error("TLS listener bind failed: {0}")]
    Bind(String),
}

pub struct TlsPskServer {
    pub config: TlsPskConfig,
    #[cfg(target_os = "linux")]
    context: Arc<SslContext>,
}

impl TlsPskServer {
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
                config,
                context: Arc::new(context),
            })
        }
    }

    #[cfg(target_os = "linux")]
    pub async fn incoming(
        &self,
        address: SocketAddr,
    ) -> Result<impl Stream<Item = Result<TlsConnection, std::io::Error>>, TransportError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| TransportError::Bind(error.to_string()))?;
        let context = self.context.clone();
        Ok(TcpListenerStream::new(listener).then(move |accepted| {
            let context = context.clone();
            async move {
                let stream = accepted?;
                let peer_addr = stream.peer_addr()?;
                let ssl = Ssl::new(&context)
                    .map_err(|_| std::io::Error::other("TLS session initialization failed"))?;
                let mut stream = SslStream::new(ssl, stream)
                    .map_err(|_| std::io::Error::other("TLS session initialization failed"))?;
                Pin::new(&mut stream)
                    .accept()
                    .await
                    .map_err(|_| std::io::Error::other("TLS handshake failed"))?;
                Ok(TlsConnection { stream, peer_addr })
            }
        }))
    }
}

#[cfg(target_os = "linux")]
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
fn openssl_error(error: ErrorStack) -> TransportError {
    TransportError::Tls(error.to_string())
}

#[cfg(target_os = "linux")]
pub struct TlsConnection {
    stream: SslStream<TcpStream>,
    peer_addr: SocketAddr,
}

#[cfg(target_os = "linux")]
impl Connected for TlsConnection {
    type ConnectInfo = SocketAddr;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer_addr
    }
}

#[cfg(target_os = "linux")]
impl AsyncRead for TlsConnection {
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
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

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
}
