// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Owns startup, transport serving, and shutdown ordering for the control
//! service.

use std::{net::SocketAddr, sync::Arc};

use thiserror::Error;
use tokio::sync::watch;
#[cfg(all(target_os = "linux", any(feature = "tls-psk", feature = "tls-rustls")))]
use tonic::transport::Server;

#[cfg(all(feature = "tls-rustls", not(feature = "tls-psk")))]
use crate::transport::TlsRustlsConfig;
#[cfg(all(target_os = "linux", feature = "tls-rustls", not(feature = "tls-psk")))]
use crate::transport::TlsRustlsServer;
#[cfg(feature = "tls-psk")]
use crate::transport::{TlsPskConfig, TlsPskServer};
use crate::{
    bpf::{BackendError, BpfBackend},
    config::{ConfigError, ConfigStore, RuntimeConfig},
    logs::LogRing,
    service::ControlService,
    transport::{TlsConfig, TransportError},
};

#[derive(Debug, Error)]
/// Startup, serving, or cleanup failure at the runtime boundary.
pub enum RuntimeError {
    #[error("configuration error: {0}")]
    /// Initial or updated runtime configuration was invalid.
    Config(#[from] ConfigError),
    #[error("transport error: {0}")]
    /// TLS transport initialization or binding failed.
    Transport(#[from] TransportError),
    #[error("backend cleanup error: {0}")]
    /// BPF detachment or cleanup failed during shutdown.
    Backend(#[from] BackendError),
    #[error("gRPC server error: {0}")]
    /// The tonic server terminated with a transport error.
    Grpc(#[from] tonic::transport::Error),
}

/// Coordinates the backend, control RPC state, and server.
pub struct ServiceRuntime<B: BpfBackend + 'static> {
    /// Backend used to attach and maintain the BPF program.
    backend: Arc<B>,
    /// Shared validated runtime configuration.
    pub config: Arc<ConfigStore>,
    /// Bounded service log ring.
    pub logs: Arc<LogRing>,
    /// Shutdown signal owned by this runtime.
    shutdown: watch::Sender<bool>,
    /// gRPC control service instance.
    pub service: Arc<ControlService>,
    #[cfg(feature = "tls-psk")]
    /// OpenSSL TLS-PSK transport server.
    transport: Option<TlsPskServer>,
    #[cfg(all(target_os = "linux", feature = "tls-rustls", not(feature = "tls-psk")))]
    /// rustls mutual-certificate transport server.
    rustls_transport: Option<TlsRustlsServer>,
}

impl<B: BpfBackend + 'static> ServiceRuntime<B> {
    /// Creates a runtime using the default control listener `0.0.0.0:50051`.
    pub fn new(backend: B) -> Self {
        Self::new_with_listener(
            backend,
            "0.0.0.0:50051"
                .parse()
                .expect("valid default listener address"),
        )
    }

    /// Creates validated shared state for an explicit control listener.
    pub fn new_with_listener(backend: B, listener: SocketAddr) -> Self {
        let initial = RuntimeConfig {
            listener: crate::config::ListenerDescriptor::from_socket_addr(listener),
            ..RuntimeConfig::default()
        };
        let config = Arc::new(ConfigStore::new(initial).expect("valid listener configuration"));
        let logs = Arc::new(LogRing::new(config.snapshot().log_capacity));
        let backend = Arc::new(backend);
        let service = Arc::new(ControlService::new(
            backend.clone(),
            config.clone(),
            logs.clone(),
        ));
        let (shutdown, _) = watch::channel(false);
        Self {
            backend,
            config,
            logs,
            shutdown,
            service,
            #[cfg(feature = "tls-psk")]
            transport: None,
            #[cfg(all(target_os = "linux", feature = "tls-rustls", not(feature = "tls-psk")))]
            rustls_transport: None,
        }
    }

    /// Reads the selected TLS credentials from the environment and
    /// initializes transport. CLI callers should use `start_with_tls` after
    /// resolving duplicate CLI/environment settings.
    pub async fn start(&mut self) -> Result<(), RuntimeError> {
        #[cfg(feature = "tls-psk")]
        {
            self.start_with_tls(TlsConfig::Psk(TlsPskConfig {
                identity: std::env::var("SSP_TLS_PSK_IDENTITY").unwrap_or_default(),
                secret: std::env::var("SSP_TLS_PSK_SECRET")
                    .map(|value| value.into_bytes())
                    .unwrap_or_default(),
            }))
            .await
        }

        #[cfg(all(feature = "tls-rustls", not(feature = "tls-psk")))]
        {
            let certificate_file = std::env::var("SSP_TLS_CERT_FILE")
                .map_err(|_| TransportError::Tls("SSP_TLS_CERT_FILE is required".into()))?;
            let key_file = std::env::var("SSP_TLS_KEY_FILE")
                .map_err(|_| TransportError::Tls("SSP_TLS_KEY_FILE is required".into()))?;
            let peer_pin = std::env::var("SSP_TLS_PEER_CERT_SHA256")
                .map_err(|_| TransportError::Tls("SSP_TLS_PEER_CERT_SHA256 is required".into()))?;
            let config = TlsRustlsConfig::load(certificate_file, key_file, &peer_pin)
                .map_err(|error| TransportError::Tls(error.to_string()))?;
            self.start_with_tls(TlsConfig::Rustls(config)).await
        }

        #[cfg(not(any(feature = "tls-psk", feature = "tls-rustls")))]
        Err(RuntimeError::Transport(TransportError::NoTlsModeSelected))
    }

    /// Initializes the selected transport from already-resolved startup
    /// configuration.
    pub async fn start_with_tls(&mut self, config: TlsConfig) -> Result<(), RuntimeError> {
        #[cfg(feature = "tls-psk")]
        {
            let TlsConfig::Psk(config) = config;
            self.transport = Some(TlsPskServer::new(config)?);
            Ok(())
        }

        #[cfg(all(target_os = "linux", feature = "tls-rustls", not(feature = "tls-psk")))]
        {
            let TlsConfig::Rustls(config) = config;
            self.rustls_transport = Some(TlsRustlsServer::new(config)?);
            Ok(())
        }

        #[cfg(all(
            feature = "tls-rustls",
            not(feature = "tls-psk"),
            not(target_os = "linux")
        ))]
        {
            let _ = config;
            Err(RuntimeError::Transport(
                TransportError::UnsupportedTlsRustls,
            ))
        }

        #[cfg(not(any(feature = "tls-psk", feature = "tls-rustls")))]
        {
            let _ = config;
            Err(RuntimeError::Transport(TransportError::NoTlsModeSelected))
        }
    }

    /// Serves the gRPC control API with the selected TLS transport.
    pub async fn serve(&self) -> Result<(), RuntimeError> {
        let address = self.config.snapshot().listener.socket_addr();
        #[cfg(all(feature = "tls-psk", not(target_os = "linux")))]
        {
            let _ = address;
            Err(RuntimeError::Transport(
                crate::transport::TransportError::UnsupportedTlsPsk,
            ))
        }

        #[cfg(all(
            feature = "tls-rustls",
            not(feature = "tls-psk"),
            not(target_os = "linux")
        ))]
        {
            let _ = address;
            Err(RuntimeError::Transport(
                crate::transport::TransportError::UnsupportedTlsRustls,
            ))
        }

        #[cfg(all(target_os = "linux", feature = "tls-psk"))]
        {
            let transport = self
                .transport
                .as_ref()
                .ok_or(crate::transport::TransportError::InvalidConfig)?;
            let incoming = transport.incoming(address).await?;
            Server::builder()
                .add_service(crate::proto::control_server::ControlServer::new(
                    (*self.service).clone(),
                ))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_err(RuntimeError::Grpc)
        }

        #[cfg(all(target_os = "linux", feature = "tls-rustls", not(feature = "tls-psk")))]
        {
            let transport = self
                .rustls_transport
                .as_ref()
                .ok_or(crate::transport::TransportError::InvalidConfig)?;
            let incoming = transport.incoming(address).await?;
            Server::builder()
                .add_service(crate::proto::control_server::ControlServer::new(
                    (*self.service).clone(),
                ))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_err(RuntimeError::Grpc)
        }

        #[cfg(not(any(feature = "tls-psk", feature = "tls-rustls")))]
        {
            let _ = address;
            Err(RuntimeError::Transport(TransportError::NoTlsModeSelected))
        }
    }

    /// Marks the service unready and detaches all backend-owned links.
    pub async fn shutdown(&mut self) -> Result<(), RuntimeError> {
        self.service.set_ready(false);
        let _ = self.shutdown.send(true);
        self.backend.detach(None).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::InMemoryBackend;

    #[tokio::test]
    async fn shutdown_cleans_owned_attachments() {
        let backend = InMemoryBackend::default();
        let mut runtime = ServiceRuntime::new(backend.clone());
        runtime.shutdown().await.unwrap();
        assert!(backend.attachments().is_empty());
    }
}
