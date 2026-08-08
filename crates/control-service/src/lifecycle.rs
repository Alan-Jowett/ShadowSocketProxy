// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Owns startup, maintenance-task lifetime, transport serving, and shutdown
//! ordering for the control service.

use std::{net::SocketAddr, sync::Arc};

use thiserror::Error;
use tokio::sync::watch;
#[cfg(target_os = "linux")]
use tonic::transport::Server;

use crate::{
    bpf::{BackendError, BpfBackend},
    config::{ConfigError, ConfigStore, RuntimeConfig},
    logs::LogRing,
    maintenance::{self, MaintenanceStats},
    service::ControlService,
    transport::{TlsPskConfig, TlsPskServer},
};

#[derive(Debug, Error)]
/// Startup, serving, or cleanup failure at the runtime boundary.
pub enum RuntimeError {
    #[error("configuration error: {0}")]
    /// Initial or updated runtime configuration was invalid.
    Config(#[from] ConfigError),
    #[error("transport error: {0}")]
    /// TLS-PSK transport initialization or binding failed.
    Transport(#[from] crate::transport::TransportError),
    #[error("backend cleanup error: {0}")]
    /// BPF detachment or cleanup failed during shutdown.
    Backend(#[from] BackendError),
    #[error("gRPC server error: {0}")]
    /// The tonic server terminated with a transport error.
    Grpc(#[from] tonic::transport::Error),
}

/// Coordinates the backend, control RPC state, maintenance worker, and server.
pub struct ServiceRuntime<B: BpfBackend + 'static> {
    /// Backend used to attach and maintain the BPF program.
    backend: Arc<B>,
    /// Shared validated runtime configuration.
    pub config: Arc<ConfigStore>,
    /// Bounded service log ring.
    pub logs: Arc<LogRing>,
    /// Maintenance worker statistics.
    pub stats: Arc<MaintenanceStats>,
    /// Shutdown signal owned by this runtime.
    shutdown: watch::Sender<bool>,
    /// Receiver used by serving and maintenance tasks.
    shutdown_rx: watch::Receiver<bool>,
    /// Optional maintenance task handle.
    worker: Option<tokio::task::JoinHandle<()>>,
    /// gRPC control service instance.
    pub service: Arc<ControlService>,
    /// Optional TLS transport server.
    transport: Option<TlsPskServer>,
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
        let stats = Arc::new(MaintenanceStats::default());
        let backend = Arc::new(backend);
        let service = Arc::new(ControlService::new(
            backend.clone(),
            config.clone(),
            logs.clone(),
            stats.clone(),
        ));
        let (shutdown, shutdown_rx) = watch::channel(false);
        Self {
            backend,
            config,
            logs,
            stats,
            shutdown,
            shutdown_rx,
            worker: None,
            service,
            transport: None,
        }
    }

    /// Reads TLS-PSK credentials from the environment, initializes transport,
    /// and starts maintenance.
    pub async fn start(&mut self) -> Result<(), RuntimeError> {
        self.transport = Some(TlsPskServer::new(TlsPskConfig {
            identity: std::env::var("SSP_TLS_PSK_IDENTITY").unwrap_or_default(),
            secret: std::env::var("SSP_TLS_PSK_SECRET")
                .map(|value| value.into_bytes())
                .unwrap_or_default(),
        })?);
        self.start_without_transport_for_tests().await;
        Ok(())
    }

    /// Starts only maintenance; intended for environments without TLS transport.
    pub async fn start_without_transport_for_tests(&mut self) {
        self.worker = Some(maintenance::spawn_worker(
            self.backend.clone(),
            self.config.clone(),
            self.stats.clone(),
            self.logs.clone(),
            self.shutdown_rx.clone(),
        ));
    }

    /// Serves the gRPC control API with TLS-PSK on Linux; other platforms
    /// return `UnsupportedTlsPsk`.
    pub async fn serve(&self) -> Result<(), RuntimeError> {
        let address = self.config.snapshot().listener.socket_addr();
        #[cfg(not(target_os = "linux"))]
        {
            let _ = address;
            return Err(RuntimeError::Transport(
                crate::transport::TransportError::UnsupportedTlsPsk,
            ));
        }

        #[cfg(target_os = "linux")]
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
    }

    /// Marks the service unready, stops maintenance, waits for it, then detaches
    /// all backend-owned links.
    pub async fn shutdown(&mut self) -> Result<(), RuntimeError> {
        self.service.set_ready(false);
        let _ = self.shutdown.send(true);
        if let Some(worker) = self.worker.take() {
            let _ = worker.await;
        }
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
        runtime.start_without_transport_for_tests().await;
        runtime.shutdown().await.unwrap();
        assert!(backend.attachments().is_empty());
    }
}
