// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

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
pub enum RuntimeError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("transport error: {0}")]
    Transport(#[from] crate::transport::TransportError),
    #[error("backend cleanup error: {0}")]
    Backend(#[from] BackendError),
    #[error("gRPC server error: {0}")]
    Grpc(#[from] tonic::transport::Error),
}

pub struct ServiceRuntime<B: BpfBackend + 'static> {
    backend: Arc<B>,
    pub config: Arc<ConfigStore>,
    pub logs: Arc<LogRing>,
    pub stats: Arc<MaintenanceStats>,
    shutdown: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    worker: Option<tokio::task::JoinHandle<()>>,
    pub service: Arc<ControlService>,
    transport: Option<TlsPskServer>,
}

impl<B: BpfBackend + 'static> ServiceRuntime<B> {
    pub fn new(backend: B) -> Self {
        Self::new_with_listener(
            backend,
            "0.0.0.0:50051"
                .parse()
                .expect("valid default listener address"),
        )
    }

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

    pub async fn start_without_transport_for_tests(&mut self) {
        self.worker = Some(maintenance::spawn_worker(
            self.backend.clone(),
            self.config.clone(),
            self.stats.clone(),
            self.logs.clone(),
            self.shutdown_rx.clone(),
        ));
    }

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
