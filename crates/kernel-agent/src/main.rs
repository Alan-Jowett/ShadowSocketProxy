// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Opaque Windows device-to-control agent for the WSK kernel relay.

#[cfg(not(windows))]
compile_error!("shadow-socket-proxy-kernel-agent is a Windows-only executable");

#[cfg(windows)]
mod core;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
use clap::Parser;
#[cfg(windows)]
#[cfg(feature = "tls-psk")]
use shadow_socket_proxy_control_client::connect_psk;
#[cfg(windows)]
#[cfg(feature = "tls-rustls")]
use shadow_socket_proxy_control_client::connect_rustls;
#[cfg(windows)]
use shadow_socket_proxy_kernel_relay::{
    agent::{GrpcOpaqueTransport, HostTunnelAgent, OpaqueRpcTransport},
    device::{TunnelResponse, TunnelResponseStatus},
    ioctl::{IoctlTunnelTransport, TransportChannelState, TransportStatusReport},
};
#[cfg(windows)]
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
#[cfg(windows)]
use tokio::{task::JoinSet, time::sleep};
#[cfg(all(windows, feature = "tls-psk"))]
use zeroize::Zeroize;

#[cfg(windows)]
#[derive(Debug, Parser)]
#[command(name = "shadow-socket-proxy-kernel-agent")]
struct Args {
    #[arg(
        long,
        env = "SSP_KERNEL_DEVICE",
        default_value = r"\\.\ShadowSocketProxyKernelRelay"
    )]
    device: String,
    #[arg(long, env = "SSP_KERNEL_CONTROL_ENDPOINT")]
    control_endpoint: String,
    #[arg(long, env = "SSP_KERNEL_MAX_WORKERS", default_value_t = 32)]
    max_workers: usize,
    #[arg(long, env = "SSP_KERNEL_PSK_IDENTITY")]
    psk_identity: Option<String>,
    #[arg(long, env = "SSP_KERNEL_PSK_SECRET_FILE")]
    psk_secret_file: Option<PathBuf>,
    #[arg(long, env = "SSP_KERNEL_TLS_CERT_FILE")]
    tls_cert_file: Option<PathBuf>,
    #[arg(long, env = "SSP_KERNEL_TLS_KEY_FILE")]
    tls_key_file: Option<PathBuf>,
    #[arg(long, env = "SSP_KERNEL_TLS_PEER_CERT_SHA256")]
    tls_peer_cert_sha256: Option<String>,
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    if args.max_workers == 0 || args.max_workers > 1024 {
        return Err("max-workers must be between 1 and 1024".into());
    }
    if args.control_endpoint.is_empty() {
        return Err("control endpoint is required".into());
    }
    let device = windows::WindowsDevice::open(&args.device)?;
    let epoch = AtomicU64::new(0);
    let shutdown_io = IoctlTunnelTransport::new(device.clone());
    tokio::select! {
        result = run_agent(args, device, &epoch) => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            let _ = shutdown_io.report_transport(TransportStatusReport {
                state: TransportChannelState::ShuttingDown,
                epoch: epoch.load(Ordering::Acquire),
            }).await;
            Ok(())
        }
    }
}

#[cfg(windows)]
async fn run_agent(
    args: Args,
    device: windows::WindowsDevice,
    epoch: &AtomicU64,
) -> Result<(), Box<dyn std::error::Error>> {
    let io = IoctlTunnelTransport::new(device.clone());
    let mut retry = Duration::from_millis(100);
    loop {
        let transport = match connect_transport(&args).await {
            Ok(transport) => transport,
            Err(error) => {
                tracing::warn!(error = %error, "kernel agent control connection failed");
                sleep(retry).await;
                retry = retry.saturating_mul(2).min(Duration::from_secs(5));
                continue;
            }
        };
        retry = Duration::from_millis(100);
        let current_epoch = epoch.fetch_add(1, Ordering::AcqRel) + 1;
        io.report_transport(TransportStatusReport {
            state: TransportChannelState::Connected,
            epoch: current_epoch,
        })
        .await?;
        if let Err(error) = serve_until_disconnect(io.clone(), transport, args.max_workers).await {
            tracing::warn!(error = %error, "kernel agent transport stopped");
        }
        let _ = io
            .report_transport(TransportStatusReport {
                state: TransportChannelState::Disconnected,
                epoch: current_epoch,
            })
            .await;
        sleep(retry).await;
        retry = retry.saturating_mul(2).min(Duration::from_secs(5));
    }
}

#[cfg(windows)]
async fn serve_until_disconnect<R>(
    io: IoctlTunnelTransport<windows::WindowsDevice>,
    rpc: R,
    max_workers: usize,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: OpaqueRpcTransport + Clone + 'static,
{
    let agent = HostTunnelAgent::new(rpc);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_workers));
    let mut workers = JoinSet::new();
    let mut backoff = core::PollBackoff::new();
    loop {
        match io.dequeue_request().await {
            Ok(Some(request)) => {
                backoff.reset();
                let permit = semaphore.clone().acquire_owned().await?;
                let io = io.clone();
                let agent = agent.clone();
                workers.spawn(async move {
                    let _permit = permit;
                    let expected_epoch = request.epoch;
                    let response = agent.forward_request(request).await;
                    let response = if core::accepts_epoch(expected_epoch, response.epoch) {
                        response
                    } else {
                        TunnelResponse {
                            request_id: response.request_id,
                            generation: response.generation,
                            epoch: expected_epoch,
                            status: TunnelResponseStatus::InvalidState,
                            payload: Vec::new(),
                        }
                    };
                    io.complete_response(response).await
                });
                while let Some(result) = workers.try_join_next() {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(error = %error, "kernel-agent response completion failed");
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "kernel-agent worker task failed");
                        }
                    }
                }
            }
            Ok(None) => {
                sleep(backoff.delay()).await;
                backoff.idle();
            }
            Err(error) => {
                while let Some(result) = workers.join_next().await {
                    result??;
                }
                return Err(error.into());
            }
        }
    }
}

#[cfg(windows)]
async fn connect_transport(args: &Args) -> Result<GrpcOpaqueTransport, Box<dyn std::error::Error>> {
    #[cfg(all(feature = "tls-psk", feature = "tls-rustls"))]
    compile_error!("tls-psk and tls-rustls are mutually exclusive");

    #[cfg(feature = "tls-psk")]
    {
        let identity = args
            .psk_identity
            .as_deref()
            .ok_or("PSK identity is required")?;
        let path = args
            .psk_secret_file
            .as_ref()
            .ok_or("PSK secret file is required")?;
        let secret = std::fs::read(path)?;
        let channel = connect_psk(&args.control_endpoint, identity, &secret).await?;
        let mut secret = secret;
        secret.zeroize();
        return Ok(GrpcOpaqueTransport::new(channel));
    }
    #[cfg(feature = "tls-rustls")]
    {
        let cert = args
            .tls_cert_file
            .as_ref()
            .ok_or("TLS certificate is required")?;
        let key = args.tls_key_file.as_ref().ok_or("TLS key is required")?;
        let pin = args
            .tls_peer_cert_sha256
            .as_deref()
            .ok_or("TLS peer certificate pin is required")?;
        let channel = connect_rustls(&args.control_endpoint, cert, key, pin).await?;
        return Ok(GrpcOpaqueTransport::new(channel));
    }
    #[cfg(not(any(feature = "tls-psk", feature = "tls-rustls")))]
    {
        let _ = args;
        Err("build exactly one of tls-psk or tls-rustls".into())
    }
}
