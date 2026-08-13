// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Parses host-proxy options, initializes the selected TLS client, and runs
//! TCP/UDP forwarding.

#[cfg(feature = "tls-psk")]
use std::fs;
#[cfg(feature = "tls-rustls")]
use std::path::Path;
use std::{net::SocketAddr, path::PathBuf};
#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
use std::{sync::Arc, time::Duration};

#[cfg(all(feature = "wsk", target_os = "windows"))]
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
#[cfg(feature = "tls-psk")]
use shadow_socket_proxy_host::TlsPskMappingClient;
#[cfg(feature = "tls-rustls")]
use shadow_socket_proxy_host::TlsRustlsMappingClient;
#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
use shadow_socket_proxy_host::{Proxy, ProxyConfig};
#[cfg(all(feature = "wsk", target_os = "windows"))]
use shadow_socket_proxy_host::wsk::WskDeviceClient;
use tokio::sync::watch;

#[cfg(all(feature = "tls-psk", feature = "tls-rustls"))]
compile_error!("tls-psk and tls-rustls are mutually exclusive");

#[derive(Debug, Parser)]
#[command(name = "shadow-socket-proxy-host")]
/// Command-line settings for the host proxy and its control client.
struct Args {
    #[arg(long, default_value = "127.0.0.1:15000")]
    /// Specific local TCP/UDP listener address.
    listen: SocketAddr,
    #[arg(long, default_value_t = 1024)]
    /// Native TCP listen backlog; Windows conditional work is fixed at one
    /// queue-head attempt regardless of this value.
    listen_backlog: u32,
    #[arg(long, default_value = "https://127.0.0.1:50051")]
    /// TLS control-service endpoint.
    control_endpoint: String,
    #[arg(long)]
    /// Identity sent during TLS-PSK control-service authentication.
    psk_identity: Option<String>,
    #[arg(long, env = "SSP_TLS_PSK_SECRET")]
    /// Inline PSK secret, mutually exclusive with `psk_secret_file`.
    psk_secret: Option<String>,
    #[arg(long)]
    /// File containing the PSK secret when inline credentials are omitted.
    psk_secret_file: Option<PathBuf>,
    #[arg(long)]
    /// PEM certificate chain used by the rustls control client.
    tls_cert_file: Option<PathBuf>,
    #[arg(long)]
    /// PEM private key used by the rustls control client.
    tls_key_file: Option<PathBuf>,
    #[arg(long)]
    /// SHA-256 pin for the control service's leaf certificate.
    tls_peer_cert_sha256: Option<String>,
    #[arg(long)]
    /// BPF ELF path as visible from the Linux control service.
    bpf_elf: String,
    #[arg(long)]
    /// WSL interface on which the control service attaches the BPF programs.
    interface: String,
    #[arg(long, default_value_t = 60)]
    /// Seconds of UDP inactivity before an association is discarded.
    udp_idle_timeout_secs: u64,
    #[arg(long, default_value_t = 10)]
    /// Seconds between host-owned flow maintenance passes.
    cleanup_interval_secs: u64,
    #[arg(long, default_value_t = 60)]
    /// Seconds before an incomplete flow is considered idle.
    idle_ttl_secs: u64,
    #[arg(long, default_value_t = 30)]
    /// Seconds of grace after a completed TCP close.
    tcp_terminal_grace_secs: u64,
    #[arg(long, default_value_t = 256)]
    /// Maximum number of flows requested in one maintenance page.
    flow_scan_batch: u32,
    #[cfg(feature = "wsk")]
    #[arg(long)]
    /// Use the installed WSK driver instead of Tokio TCP/UDP listeners.
    wsk: bool,
}

#[cfg(all(feature = "wsk", target_os = "windows"))]
fn client_nonce() -> shadow_socket_proxy_host::wsk::abi::SessionNonce {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    let address = (&now as *const [u8; 16] as usize).to_le_bytes();
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&now);
    for (index, byte) in address.iter().enumerate() {
        bytes[16 + index] = *byte;
    }
    shadow_socket_proxy_host::wsk::abi::SessionNonce::new(bytes)
}

/// Selects the inline secret or reads and trims the configured secret file.
#[cfg(feature = "tls-psk")]
fn load_secret(args: &Args) -> Result<Vec<u8>, String> {
    match (&args.psk_secret, &args.psk_secret_file) {
        (Some(_), Some(_)) => Err("provide only one PSK secret source".into()),
        (Some(secret), None) => Ok(secret.as_bytes().to_vec()),
        (None, Some(path)) => fs::read(path).map_err(|error| format!("read PSK secret: {error}")),
        (None, None) => Err("PSK secret is required".into()),
    }
}

#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
/// Runtime certificate and peer-pin settings for rustls mode.
type RustlsOptions = (Option<PathBuf>, Option<PathBuf>, Option<String>);

#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
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

#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
/// Resolves rustls certificate and peer-pin settings.
fn resolve_rustls_options(args: &Args) -> Result<RustlsOptions, String> {
    Ok((
        select_value(
            args.tls_cert_file.clone(),
            "SSP_TLS_CERT_FILE",
            PathBuf::from,
        )?,
        select_value(args.tls_key_file.clone(), "SSP_TLS_KEY_FILE", PathBuf::from)?,
        select_value(
            args.tls_peer_cert_sha256.clone(),
            "SSP_TLS_PEER_CERT_SHA256",
            |value| value,
        )?,
    ))
}

#[cfg(feature = "tls-psk")]
/// Connects to the control service using the selected PSK credentials.
async fn connect_client(
    args: &Args,
    secret: &[u8],
) -> Result<TlsPskMappingClient, shadow_socket_proxy_host::ProxyError> {
    let identity = args.psk_identity.as_deref().ok_or_else(|| {
        shadow_socket_proxy_host::ProxyError::InvalidConfiguration(
            "PSK identity is required in tls-psk mode".into(),
        )
    })?;
    TlsPskMappingClient::connect(&args.control_endpoint, identity, secret).await
}

#[cfg(feature = "tls-rustls")]
/// Connects to the control service using the selected rustls credentials.
async fn connect_client(
    args: &Args,
    tls_cert_file: &Path,
    tls_key_file: &Path,
    tls_peer_cert_sha256: &str,
) -> Result<TlsRustlsMappingClient, shadow_socket_proxy_host::ProxyError> {
    TlsRustlsMappingClient::connect(
        &args.control_endpoint,
        tls_cert_file,
        tls_key_file,
        tls_peer_cert_sha256,
    )
    .await
}

#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
/// Builds the host-proxy runtime configuration.
fn proxy_config(args: &Args, psk_identity: String, psk_secret: Vec<u8>) -> ProxyConfig {
    ProxyConfig {
        listen: args.listen,
        listen_backlog: args.listen_backlog,
        control_endpoint: args.control_endpoint.clone(),
        psk_identity,
        psk_secret,
        udp_idle_timeout: Duration::from_secs(args.udp_idle_timeout_secs),
        cleanup_interval: Duration::from_secs(args.cleanup_interval_secs),
        idle_ttl: Duration::from_secs(args.idle_ttl_secs),
        tcp_terminal_grace: Duration::from_secs(args.tcp_terminal_grace_secs),
        flow_scan_batch: args.flow_scan_batch,
    }
}

#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
/// Validates options, connects the platform mapping client, and runs until the
/// shutdown watch is triggered or forwarding fails.
async fn run() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let (tls_cert_file, tls_key_file, tls_peer_cert_sha256) = match resolve_rustls_options(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("invalid TLS configuration: {error}");
            std::process::exit(2);
        }
    };

    #[cfg(feature = "tls-psk")]
    let secret = match load_secret(&args) {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("invalid configuration: {error}");
            std::process::exit(2);
        }
    };

    #[cfg(feature = "tls-psk")]
    if tls_cert_file.is_some() || tls_key_file.is_some() || tls_peer_cert_sha256.is_some() {
        eprintln!("rustls TLS settings require building with the tls-rustls feature");
        std::process::exit(2);
    }

    #[cfg(feature = "tls-rustls")]
    if args.psk_identity.is_some() || args.psk_secret.is_some() || args.psk_secret_file.is_some() {
        eprintln!("PSK settings cannot be combined with the tls-rustls feature");
        std::process::exit(2);
    }

    #[cfg(feature = "tls-rustls")]
    let (tls_cert_file, tls_key_file, tls_peer_cert_sha256) =
        match (tls_cert_file, tls_key_file, tls_peer_cert_sha256) {
            (Some(cert), Some(key), Some(pin)) => (cert, key, pin),
            _ => {
                eprintln!(
                    "invalid TLS configuration: --tls-cert-file, --tls-key-file, and \
                 --tls-peer-cert-sha256 are required"
                );
                std::process::exit(2);
            }
        };

    #[cfg(feature = "tls-psk")]
    let config = proxy_config(
        &args,
        args.psk_identity.clone().unwrap_or_default(),
        secret.clone(),
    );
    #[cfg(feature = "tls-rustls")]
    let config = proxy_config(&args, String::new(), Vec::new());
    if let Err(error) = config.validate() {
        eprintln!("invalid configuration: {error}");
        std::process::exit(2);
    }
    #[cfg(feature = "tls-psk")]
    if let Err(error) = config.validate_tls_psk() {
        eprintln!("invalid configuration: {error}");
        std::process::exit(2);
    }
    #[cfg(feature = "tls-psk")]
    let client = match connect_client(&args, &secret).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!("control service initialization failed: {error}");
            std::process::exit(1);
        }
    };
    #[cfg(feature = "tls-rustls")]
    let client =
        match connect_client(&args, &tls_cert_file, &tls_key_file, &tls_peer_cert_sha256).await {
            Ok(client) => client,
            Err(error) => {
                eprintln!("control service initialization failed: {error}");
                std::process::exit(1);
            }
        };
    eprintln!(
        "host proxy: connected to control service at {}",
        args.control_endpoint
    );
    let proxy =
        Proxy::new(config.clone(), Arc::new(client.clone())).expect("validated configuration");

    #[cfg(all(feature = "wsk", target_os = "windows"))]
    if args.wsk {
        if args.listen.port() != 15_000 {
            eprintln!("WSK mode requires --listen port 15000");
            std::process::exit(2);
        }
        let device = match WskDeviceClient::connect(client_nonce()) {
            Ok(device) => device,
            Err(error) => {
                eprintln!("WSK device initialization failed: {error}");
                std::process::exit(1);
            }
        };
        if let Err(error) = client
            .activate(&args.bpf_elf, &args.interface, args.listen)
            .await
        {
            eprintln!("control service activation failed: {error}");
            std::process::exit(1);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (shutdown, receiver) = watch::channel(false);
        let broker_client = Arc::new(client.clone());
        let broker_stop = stop.clone();
        let mut broker_task = tokio::task::spawn_blocking(move || {
            WskDeviceClient::run_mapping_broker(device, broker_client, broker_stop)
        });
        let maintenance = proxy.run_wsk_maintenance(receiver);
        tokio::pin!(maintenance);
        let mut broker_finished = false;
        let result = tokio::select! {
            result = &mut broker_task => {
                broker_finished = true;
                result
                    .map_err(|error| shadow_socket_proxy_host::ProxyError::Control(error.to_string()))
                    .and_then(|result| result.map_err(|error| shadow_socket_proxy_host::ProxyError::Control(error.to_string())))
            },
            result = &mut maintenance => {
                let _ = result;
                Ok(())
            },
            result = tokio::signal::ctrl_c() => {
                result.map_err(shadow_socket_proxy_host::ProxyError::Io)
            }
        };
        stop.store(true, Ordering::Release);
        let _ = shutdown.send(true);
        if !broker_finished {
            let _ = tokio::time::timeout(Duration::from_secs(6), &mut broker_task).await;
        }
        if let Err(error) =
            tokio::time::timeout(Duration::from_secs(5), client.detach(&args.interface))
                .await
                .map_err(|_| {
                    shadow_socket_proxy_host::ProxyError::Control("control detach timed out".into())
                })
                .and_then(|result| result)
        {
            eprintln!("control service detachment failed: {error}");
            std::process::exit(1);
        }
        if let Err(error) = result {
            eprintln!("host proxy failed: {error}");
            std::process::exit(1);
        }
        return;
    }

    let (tcp_listener, udp_socket) = match proxy.bind().await {
        Ok(listeners) => listeners,
        Err(error) => {
            eprintln!("host proxy bind failed: {error}");
            std::process::exit(1);
        }
    };
    let proxy_address = match tcp_listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            eprintln!("host proxy listener address lookup failed: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = client
        .activate(&args.bpf_elf, &args.interface, proxy_address)
        .await
    {
        eprintln!("control service activation failed: {error}");
        std::process::exit(1);
    }
    eprintln!(
        "host proxy: attached BPF {} to {} and configured proxy target {}",
        args.bpf_elf, args.interface, proxy_address
    );
    let control = client.clone();
    let (shutdown, receiver) = watch::channel(false);
    let mut proxy_task = tokio::spawn(proxy.run_bound(tcp_listener, udp_socket, receiver));
    let result = tokio::select! {
        result = &mut proxy_task => result
            .map_err(|error| shadow_socket_proxy_host::ProxyError::Control(error.to_string()))
            .and_then(|result| result),
        result = tokio::signal::ctrl_c() => {
            match result {
                Err(error) => Err(shadow_socket_proxy_host::ProxyError::Io(error)),
                Ok(()) => {
                    let _ = shutdown.send(true);
                    proxy_task
                        .await
                        .map_err(|error| shadow_socket_proxy_host::ProxyError::Control(error.to_string()))
                        .and_then(|result| result)
                }
            }
        }
    };
    if let Err(error) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.detach(&args.interface),
    )
    .await
    .map_err(|_| shadow_socket_proxy_host::ProxyError::Control("control detach timed out".into()))
    .and_then(|result| result)
    {
        tracing::error!(interface = %args.interface, error = %error, "control-service detach failed");
        eprintln!("control service detachment failed: {error}");
        std::process::exit(1);
    }
    if let Err(error) = result {
        eprintln!("host proxy failed: {error}");
        std::process::exit(1);
    }
}

#[tokio::main]
/// Selects a TLS feature at compile time and rejects an unconfigured
/// runnable binary at startup.
async fn main() {
    #[cfg(not(any(feature = "tls-psk", feature = "tls-rustls")))]
    {
        eprintln!(
            "shadow-socket-proxy-host requires exactly one of the tls-psk or tls-rustls features"
        );
        std::process::exit(2);
    }

    #[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
    run().await;
}

#[cfg(all(test, any(feature = "tls-psk", feature = "tls-rustls")))]
mod tests {
    use super::*;

    #[test]
    fn duplicate_cli_and_environment_tls_values_are_rejected() {
        let env_name = "SSP_TEST_HOST_TLS_DUPLICATE";
        std::env::set_var(env_name, "environment");
        let result = select_value(Some("command-line".to_owned()), env_name, |value| value);
        std::env::remove_var(env_name);
        assert!(result.is_err());
    }
}
