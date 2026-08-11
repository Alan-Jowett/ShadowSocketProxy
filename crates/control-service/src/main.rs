// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Starts the control runtime, serves gRPC, and detaches BPF state on exit.

use clap::Parser;
#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
use shadow_socket_proxy_control::{
    bpf::LinuxBpfBackend, lifecycle::ServiceRuntime, transport::TlsConfig,
};
#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
use std::net::SocketAddr;
use std::path::PathBuf;

#[cfg(feature = "tls-rustls")]
use shadow_socket_proxy_control::transport::TlsRustlsConfig;

#[cfg(all(feature = "tls-psk", feature = "tls-rustls"))]
compile_error!("tls-psk and tls-rustls are mutually exclusive");

#[derive(Debug, Parser)]
#[command(name = "shadow-socket-proxy-control")]
/// Startup-only control-service options.
struct Args {
    #[arg(long)]
    /// PEM certificate chain for the rustls listener.
    tls_cert_file: Option<PathBuf>,
    #[arg(long)]
    /// PEM private key for the rustls listener.
    tls_key_file: Option<PathBuf>,
    #[arg(long)]
    /// SHA-256 pin for the peer's leaf certificate.
    tls_peer_cert_sha256: Option<String>,
}

#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
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
fn resolve_tls_config(args: &Args) -> Result<TlsConfig, String> {
    let certificate_file = select_value(
        args.tls_cert_file.clone(),
        "SSP_TLS_CERT_FILE",
        PathBuf::from,
    )?;
    let key_file = select_value(args.tls_key_file.clone(), "SSP_TLS_KEY_FILE", PathBuf::from)?;
    let peer_pin = select_value(
        args.tls_peer_cert_sha256.clone(),
        "SSP_TLS_PEER_CERT_SHA256",
        |value| value,
    )?;

    #[cfg(feature = "tls-psk")]
    {
        if certificate_file.is_some() || key_file.is_some() || peer_pin.is_some() {
            return Err(
                "rustls TLS settings were supplied, but this binary was built with tls-psk".into(),
            );
        }
        Ok(TlsConfig::Psk(
            shadow_socket_proxy_control::transport::TlsPskConfig {
                identity: std::env::var("SSP_TLS_PSK_IDENTITY").unwrap_or_default(),
                secret: std::env::var("SSP_TLS_PSK_SECRET")
                    .map(|value| value.into_bytes())
                    .unwrap_or_default(),
            },
        ))
    }

    #[cfg(feature = "tls-rustls")]
    {
        if std::env::var_os("SSP_TLS_PSK_IDENTITY").is_some()
            || std::env::var_os("SSP_TLS_PSK_SECRET").is_some()
        {
            return Err("PSK settings cannot be combined with the tls-rustls feature".into());
        }
        let certificate_file = certificate_file.ok_or("TLS certificate file is required")?;
        let key_file = key_file.ok_or("TLS private key file is required")?;
        let peer_pin = peer_pin.ok_or("TLS peer certificate SHA-256 pin is required")?;
        let config = TlsRustlsConfig::load(certificate_file, key_file, &peer_pin)
            .map_err(|error| error.to_string())?;
        Ok(TlsConfig::Rustls(config))
    }

    #[cfg(not(any(feature = "tls-psk", feature = "tls-rustls")))]
    {
        let _ = (certificate_file, key_file, peer_pin);
        Err(TransportError::NoTlsModeSelected.to_string())
    }
}

#[tokio::main]
/// Builds the Linux backend, starts the runtime, and returns a process status
/// after serving or reporting a startup/runtime error.
#[cfg(any(feature = "tls-psk", feature = "tls-rustls"))]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let address = std::env::var("SSP_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".into())
        .parse::<SocketAddr>()
        .unwrap_or_else(|error| {
            eprintln!("invalid SSP_LISTEN_ADDR: {error}");
            std::process::exit(1);
        });
    if address.port() == 0 {
        eprintln!("invalid SSP_LISTEN_ADDR: listener port must be non-zero");
        std::process::exit(1);
    }
    let backend = match std::env::var("SSP_TC_HOOK_LAYOUT") {
        Ok(value) if value == "wsl" => LinuxBpfBackend::new_with_wsl_hooks(),
        Ok(value) => {
            eprintln!("invalid SSP_TC_HOOK_LAYOUT: expected wsl, got {value}");
            std::process::exit(1);
        }
        Err(std::env::VarError::NotPresent) => LinuxBpfBackend::new(),
        Err(error) => {
            eprintln!("invalid SSP_TC_HOOK_LAYOUT: {error}");
            std::process::exit(1);
        }
    };
    let mut runtime = ServiceRuntime::new_with_listener(backend, address);
    let tls_config = match resolve_tls_config(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("invalid TLS configuration: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = runtime.start_with_tls(tls_config).await {
        eprintln!("shadow-socket-proxy-control failed to start: {error}");
        std::process::exit(1);
    }
    eprintln!("control service: ready for BPF attachment at {address}");
    if let Err(error) = runtime.serve().await {
        eprintln!("shadow-socket-proxy-control server failed: {error}");
        std::process::exit(1);
    }
    if let Err(error) = runtime.shutdown().await {
        eprintln!("shadow-socket-proxy-control shutdown failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(any(feature = "tls-psk", feature = "tls-rustls")))]
/// Reports that a runnable control service must select exactly one TLS mode.
fn main() {
    eprintln!(
        "shadow-socket-proxy-control requires exactly one of the tls-psk or tls-rustls features"
    );
    std::process::exit(2);
}

#[cfg(all(test, any(feature = "tls-psk", feature = "tls-rustls")))]
mod tests {
    use super::*;

    #[test]
    fn duplicate_cli_and_environment_tls_values_are_rejected() {
        let env_name = "SSP_TEST_CONTROL_TLS_DUPLICATE";
        std::env::set_var(env_name, "environment");
        let result = select_value(Some("command-line".to_owned()), env_name, |value| value);
        std::env::remove_var(env_name);
        assert!(result.is_err());
    }
}
