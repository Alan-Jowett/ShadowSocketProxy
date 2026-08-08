// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Parses host-proxy options, loads the PSK, and runs TCP/UDP forwarding.

use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use shadow_socket_proxy_host::{Proxy, ProxyConfig, TlsPskMappingClient};
use tokio::sync::watch;

#[derive(Debug, Parser)]
#[command(name = "shadow-socket-proxy-host")]
/// Command-line settings for the host proxy and its control client.
struct Args {
    #[arg(long, default_value = "127.0.0.1:15000")]
    /// Specific local TCP/UDP listener address.
    listen: SocketAddr,
    #[arg(long, default_value = "https://127.0.0.1:50051")]
    /// TLS-PSK control-service endpoint.
    control_endpoint: String,
    #[arg(long)]
    /// Identity sent during control-service authentication.
    psk_identity: String,
    #[arg(long, env = "SSP_TLS_PSK_SECRET")]
    /// Inline PSK secret, mutually exclusive with `psk_secret_file`.
    psk_secret: Option<String>,
    #[arg(long)]
    /// File containing the PSK secret when inline credentials are omitted.
    psk_secret_file: Option<PathBuf>,
    #[arg(long, default_value_t = 60)]
    /// Seconds of UDP inactivity before an association is discarded.
    udp_idle_timeout_secs: u64,
}

/// Selects the inline secret or reads and trims the configured secret file.
fn load_secret(args: &Args) -> Result<Vec<u8>, String> {
    match (&args.psk_secret, &args.psk_secret_file) {
        (Some(_), Some(_)) => Err("provide only one PSK secret source".into()),
        (Some(secret), None) => Ok(secret.as_bytes().to_vec()),
        (None, Some(path)) => fs::read(path).map_err(|error| format!("read PSK secret: {error}")),
        (None, None) => Err("PSK secret is required".into()),
    }
}

#[tokio::main]
/// Validates options, connects the platform mapping client, and runs until the
/// shutdown watch is triggered or forwarding fails.
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let secret = match load_secret(&args) {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("invalid configuration: {error}");
            std::process::exit(2);
        }
    };
    let config = ProxyConfig {
        listen: args.listen,
        control_endpoint: args.control_endpoint.clone(),
        psk_identity: args.psk_identity.clone(),
        psk_secret: secret.clone(),
        udp_idle_timeout: Duration::from_secs(args.udp_idle_timeout_secs),
    };
    if let Err(error) = config.validate() {
        eprintln!("invalid configuration: {error}");
        std::process::exit(2);
    }
    let client =
        match TlsPskMappingClient::connect(&args.control_endpoint, &args.psk_identity, &secret)
            .await
        {
            Ok(client) => client,
            Err(error) => {
                eprintln!("control service initialization failed: {error}");
                std::process::exit(1);
            }
        };
    let proxy = Proxy::new(config, Arc::new(client)).expect("validated configuration");
    let (shutdown, receiver) = watch::channel(false);
    tokio::select! {
        result = proxy.run(receiver) => {
            if let Err(error) = result {
                eprintln!("host proxy failed: {error}");
                std::process::exit(1);
            }
        }
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                eprintln!("shutdown signal failed: {error}");
                std::process::exit(1);
            }
            let _ = shutdown.send(true);
        }
    }
}
