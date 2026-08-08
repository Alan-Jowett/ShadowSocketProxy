// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Starts the control runtime, serves gRPC, and detaches BPF state on exit.

use shadow_socket_proxy_control::{bpf::LinuxBpfBackend, lifecycle::ServiceRuntime};
use std::net::SocketAddr;

#[tokio::main]
/// Builds the Linux backend, starts the runtime, and returns a process status
/// after serving or reporting a startup/runtime error.
async fn main() {
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
    if let Err(error) = runtime.start().await {
        eprintln!("shadow-socket-proxy-control failed to start: {error}");
        std::process::exit(1);
    }
    if let Err(error) = runtime.serve().await {
        eprintln!("shadow-socket-proxy-control server failed: {error}");
        std::process::exit(1);
    }
    if let Err(error) = runtime.shutdown().await {
        eprintln!("shadow-socket-proxy-control shutdown failed: {error}");
        std::process::exit(1);
    }
}
