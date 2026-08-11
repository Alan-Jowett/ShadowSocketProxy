// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Control-plane library combining BPF lifecycle, configuration, logs, ABI
//! mapping, gRPC service, and TLS transport modules.

#[cfg(all(feature = "tls-psk", feature = "tls-rustls"))]
compile_error!("tls-psk and tls-rustls are mutually exclusive");

/// BPF attachment, map, counter, and cleanup backends.
pub mod bpf;
/// Runtime configuration validation and atomic publication.
pub mod config;
/// Startup, serving, and shutdown orchestration.
pub mod lifecycle;
/// Bounded service log ring and cursor errors.
pub mod logs;
/// Shared tuple, flow-state, and map-ABI types.
pub mod mapping;
/// gRPC methods and protobuf/ABI conversion helpers.
pub mod service;
/// Feature-selected TLS listener for the control service.
pub mod transport;

/// Generated protobuf and tonic service bindings.
pub mod proto {
    tonic::include_proto!("shadow_socket_proxy.control.v1");
}
