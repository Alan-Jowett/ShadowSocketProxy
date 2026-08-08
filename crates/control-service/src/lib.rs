// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Control-plane library combining BPF lifecycle, configuration, maintenance,
//! logs, ABI mapping, gRPC service, and TLS transport modules.

/// BPF attachment, map, counter, and cleanup backends.
pub mod bpf;
/// Runtime configuration validation and atomic publication.
pub mod config;
/// Startup, serving, maintenance, and shutdown orchestration.
pub mod lifecycle;
/// Bounded service log ring and cursor errors.
pub mod logs;
/// Expiration scans and maintenance statistics.
pub mod maintenance;
/// Shared tuple, flow-state, and map-ABI types.
pub mod mapping;
/// gRPC methods and protobuf/ABI conversion helpers.
pub mod service;
/// Linux TLS-PSK listener for the control service.
pub mod transport;

/// Generated protobuf and tonic service bindings.
pub mod proto {
    tonic::include_proto!("shadow_socket_proxy.control.v1");
}
