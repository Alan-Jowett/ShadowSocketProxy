// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

pub mod bpf;
pub mod config;
pub mod lifecycle;
pub mod logs;
pub mod maintenance;
pub mod mapping;
pub mod service;
pub mod transport;

pub mod proto {
    tonic::include_proto!("shadow_socket_proxy.control.v1");
}
