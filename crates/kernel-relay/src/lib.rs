// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Host-independent WSK kernel-relay core.
//!
//! This crate keeps the driver-facing flow lifecycle, the complete
//! `GetMapping` protobuf construction and validation logic, the opaque tunnel
//! framing used by the first user-mode transport, and Windows-gated WSK/WDM
//! skeletons in one place without changing the existing Linux control service
//! or user-mode host proxy data path.

#![cfg_attr(ssp_wdk_native, no_std)]

extern crate alloc;
#[cfg(ssp_wdk_native)]
extern crate wdk_panic;
#[cfg(ssp_wdk_native)]
use wdk_alloc::WdkAllocator;
#[cfg(ssp_wdk_native)]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

#[cfg(feature = "opaque-user-tunnel")]
pub mod agent;
pub mod codec;
pub mod device;
pub mod error;
pub mod ioctl;
pub mod relay;
pub mod state;
pub mod telemetry;
pub mod tuple;
#[cfg(ssp_wsk_windows)]
pub mod windows;

pub use codec::{
    decode_get_mapping_response, encode_get_mapping_request, mapping_method_path,
    MAX_PROTO_MESSAGE_LEN,
};
pub use device::{
    MessageDirection, TunnelRequest, TunnelRequestKind, TunnelResponse, TunnelResponseStatus,
    MAX_TUNNEL_PAYLOAD_LEN, TUNNEL_ABI_VERSION, TUNNEL_HEADER_LEN,
};
pub use error::KernelRelayError;
pub use ioctl::{
    CancelTunnelRequest, TransportChannelState, TransportStatusReport, IOCTL_SSP_CANCEL_REQUEST,
    IOCTL_SSP_COMPLETE_RESPONSE, IOCTL_SSP_DEQUEUE_REQUEST, IOCTL_SSP_REPORT_TRANSPORT,
};
#[cfg(feature = "opaque-user-tunnel")]
pub use ioctl::{DeviceIoControlChannel, HostAgentIoctlBridge, IoctlTunnelTransport};
pub use relay::{DeadlineDisposition, RelayBuffers, RelayDirection, RelayState, TcpRelayOwnership};
pub use state::{
    CompletionDisposition, FlowAdmission, FlowController, FlowIdentity, FlowMode, FlowState,
    MappingReady, ResourceLimits,
};
#[cfg(not(ssp_wdk_native))]
pub use telemetry::RecordingTelemetry;
pub use telemetry::{
    ExecutionLevel, FailingTelemetry, NoopTelemetry, TelemetrySink, TransitionEvent,
    TransitionOutcome,
};
pub use tuple::{FlowProtocol, SocketTuple, ValidatedMapping};

/// Generated protobuf messages shared with the existing control plane.
pub mod proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/shadow_socket_proxy.control.v1.rs"
    ));
}

#[cfg(ssp_wdk_native)]
#[doc(hidden)]
pub mod wsk_bindings {
    #![allow(
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        dead_code,
        unnecessary_transmutes,
        clippy::all
    )]
    include!(concat!(env!("OUT_DIR"), "/wsk_bindings.rs"));
}
