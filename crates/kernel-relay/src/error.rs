// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Shared error types for the kernel-relay core.

use alloc::string::String;

/// Failures surfaced while validating tuples, framing opaque tunnel messages,
/// driving the state machine, or transporting raw gRPC bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelRelayError {
    /// The request or response envelope used an unsupported ABI version.
    UnsupportedAbiVersion { expected: u16, actual: u16 },
    /// The opaque tunnel frame used an unexpected direction discriminator.
    InvalidMessageDirection(u8),
    /// The opaque tunnel request kind is not supported by this build.
    InvalidRequestKind(u8),
    /// The opaque tunnel response status is unknown.
    InvalidResponseStatus(u8),
    /// The frame ended before its fixed-width header or declared payload.
    TruncatedFrame { expected: usize, actual: usize },
    /// A bounded payload exceeded the configured limit.
    PayloadTooLarge { actual: usize, max: usize },
    /// Family, address, port, or protocol validation failed.
    InvalidTuple(String),
    /// The returned protobuf did not match the requesting flow or bounds.
    InvalidMapping(String),
    /// A bounded queue or table refused a new operation.
    ResourceExhausted(&'static str),
    /// A state transition was invalid for the current flow lifecycle.
    InvalidState(String),
    /// The requested flow no longer exists.
    FlowNotFound { flow_id: u64, generation: u32 },
    /// A tunnel completion did not match a current pending request.
    RequestNotFound {
        request_id: u64,
        generation: u32,
        epoch: u64,
    },
    /// The remote control service reported that no mapping exists.
    MappingNotFound,
    /// Shutdown or explicit cancellation ended the operation.
    Cancelled(&'static str),
    /// The opaque gRPC transport failed before a valid reply arrived.
    Transport(String),
}

impl core::fmt::Display for KernelRelayError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for KernelRelayError {}
