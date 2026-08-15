// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Shared error types for the kernel-relay core.

use thiserror::Error;

/// Failures surfaced while validating tuples, framing opaque tunnel messages,
/// driving the state machine, or transporting raw gRPC bytes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KernelRelayError {
    #[error("unsupported tunnel ABI version: expected {expected}, got {actual}")]
    /// The request or response envelope used an unsupported ABI version.
    UnsupportedAbiVersion { expected: u16, actual: u16 },
    #[error("invalid message direction {0}")]
    /// The opaque tunnel frame used an unexpected direction discriminator.
    InvalidMessageDirection(u8),
    #[error("invalid request kind {0}")]
    /// The opaque tunnel request kind is not supported by this build.
    InvalidRequestKind(u8),
    #[error("invalid response status {0}")]
    /// The opaque tunnel response status is unknown.
    InvalidResponseStatus(u8),
    #[error("truncated tunnel frame: expected at least {expected} bytes, got {actual}")]
    /// The frame ended before its fixed-width header or declared payload.
    TruncatedFrame { expected: usize, actual: usize },
    #[error("payload too large: got {actual} bytes, limit is {max}")]
    /// A bounded payload exceeded the configured limit.
    PayloadTooLarge { actual: usize, max: usize },
    #[error("invalid tuple: {0}")]
    /// Family, address, port, or protocol validation failed.
    InvalidTuple(String),
    #[error("invalid mapping response: {0}")]
    /// The returned protobuf did not match the requesting flow or bounds.
    InvalidMapping(String),
    #[error("resource exhausted: {0}")]
    /// A bounded queue or table refused a new operation.
    ResourceExhausted(&'static str),
    #[error("state transition rejected: {0}")]
    /// A state transition was invalid for the current flow lifecycle.
    InvalidState(String),
    #[error("flow {flow_id}:{generation} not found")]
    /// The requested flow no longer exists.
    FlowNotFound { flow_id: u64, generation: u32 },
    #[error("request {request_id}:{generation}@{epoch} not found")]
    /// A tunnel completion did not match a current pending request.
    RequestNotFound {
        request_id: u64,
        generation: u32,
        epoch: u64,
    },
    #[error("mapping not found")]
    /// The remote control service reported that no mapping exists.
    MappingNotFound,
    #[error("operation cancelled: {0}")]
    /// Shutdown or explicit cancellation ended the operation.
    Cancelled(&'static str),
    #[error("transport error: {0}")]
    /// The opaque gRPC transport failed before a valid reply arrived.
    Transport(String),
}
