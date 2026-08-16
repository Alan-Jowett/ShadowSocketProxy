// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Replaceable state-transition telemetry for the kernel relay.

#[cfg(not(ssp_wdk_native))]
use alloc::vec::Vec;
#[cfg(not(ssp_wdk_native))]
use std::sync::Mutex;

#[cfg(ssp_wsk_windows)]
use crate::windows::telemetry::emit_dbg_print;
use crate::{error::KernelRelayError, state::FlowState, tuple::FlowProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Execution level declared by the caller for the current transition.
pub enum ExecutionLevel {
    /// PASSIVE-level code paths may wait, allocate, and call pageable code.
    Passive,
    /// DISPATCH-level code paths must remain nonblocking and nonpageable.
    Dispatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Outcome emitted for every accepted or rejected state transition.
pub enum TransitionOutcome {
    /// The flow advanced to the next lifecycle state.
    Accepted(FlowState),
    /// The attempted action was rejected and the flow remained in place.
    Rejected(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Privacy-safe transition event emitted by the relay state machine.
pub struct TransitionEvent {
    /// Stable flow identity.
    pub flow_id: u64,
    /// Driver-generated request correlation when one exists.
    pub request_id: Option<u64>,
    /// Current generation paired with the flow identity.
    pub generation: u32,
    /// Canonical transport semantics for the flow.
    pub protocol: FlowProtocol,
    /// Prior state observed at the transition point.
    pub previous: FlowState,
    /// Accepted next state or rejection.
    pub outcome: TransitionOutcome,
    /// Short reason string suitable for DbgPrintEx or tests.
    pub reason: &'static str,
    /// Declared execution level for the transition.
    pub execution_level: ExecutionLevel,
}

/// Replaceable telemetry sink. Sink failure never changes relay correctness.
pub trait TelemetrySink: Send + Sync {
    /// Emits a privacy-safe transition event.
    fn emit(&self, event: &TransitionEvent) -> Result<(), KernelRelayError>;
}

#[derive(Debug, Default)]
/// Sink that drops all events.
pub struct NoopTelemetry;

impl TelemetrySink for NoopTelemetry {
    fn emit(&self, _event: &TransitionEvent) -> Result<(), KernelRelayError> {
        Ok(())
    }
}

#[cfg(not(ssp_wdk_native))]
#[derive(Debug, Default)]
/// Test sink that records all emitted events.
pub struct RecordingTelemetry {
    events: Mutex<Vec<TransitionEvent>>,
}

#[cfg(not(ssp_wdk_native))]
impl RecordingTelemetry {
    /// Returns a snapshot of the captured transition events.
    pub fn events(&self) -> Vec<TransitionEvent> {
        self.events.lock().expect("telemetry mutex").clone()
    }
}

#[cfg(not(ssp_wdk_native))]
impl TelemetrySink for RecordingTelemetry {
    fn emit(&self, event: &TransitionEvent) -> Result<(), KernelRelayError> {
        self.events
            .lock()
            .expect("telemetry mutex")
            .push(event.clone());
        Ok(())
    }
}

#[derive(Debug, Default)]
/// Test sink that always fails to prove telemetry failure isolation.
pub struct FailingTelemetry;

impl TelemetrySink for FailingTelemetry {
    fn emit(&self, _event: &TransitionEvent) -> Result<(), KernelRelayError> {
        Err(KernelRelayError::Transport(
            "telemetry sink rejected the event".into(),
        ))
    }
}

#[cfg(ssp_wsk_windows)]
#[derive(Debug, Default)]
/// Windows `DbgPrintEx` telemetry sink with heap-free DISPATCH formatting.
pub struct DbgPrintTelemetry;

#[cfg(ssp_wsk_windows)]
impl TelemetrySink for DbgPrintTelemetry {
    fn emit(&self, event: &TransitionEvent) -> Result<(), KernelRelayError> {
        emit_dbg_print(event)
    }
}
