// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Heap-free `DbgPrintEx` telemetry formatting for DISPATCH-safe state
//! transitions.

use core::fmt::{self, Write};

use crate::{
    error::KernelRelayError,
    telemetry::{ExecutionLevel, TransitionEvent, TransitionOutcome},
};

use super::ffi;

struct StackBuffer<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> StackBuffer<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_c_str(&mut self) -> *const u8 {
        let terminator = self.len.min(N.saturating_sub(1));
        self.bytes[terminator] = 0;
        self.bytes.as_ptr()
    }
}

impl<const N: usize> Write for StackBuffer<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let available = N.saturating_sub(self.len + 1);
        if available == 0 {
            return Ok(());
        }
        let copy_len = available.min(text.len());
        self.bytes[self.len..self.len + copy_len].copy_from_slice(&text.as_bytes()[..copy_len]);
        self.len += copy_len;
        Ok(())
    }
}

pub(crate) fn emit_dbg_print(event: &TransitionEvent) -> Result<(), KernelRelayError> {
    let mut buffer = StackBuffer::<384>::new();
    write!(buffer, "SSP-WKR flow={} req=", event.flow_id)
        .map_err(|_| KernelRelayError::Transport("DbgPrintEx formatting failed".into()))?;
    match event.request_id {
        Some(request_id) => write!(buffer, "{request_id}").ok(),
        None => buffer.write_str("-").ok(),
    };
    let _ = write!(
        buffer,
        " gen={} proto={:?} prev={:?} ",
        event.generation, event.protocol, event.previous
    );
    match event.outcome {
        TransitionOutcome::Accepted(next) => {
            let _ = write!(buffer, "next={next:?}");
        }
        TransitionOutcome::Rejected(reason) => {
            let _ = write!(buffer, "rejected={reason}");
        }
    }
    let _ = write!(
        buffer,
        " reason={} irql={:?}",
        event.reason, event.execution_level
    );

    let level = match event.execution_level {
        ExecutionLevel::Passive => ffi::DPFLTR_INFO_LEVEL,
        ExecutionLevel::Dispatch => ffi::DPFLTR_ERROR_LEVEL,
    };
    #[cfg(ssp_wdk_native)]
    unsafe {
        ffi::DbgPrintEx(
            ffi::DPFLTR_IHVNETWORK_ID,
            level,
            b"%s\0".as_ptr(),
            buffer.as_c_str(),
        );
    }
    #[cfg(not(ssp_wdk_native))]
    let _ = (level, buffer.as_c_str());
    Ok(())
}
