// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Host-independent TCP relay ownership, half-close, deadline, and bounds
//! bookkeeping used by the native Windows relay path.

use crate::error::KernelRelayError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Direction of one TCP byte stream.
pub enum RelayDirection {
    /// Client-to-original-destination traffic.
    ClientToOrigin,
    /// Original-destination-to-client traffic.
    OriginToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Observable relay state for one connected TCP pair.
pub enum RelayState {
    /// The outbound socket has not yet been published.
    Connecting,
    /// Both sockets are owned by the relay and data may flow both ways.
    Relaying,
    /// One half closed or shutdown began; reverse draining may continue.
    Draining,
    /// The relay released both socket owners.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Result of polling or expiring relay deadlines.
pub enum DeadlineDisposition {
    /// No deadline fired.
    Pending,
    /// The relay expired and should close for the given reason.
    Expired(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Bounded relay buffer accounting.
pub struct RelayBuffers {
    /// Maximum bytes that may be in flight at once.
    pub max_bytes: usize,
    /// Current accounted bytes.
    pub in_flight_bytes: usize,
}

impl RelayBuffers {
    /// Creates bounded buffer accounting with the given limit.
    pub const fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            in_flight_bytes: 0,
        }
    }

    /// Reserves bytes or rejects the operation without partial success.
    pub fn reserve(&mut self, bytes: usize) -> Result<(), KernelRelayError> {
        let Some(total) = self.in_flight_bytes.checked_add(bytes) else {
            return Err(KernelRelayError::ResourceExhausted(
                "relay buffer accounting overflowed",
            ));
        };
        if total > self.max_bytes {
            return Err(KernelRelayError::ResourceExhausted(
                "relay buffer bound exceeded",
            ));
        }
        self.in_flight_bytes = total;
        Ok(())
    }

    /// Releases bytes back to the relay budget.
    pub fn release(&mut self, bytes: usize) {
        self.in_flight_bytes = self.in_flight_bytes.saturating_sub(bytes);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// TCP relay ownership model with half-close and deadline bookkeeping.
pub struct TcpRelayOwnership {
    state: RelayState,
    client_owned: bool,
    origin_owned: bool,
    client_to_origin_open: bool,
    origin_to_client_open: bool,
    connect_deadline_ns: u64,
    idle_deadline_ns: Option<u64>,
    shutdown_deadline_ns: Option<u64>,
    /// Explicit bounded relay buffers shared by both directions.
    pub buffers: RelayBuffers,
}

impl TcpRelayOwnership {
    /// Creates a connecting relay with explicit connect and buffer bounds.
    pub fn new(connect_deadline_ns: u64, max_buffer_bytes: usize) -> Self {
        Self {
            state: RelayState::Connecting,
            client_owned: true,
            origin_owned: false,
            client_to_origin_open: true,
            origin_to_client_open: true,
            connect_deadline_ns,
            idle_deadline_ns: None,
            shutdown_deadline_ns: None,
            buffers: RelayBuffers::new(max_buffer_bytes),
        }
    }

    /// Publishes the outbound socket and starts the relay idle deadline.
    pub fn connected(&mut self, now_ns: u64, idle_timeout_ns: u64) -> Result<(), KernelRelayError> {
        if self.state != RelayState::Connecting {
            return Err(KernelRelayError::InvalidState(
                "relay publish requires the connecting state".into(),
            ));
        }
        self.origin_owned = true;
        self.state = RelayState::Relaying;
        self.idle_deadline_ns = now_ns.checked_add(idle_timeout_ns);
        Ok(())
    }

    /// Records activity and extends the idle deadline when the relay is live.
    pub fn record_activity(&mut self, now_ns: u64, idle_timeout_ns: u64) {
        if self.state != RelayState::Closed {
            self.idle_deadline_ns = now_ns.checked_add(idle_timeout_ns);
        }
    }

    /// Models EOF on one direction and preserves reverse draining semantics.
    pub fn half_close(
        &mut self,
        direction: RelayDirection,
    ) -> Result<RelayState, KernelRelayError> {
        if self.state == RelayState::Closed {
            return Err(KernelRelayError::InvalidState(
                "cannot half-close a released relay".into(),
            ));
        }
        match direction {
            RelayDirection::ClientToOrigin => self.client_to_origin_open = false,
            RelayDirection::OriginToClient => self.origin_to_client_open = false,
        }
        if !self.client_to_origin_open && !self.origin_to_client_open {
            self.release_all();
        } else {
            self.state = RelayState::Draining;
        }
        Ok(self.state)
    }

    /// Starts bounded shutdown draining without releasing ownership early.
    pub fn begin_shutdown(&mut self, now_ns: u64, drain_timeout_ns: u64) {
        if self.state != RelayState::Closed {
            self.state = RelayState::Draining;
            self.shutdown_deadline_ns = now_ns.checked_add(drain_timeout_ns);
        }
    }

    /// Polls connect, idle, and shutdown deadlines.
    pub fn poll_deadlines(&mut self, now_ns: u64) -> DeadlineDisposition {
        if self.state == RelayState::Closed {
            return DeadlineDisposition::Pending;
        }
        if self.state == RelayState::Connecting && now_ns >= self.connect_deadline_ns {
            self.release_all();
            return DeadlineDisposition::Expired("connect deadline");
        }
        if let Some(deadline) = self.shutdown_deadline_ns {
            if now_ns >= deadline {
                self.release_all();
                return DeadlineDisposition::Expired("shutdown deadline");
            }
        }
        if let Some(deadline) = self.idle_deadline_ns {
            if now_ns >= deadline {
                self.release_all();
                return DeadlineDisposition::Expired("idle deadline");
            }
        }
        DeadlineDisposition::Pending
    }

    /// Releases both sockets and all deadlines after a fatal failure.
    pub fn abort(&mut self) {
        self.release_all();
    }

    /// Returns the current relay state.
    pub const fn state(&self) -> RelayState {
        self.state
    }

    /// Indicates that the client-side socket is still owned by the relay.
    pub const fn owns_client(&self) -> bool {
        self.client_owned
    }

    /// Indicates that the origin-side socket is still owned by the relay.
    pub const fn owns_origin(&self) -> bool {
        self.origin_owned
    }

    fn release_all(&mut self) {
        self.state = RelayState::Closed;
        self.client_owned = false;
        self.origin_owned = false;
        self.client_to_origin_open = false;
        self.origin_to_client_open = false;
        self.idle_deadline_ns = None;
        self.shutdown_deadline_ns = None;
        self.buffers.release(self.buffers.in_flight_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_close_preserves_reverse_drain_until_both_directions_finish() {
        let mut relay = TcpRelayOwnership::new(50, 128);
        relay.connected(10, 20).expect("connect should publish");
        assert_eq!(
            relay
                .half_close(RelayDirection::ClientToOrigin)
                .expect("half close should succeed"),
            RelayState::Draining
        );
        assert!(relay.owns_client());
        assert!(relay.owns_origin());
        assert_eq!(
            relay
                .half_close(RelayDirection::OriginToClient)
                .expect("second half close should succeed"),
            RelayState::Closed
        );
        assert!(!relay.owns_client());
        assert!(!relay.owns_origin());
    }

    #[test]
    fn connect_deadline_expires_unpublished_socket() {
        let mut relay = TcpRelayOwnership::new(30, 64);
        assert_eq!(
            relay.poll_deadlines(30),
            DeadlineDisposition::Expired("connect deadline")
        );
        assert_eq!(relay.state(), RelayState::Closed);
    }

    #[test]
    fn idle_deadline_expires_active_relay() {
        let mut relay = TcpRelayOwnership::new(50, 64);
        relay.connected(10, 15).expect("connect should publish");
        relay.record_activity(12, 15);
        assert_eq!(
            relay.poll_deadlines(27),
            DeadlineDisposition::Expired("idle deadline")
        );
        assert_eq!(relay.state(), RelayState::Closed);
    }

    #[test]
    fn shutdown_deadline_closes_draining_relay() {
        let mut relay = TcpRelayOwnership::new(50, 64);
        relay.connected(10, 50).expect("connect should publish");
        relay.begin_shutdown(20, 5);
        assert_eq!(relay.state(), RelayState::Draining);
        assert_eq!(
            relay.poll_deadlines(25),
            DeadlineDisposition::Expired("shutdown deadline")
        );
        assert_eq!(relay.state(), RelayState::Closed);
    }

    #[test]
    fn buffer_bounds_reject_overcommit_without_partial_success() {
        let mut relay = TcpRelayOwnership::new(50, 128);
        relay.connected(10, 50).expect("connect should publish");
        relay
            .buffers
            .reserve(100)
            .expect("first reservation should fit");
        let error = relay
            .buffers
            .reserve(40)
            .expect_err("second reservation should fail");
        assert!(matches!(
            error,
            KernelRelayError::ResourceExhausted("relay buffer bound exceeded")
        ));
        assert_eq!(relay.buffers.in_flight_bytes, 100);
        relay.buffers.release(60);
        relay
            .buffers
            .reserve(40)
            .expect("released capacity should be reusable");
    }
}
