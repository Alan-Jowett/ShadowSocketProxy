// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Canonical tuple and mapping types owned by the kernel-relay path.

use alloc::format;
use core::net::SocketAddr;

use crate::error::KernelRelayError;

/// IP protocol number used for TCP lookups.
pub const TCP_PROTOCOL: u8 = 6;
/// IP protocol number used for UDP and QUIC-as-UDP lookups.
pub const UDP_PROTOCOL: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Canonical transport semantics for a flow admitted into the kernel relay.
pub enum FlowProtocol {
    /// Stateful byte-stream relay semantics.
    Tcp,
    /// Datagram relay semantics.
    Udp,
    /// QUIC is carried as ordinary UDP payload traffic.
    QuicUdp,
}

impl FlowProtocol {
    /// Returns the protocol number serialized in `GetMapping`.
    pub fn wire_number(self) -> u8 {
        match self {
            Self::Tcp => TCP_PROTOCOL,
            Self::Udp | Self::QuicUdp => UDP_PROTOCOL,
        }
    }

    /// Indicates whether the flow uses UDP-style association semantics.
    pub fn is_udp_like(self) -> bool {
        matches!(self, Self::Udp | Self::QuicUdp)
    }

    /// Converts a wire protocol number back to a canonical protocol.
    pub fn from_wire(protocol: u8) -> Result<Self, KernelRelayError> {
        match protocol {
            TCP_PROTOCOL => Ok(Self::Tcp),
            UDP_PROTOCOL => Ok(Self::Udp),
            other => Err(KernelRelayError::InvalidTuple(format!(
                "unsupported protocol {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Exact synthetic or original five-tuple presented to the relay.
pub struct SocketTuple {
    /// Client source endpoint.
    pub source: SocketAddr,
    /// Destination endpoint, synthetic or original depending on context.
    pub destination: SocketAddr,
    /// Transport protocol and relay semantics.
    pub protocol: FlowProtocol,
}

impl SocketTuple {
    /// Returns the tuple family discriminator used by the protobuf contract.
    pub fn family(&self) -> u32 {
        if self.source.is_ipv4() {
            4
        } else {
            6
        }
    }

    /// Validates family, port, and address invariants.
    pub fn validate(&self) -> Result<(), KernelRelayError> {
        if self.source.is_ipv4() != self.destination.is_ipv4() {
            return Err(KernelRelayError::InvalidTuple(
                "source and destination families must match".into(),
            ));
        }
        if self.source.port() == 0 || self.destination.port() == 0 {
            return Err(KernelRelayError::InvalidTuple(
                "source and destination ports must be non-zero".into(),
            ));
        }
        if self.source.ip().is_unspecified() || self.destination.ip().is_unspecified() {
            return Err(KernelRelayError::InvalidTuple(
                "unspecified addresses are not allowed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Driver-validated mapping returned by the control plane.
pub struct ValidatedMapping {
    /// Synthetic tuple matched against the requesting flow.
    pub synthetic: SocketTuple,
    /// Original tuple restored by the relay.
    pub original: SocketTuple,
    /// Monotonic last-seen timestamp reported by the control service.
    pub last_seen_ns: u64,
    /// Control-plane protocol flags associated with the mapping.
    pub protocol_flags: u32,
    /// Control-plane TCP-state flags associated with the mapping.
    pub tcp_state_flags: u32,
}
