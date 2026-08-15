// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Versioned opaque tunnel framing shared between the driver and host agent.

use crate::error::KernelRelayError;

/// Current version of the driver/agent tunnel ABI.
pub const TUNNEL_ABI_VERSION: u16 = 1;
/// Fixed-width tunnel header length in bytes.
pub const TUNNEL_HEADER_LEN: usize = 28;
/// Maximum payload accepted in one tunnel request or reply.
pub const MAX_TUNNEL_PAYLOAD_LEN: usize = crate::codec::MAX_PROTO_MESSAGE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Direction marker encoded in each tunnel frame.
pub enum MessageDirection {
    /// Request issued by the driver to the user-mode agent.
    DriverToAgent = 1,
    /// Reply returned by the user-mode agent to the driver.
    AgentToDriver = 2,
}

impl TryFrom<u8> for MessageDirection {
    type Error = KernelRelayError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DriverToAgent),
            2 => Ok(Self::AgentToDriver),
            other => Err(KernelRelayError::InvalidMessageDirection(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Supported opaque request kinds.
pub enum TunnelRequestKind {
    /// Unary `GetMapping` RPC using opaque protobuf bytes.
    GetMapping = 1,
}

impl TryFrom<u8> for TunnelRequestKind {
    type Error = KernelRelayError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::GetMapping),
            other => Err(KernelRelayError::InvalidRequestKind(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Result categories returned by the tunnel agent.
pub enum TunnelResponseStatus {
    /// The opaque gRPC call succeeded and payload bytes contain the reply.
    Ok = 0,
    /// No mapping existed for the requesting tuple.
    MappingNotFound = 1,
    /// The driver cancelled the request or transport session.
    Cancelled = 2,
    /// The agent or authenticated gRPC channel failed.
    TransportError = 3,
    /// The request or reply exceeded explicit bounds.
    Oversized = 4,
    /// The agent rejected the request because it was stale or malformed.
    InvalidState = 5,
}

impl TryFrom<u8> for TunnelResponseStatus {
    type Error = KernelRelayError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::MappingNotFound),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::TransportError),
            4 => Ok(Self::Oversized),
            5 => Ok(Self::InvalidState),
            other => Err(KernelRelayError::InvalidResponseStatus(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Opaque request envelope emitted by the driver.
pub struct TunnelRequest {
    /// Driver-generated correlation identity.
    pub request_id: u64,
    /// Flow generation paired with the request.
    pub generation: u32,
    /// Transport connection epoch.
    pub epoch: u64,
    /// Operation carried by the opaque payload.
    pub kind: TunnelRequestKind,
    /// Serialized protobuf bytes produced by the driver.
    pub payload: Vec<u8>,
}

impl TunnelRequest {
    /// Encodes the fixed-width header and opaque payload.
    pub fn encode(&self) -> Result<Vec<u8>, KernelRelayError> {
        enforce_payload_bound(self.payload.len())?;
        let mut bytes = Vec::with_capacity(TUNNEL_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(&TUNNEL_ABI_VERSION.to_le_bytes());
        bytes.push(MessageDirection::DriverToAgent as u8);
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes and validates an opaque driver request.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelRelayError> {
        let (direction, code, request_id, generation, epoch, payload) = decode_parts(bytes)?;
        if direction != MessageDirection::DriverToAgent {
            return Err(KernelRelayError::InvalidMessageDirection(direction as u8));
        }
        Ok(Self {
            request_id,
            generation,
            epoch,
            kind: TunnelRequestKind::try_from(code)?,
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Opaque reply envelope returned by the user-mode agent.
pub struct TunnelResponse {
    /// Driver-generated correlation identity echoed by the agent.
    pub request_id: u64,
    /// Flow generation echoed by the agent.
    pub generation: u32,
    /// Transport connection epoch echoed by the agent.
    pub epoch: u64,
    /// Agent result category.
    pub status: TunnelResponseStatus,
    /// Opaque protobuf response bytes or empty error details.
    pub payload: Vec<u8>,
}

impl TunnelResponse {
    /// Encodes the fixed-width header and opaque payload.
    pub fn encode(&self) -> Result<Vec<u8>, KernelRelayError> {
        enforce_payload_bound(self.payload.len())?;
        let mut bytes = Vec::with_capacity(TUNNEL_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(&TUNNEL_ABI_VERSION.to_le_bytes());
        bytes.push(MessageDirection::AgentToDriver as u8);
        bytes.push(self.status as u8);
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes and validates an opaque agent reply.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelRelayError> {
        let (direction, code, request_id, generation, epoch, payload) = decode_parts(bytes)?;
        if direction != MessageDirection::AgentToDriver {
            return Err(KernelRelayError::InvalidMessageDirection(direction as u8));
        }
        Ok(Self {
            request_id,
            generation,
            epoch,
            status: TunnelResponseStatus::try_from(code)?,
            payload,
        })
    }
}

fn decode_parts(
    bytes: &[u8],
) -> Result<(MessageDirection, u8, u64, u32, u64, Vec<u8>), KernelRelayError> {
    if bytes.len() < TUNNEL_HEADER_LEN {
        return Err(KernelRelayError::TruncatedFrame {
            expected: TUNNEL_HEADER_LEN,
            actual: bytes.len(),
        });
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    if version != TUNNEL_ABI_VERSION {
        return Err(KernelRelayError::UnsupportedAbiVersion {
            expected: TUNNEL_ABI_VERSION,
            actual: version,
        });
    }
    let direction = MessageDirection::try_from(bytes[2])?;
    let code = bytes[3];
    let request_id = u64::from_le_bytes(bytes[4..12].try_into().expect("fixed-width request id"));
    let generation = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed-width generation"));
    let epoch = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed-width epoch"));
    let payload_len =
        u32::from_le_bytes(bytes[24..28].try_into().expect("fixed-width payload len")) as usize;
    enforce_payload_bound(payload_len)?;
    let expected = TUNNEL_HEADER_LEN + payload_len;
    if bytes.len() < expected {
        return Err(KernelRelayError::TruncatedFrame {
            expected,
            actual: bytes.len(),
        });
    }
    Ok((
        direction,
        code,
        request_id,
        generation,
        epoch,
        bytes[TUNNEL_HEADER_LEN..expected].to_vec(),
    ))
}

fn enforce_payload_bound(actual: usize) -> Result<(), KernelRelayError> {
    if actual > MAX_TUNNEL_PAYLOAD_LEN {
        return Err(KernelRelayError::PayloadTooLarge {
            actual,
            max: MAX_TUNNEL_PAYLOAD_LEN,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let request = TunnelRequest {
            request_id: 7,
            generation: 9,
            epoch: 11,
            kind: TunnelRequestKind::GetMapping,
            payload: vec![1, 2, 3],
        };
        let bytes = request.encode().expect("request should encode");
        let decoded = TunnelRequest::decode(&bytes).expect("request should decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn response_rejects_wrong_direction() {
        let request = TunnelRequest {
            request_id: 1,
            generation: 2,
            epoch: 3,
            kind: TunnelRequestKind::GetMapping,
            payload: vec![0],
        };
        let bytes = request.encode().expect("request should encode");
        let error = TunnelResponse::decode(&bytes).expect_err("response decode should fail");
        assert!(matches!(
            error,
            KernelRelayError::InvalidMessageDirection(1)
        ));
    }

    #[test]
    fn rejects_oversized_payloads() {
        let request = TunnelRequest {
            request_id: 1,
            generation: 1,
            epoch: 1,
            kind: TunnelRequestKind::GetMapping,
            payload: vec![0; MAX_TUNNEL_PAYLOAD_LEN + 1],
        };
        let error = request.encode().expect_err("oversized request should fail");
        assert!(matches!(
            error,
            KernelRelayError::PayloadTooLarge {
                actual,
                max: MAX_TUNNEL_PAYLOAD_LEN
            } if actual == MAX_TUNNEL_PAYLOAD_LEN + 1
        ));
    }
}
