// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Explicit host-agent/IOCTL transport interface for the opaque user-mode
//! tunnel.

#[cfg(feature = "opaque-user-tunnel")]
use crate::device::TunnelResponse;
use crate::error::KernelRelayError;
use alloc::format;

/// Driver dequeue request IOCTL.
pub const IOCTL_SSP_DEQUEUE_REQUEST: u32 = ctl_code(0x12, 0x800, 0, 0);
/// Driver response completion IOCTL.
pub const IOCTL_SSP_COMPLETE_RESPONSE: u32 = ctl_code(0x12, 0x801, 0, 0);
/// Driver cancellation IOCTL.
pub const IOCTL_SSP_CANCEL_REQUEST: u32 = ctl_code(0x12, 0x802, 0, 0);
/// Driver transport-status IOCTL.
pub const IOCTL_SSP_REPORT_TRANSPORT: u32 = ctl_code(0x12, 0x803, 0, 0);

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Channel status reported from the host agent to the driver.
pub enum TransportChannelState {
    /// Authenticated gRPC channel is live.
    Connected = 1,
    /// The channel disconnected and the driver must fail unresolved flows.
    Disconnected = 2,
    /// The agent is draining and will not accept new work.
    ShuttingDown = 3,
}

impl TryFrom<u32> for TransportChannelState {
    type Error = KernelRelayError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Connected),
            2 => Ok(Self::Disconnected),
            3 => Ok(Self::ShuttingDown),
            other => Err(KernelRelayError::InvalidState(format!(
                "unknown transport state {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-width cancellation request passed over `IOCTL_SSP_CANCEL_REQUEST`.
pub struct CancelTunnelRequest {
    /// Correlated request identifier.
    pub request_id: u64,
    /// Flow generation paired with the request.
    pub generation: u32,
    /// Transport epoch paired with the request.
    pub epoch: u64,
}

impl CancelTunnelRequest {
    /// Fixed-width encoded size.
    pub const LEN: usize = 20;

    /// Encodes the cancellation request.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut bytes = [0_u8; Self::LEN];
        bytes[0..8].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.generation.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.epoch.to_le_bytes());
        bytes
    }

    /// Decodes a cancellation request.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelRelayError> {
        if bytes.len() < Self::LEN {
            return Err(KernelRelayError::TruncatedFrame {
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            request_id: u64::from_le_bytes(bytes[0..8].try_into().expect("request id")),
            generation: u32::from_le_bytes(bytes[8..12].try_into().expect("generation")),
            epoch: u64::from_le_bytes(bytes[12..20].try_into().expect("epoch")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-width transport-state report passed over
/// `IOCTL_SSP_REPORT_TRANSPORT`.
pub struct TransportStatusReport {
    /// Current authenticated channel state.
    pub state: TransportChannelState,
    /// Transport epoch visible to the driver.
    pub epoch: u64,
}

impl TransportStatusReport {
    /// Fixed-width encoded size.
    pub const LEN: usize = 12;

    /// Encodes the transport report.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut bytes = [0_u8; Self::LEN];
        bytes[0..4].copy_from_slice(&(self.state as u32).to_le_bytes());
        bytes[4..12].copy_from_slice(&self.epoch.to_le_bytes());
        bytes
    }

    /// Decodes the transport report.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelRelayError> {
        if bytes.len() < Self::LEN {
            return Err(KernelRelayError::TruncatedFrame {
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            state: TransportChannelState::try_from(u32::from_le_bytes(
                bytes[0..4].try_into().expect("state"),
            ))?,
            epoch: u64::from_le_bytes(bytes[4..12].try_into().expect("epoch")),
        })
    }
}

#[cfg(feature = "opaque-user-tunnel")]
use crate::{
    agent::{HostTunnelAgent, OpaqueRpcTransport},
    device::TunnelRequest,
};
#[cfg(feature = "opaque-user-tunnel")]
use async_trait::async_trait;

#[cfg(feature = "opaque-user-tunnel")]
#[async_trait]
/// Abstracts the user-mode side of `DeviceIoControl` so the agent bridge can
/// compile and test without a live Windows device object.
pub trait DeviceIoControlChannel: Send + Sync {
    /// Issues a buffered IOCTL and returns the output bytes.
    async fn device_io_control(
        &self,
        code: u32,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, KernelRelayError>;
}

#[cfg(feature = "opaque-user-tunnel")]
#[derive(Clone, Debug)]
/// Typed wrapper around the raw IOCTL contract used by the host agent.
pub struct IoctlTunnelTransport<T> {
    channel: T,
}

#[cfg(feature = "opaque-user-tunnel")]
impl<T> IoctlTunnelTransport<T> {
    /// Creates an IOCTL transport over one caller-supplied device channel.
    pub fn new(channel: T) -> Self {
        Self { channel }
    }
}

#[cfg(feature = "opaque-user-tunnel")]
impl<T: DeviceIoControlChannel> IoctlTunnelTransport<T> {
    /// Dequeues the next opaque driver request, if any.
    pub async fn dequeue_request(&self) -> Result<Option<TunnelRequest>, KernelRelayError> {
        let bytes = self
            .channel
            .device_io_control(IOCTL_SSP_DEQUEUE_REQUEST, Vec::new())
            .await?;
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(TunnelRequest::decode(&bytes)?))
    }

    /// Completes one correlated reply back into the driver.
    pub async fn complete_response(
        &self,
        response: TunnelResponse,
    ) -> Result<(), KernelRelayError> {
        self.channel
            .device_io_control(IOCTL_SSP_COMPLETE_RESPONSE, response.encode()?)
            .await?;
        Ok(())
    }

    /// Cancels one request by correlation identity.
    pub async fn cancel_request(
        &self,
        cancel: CancelTunnelRequest,
    ) -> Result<(), KernelRelayError> {
        self.channel
            .device_io_control(IOCTL_SSP_CANCEL_REQUEST, cancel.encode().to_vec())
            .await?;
        Ok(())
    }

    /// Reports channel status and epoch into the driver.
    pub async fn report_transport(
        &self,
        report: TransportStatusReport,
    ) -> Result<(), KernelRelayError> {
        self.channel
            .device_io_control(IOCTL_SSP_REPORT_TRANSPORT, report.encode().to_vec())
            .await?;
        Ok(())
    }
}

#[cfg(feature = "opaque-user-tunnel")]
#[derive(Clone, Debug)]
/// Bridges IOCTL-dequeued tunnel requests to the opaque authenticated gRPC
/// transport.
pub struct HostAgentIoctlBridge<R, C> {
    agent: HostTunnelAgent<R>,
    io: IoctlTunnelTransport<C>,
}

#[cfg(feature = "opaque-user-tunnel")]
impl<R, C> HostAgentIoctlBridge<R, C> {
    /// Creates a bridge from the supplied RPC transport and IOCTL channel.
    pub fn new(rpc: R, io: C) -> Self {
        Self {
            agent: HostTunnelAgent::new(rpc),
            io: IoctlTunnelTransport::new(io),
        }
    }
}

#[cfg(feature = "opaque-user-tunnel")]
impl<R, C> HostAgentIoctlBridge<R, C>
where
    R: OpaqueRpcTransport,
    C: DeviceIoControlChannel,
{
    /// Forwards one pending request if one is available.
    pub async fn serve_once(&self) -> Result<bool, KernelRelayError> {
        let Some(request) = self.io.dequeue_request().await? else {
            return Ok(false);
        };
        let response = self.agent.forward_request(request).await;
        self.io.complete_response(response).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::TUNNEL_HEADER_LEN;
    #[cfg(feature = "opaque-user-tunnel")]
    use crate::{
        agent::OpaqueRpcTransport,
        device::{TunnelRequest, TunnelRequestKind, TunnelResponse, TunnelResponseStatus},
    };
    #[cfg(feature = "opaque-user-tunnel")]
    use async_trait::async_trait;
    #[cfg(feature = "opaque-user-tunnel")]
    use std::sync::{Arc, Mutex};

    #[test]
    fn cancel_request_round_trips() {
        let request = CancelTunnelRequest {
            request_id: 7,
            generation: 9,
            epoch: 11,
        };
        assert_eq!(
            CancelTunnelRequest::decode(&request.encode()).expect("cancel should decode"),
            request
        );
    }

    #[test]
    fn transport_report_round_trips() {
        let report = TransportStatusReport {
            state: TransportChannelState::Disconnected,
            epoch: 44,
        };
        assert_eq!(
            TransportStatusReport::decode(&report.encode()).expect("report should decode"),
            report
        );
    }

    #[test]
    fn ioctl_response_frames_use_existing_tunnel_header_bounds() {
        assert!(TUNNEL_HEADER_LEN > TransportStatusReport::LEN);
    }

    #[cfg(feature = "opaque-user-tunnel")]
    #[derive(Default)]
    struct RecordingChannel {
        dequeued: Mutex<Vec<Vec<u8>>>,
        completions: Mutex<Vec<Vec<u8>>>,
    }

    #[cfg(feature = "opaque-user-tunnel")]
    #[async_trait]
    impl DeviceIoControlChannel for RecordingChannel {
        async fn device_io_control(
            &self,
            code: u32,
            payload: Vec<u8>,
        ) -> Result<Vec<u8>, KernelRelayError> {
            match code {
                IOCTL_SSP_DEQUEUE_REQUEST => Ok(self
                    .dequeued
                    .lock()
                    .expect("queue")
                    .pop()
                    .unwrap_or_default()),
                IOCTL_SSP_COMPLETE_RESPONSE => {
                    self.completions.lock().expect("completions").push(payload);
                    Ok(Vec::new())
                }
                _ => Ok(Vec::new()),
            }
        }
    }

    #[cfg(feature = "opaque-user-tunnel")]
    #[derive(Clone, Default)]
    struct EchoTransport {
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    #[cfg(feature = "opaque-user-tunnel")]
    #[async_trait]
    impl OpaqueRpcTransport for EchoTransport {
        async fn unary(
            &self,
            _path: &'static str,
            payload: Vec<u8>,
        ) -> Result<Vec<u8>, KernelRelayError> {
            self.seen.lock().expect("seen").push(payload.clone());
            Ok(payload)
        }
    }

    #[cfg(feature = "opaque-user-tunnel")]
    #[tokio::test]
    async fn host_agent_bridge_dequeues_forwards_and_completes_one_request() {
        let request = TunnelRequest {
            request_id: 99,
            generation: 3,
            epoch: 4,
            kind: TunnelRequestKind::GetMapping,
            payload: b"opaque".to_vec(),
        };
        let channel = RecordingChannel {
            dequeued: Mutex::new(vec![request.encode().expect("request should encode")]),
            completions: Mutex::new(Vec::new()),
        };
        let transport = EchoTransport::default();
        let bridge = HostAgentIoctlBridge::new(transport.clone(), channel);

        assert!(bridge.serve_once().await.expect("bridge should serve"));

        let seen = transport.seen.lock().expect("seen");
        assert_eq!(seen.as_slice(), &[b"opaque".to_vec()]);
        drop(seen);

        let completions = bridge.io.channel.completions.lock().expect("completions");
        let response =
            TunnelResponse::decode(&completions[0]).expect("completion frame should decode");
        assert_eq!(response.request_id, 99);
        assert_eq!(response.generation, 3);
        assert_eq!(response.epoch, 4);
        assert_eq!(response.status, TunnelResponseStatus::Ok);
        assert_eq!(response.payload, b"opaque");
    }
}
