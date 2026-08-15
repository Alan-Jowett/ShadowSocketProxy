// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Driver-owned flow lifecycle and opaque tunnel correlation.

use std::collections::HashMap;

use crate::{
    codec::{decode_get_mapping_response, encode_get_mapping_request, MAX_PROTO_MESSAGE_LEN},
    device::{TunnelRequest, TunnelRequestKind, TunnelResponse, TunnelResponseStatus},
    error::KernelRelayError,
    telemetry::{ExecutionLevel, TelemetrySink, TransitionEvent, TransitionOutcome},
    tuple::{FlowProtocol, SocketTuple, ValidatedMapping},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Relay-mode-specific lifecycle used by the driver core.
pub enum FlowState {
    /// The flow was admitted and is about to request its mapping.
    Admitted,
    /// The driver is awaiting a correlated mapping reply.
    ResolvingMapping,
    /// The driver owns a validated mapping and is connecting the outbound side.
    Connecting,
    /// The paired TCP relay is active.
    MappedTcp,
    /// The UDP or QUIC-as-UDP association is active.
    MappedUdp,
    /// The flow is tearing down and releasing resources.
    Closing,
    /// All owned resources have been released.
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Transport behavior required after mapping resolution.
pub enum FlowMode {
    /// Stateful TCP relay.
    Tcp,
    /// Stateless UDP association.
    Udp,
    /// QUIC is treated as UDP payload traffic.
    QuicUdp,
}

impl FlowMode {
    fn protocol(self) -> FlowProtocol {
        match self {
            Self::Tcp => FlowProtocol::Tcp,
            Self::Udp => FlowProtocol::Udp,
            Self::QuicUdp => FlowProtocol::QuicUdp,
        }
    }

    fn mapped_state(self) -> FlowState {
        match self {
            Self::Tcp => FlowState::MappedTcp,
            Self::Udp | Self::QuicUdp => FlowState::MappedUdp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Stable driver identity for one admitted flow.
pub struct FlowIdentity {
    /// Monotonic flow identifier.
    pub flow_id: u64,
    /// Generation paired with the flow identifier.
    pub generation: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Initial result returned when a flow is admitted for mapping resolution.
pub struct FlowAdmission {
    /// Stable flow identity.
    pub flow: FlowIdentity,
    /// Opaque request forwarded by the host tunnel.
    pub request: TunnelRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Mapping result that should drive outbound connect or association setup.
pub struct MappingReady {
    /// Stable flow identity.
    pub flow: FlowIdentity,
    /// Driver-validated mapping for the exact requesting tuple.
    pub mapping: ValidatedMapping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Effect of a tunnel completion on the driver-owned state machine.
pub enum CompletionDisposition {
    /// Mapping validation succeeded and outbound connection setup may begin.
    BeginConnect(MappingReady),
    /// The completion was rejected as stale, duplicate, or malformed.
    Rejected {
        /// Echoed request correlation.
        request_id: u64,
        /// Echoed flow generation.
        generation: u32,
        /// Echoed transport epoch.
        epoch: u64,
        /// Short rejection reason.
        reason: &'static str,
    },
    /// The owning flow closed and released all state.
    Closed {
        /// Stable flow identity.
        flow: FlowIdentity,
        /// Reason for closure.
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Bounded safety limits enforced by the host-independent state machine.
pub struct ResourceLimits {
    /// Maximum simultaneously published flow records.
    pub max_active_flows: usize,
    /// Maximum aggregate bytes held in pending tunnel requests.
    pub max_pending_request_bytes: usize,
    /// Maximum protobuf payload size accepted for request or reply handling.
    pub max_proto_message_len: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_active_flows: 4096,
            max_pending_request_bytes: 128 * 1024,
            max_proto_message_len: MAX_PROTO_MESSAGE_LEN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RequestKey {
    request_id: u64,
    generation: u32,
    epoch: u64,
}

#[derive(Debug, Clone)]
struct FlowRecord {
    identity: FlowIdentity,
    tuple: SocketTuple,
    mode: FlowMode,
    state: FlowState,
    current_request: Option<RequestKey>,
    current_request_len: usize,
    current_mapping: Option<ValidatedMapping>,
}

/// Driver-owned state machine for kernel-relay flow admission, mapping
/// correlation, connect progression, failure containment, and teardown.
pub struct FlowController<T: TelemetrySink> {
    telemetry: T,
    limits: ResourceLimits,
    next_flow_id: u64,
    next_request_id: u64,
    epoch: u64,
    shutting_down: bool,
    pending_bytes: usize,
    flows: HashMap<u64, FlowRecord>,
    pending: HashMap<RequestKey, u64>,
}

impl<T: TelemetrySink> FlowController<T> {
    /// Creates a controller using the default safety limits.
    pub fn new(telemetry: T) -> Self {
        Self::with_limits(telemetry, ResourceLimits::default())
    }

    /// Creates a controller with explicit safety limits.
    pub fn with_limits(telemetry: T, limits: ResourceLimits) -> Self {
        Self {
            telemetry,
            limits,
            next_flow_id: 1,
            next_request_id: 1,
            epoch: 1,
            shutting_down: false,
            pending_bytes: 0,
            flows: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Admits a TCP flow and emits the mapping request that user mode tunnels.
    pub fn admit_tcp(
        &mut self,
        tuple: SocketTuple,
        level: ExecutionLevel,
    ) -> Result<FlowAdmission, KernelRelayError> {
        self.admit(tuple, FlowMode::Tcp, level)
    }

    /// Admits a UDP flow and emits the mapping request that user mode tunnels.
    pub fn admit_udp(
        &mut self,
        tuple: SocketTuple,
        level: ExecutionLevel,
    ) -> Result<FlowAdmission, KernelRelayError> {
        self.admit(tuple, FlowMode::Udp, level)
    }

    /// Admits a QUIC flow, which is relayed as UDP payload traffic.
    pub fn admit_quic(
        &mut self,
        tuple: SocketTuple,
        level: ExecutionLevel,
    ) -> Result<FlowAdmission, KernelRelayError> {
        self.admit(tuple, FlowMode::QuicUdp, level)
    }

    /// Applies a correlated tunnel completion.
    pub fn handle_tunnel_response(
        &mut self,
        response: TunnelResponse,
        level: ExecutionLevel,
    ) -> Result<CompletionDisposition, KernelRelayError> {
        if response.payload.len() > self.limits.max_proto_message_len {
            return Err(KernelRelayError::PayloadTooLarge {
                actual: response.payload.len(),
                max: self.limits.max_proto_message_len,
            });
        }
        let key = RequestKey {
            request_id: response.request_id,
            generation: response.generation,
            epoch: response.epoch,
        };
        let Some(flow_id) = self.pending.remove(&key) else {
            return Ok(CompletionDisposition::Rejected {
                request_id: response.request_id,
                generation: response.generation,
                epoch: response.epoch,
                reason: "stale completion",
            });
        };

        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return Ok(CompletionDisposition::Rejected {
                request_id: response.request_id,
                generation: response.generation,
                epoch: response.epoch,
                reason: "flow already released",
            });
        };
        self.pending_bytes = self.pending_bytes.saturating_sub(flow.current_request_len);
        flow.current_request = None;
        flow.current_request_len = 0;

        if flow.identity.generation != response.generation {
            Self::reject_action(
                &self.telemetry,
                flow,
                Some(response.request_id),
                level,
                "stale generation",
            );
            return Ok(CompletionDisposition::Rejected {
                request_id: response.request_id,
                generation: response.generation,
                epoch: response.epoch,
                reason: "stale generation",
            });
        }
        if flow.state != FlowState::ResolvingMapping {
            Self::reject_action(
                &self.telemetry,
                flow,
                Some(response.request_id),
                level,
                "completion in wrong state",
            );
            return Ok(CompletionDisposition::Rejected {
                request_id: response.request_id,
                generation: response.generation,
                epoch: response.epoch,
                reason: "completion in wrong state",
            });
        }

        match response.status {
            TunnelResponseStatus::Ok => {
                let mapping = decode_get_mapping_response(&flow.tuple, &response.payload)?;
                let identity = flow.identity;
                Self::advance(
                    &self.telemetry,
                    flow,
                    FlowState::Connecting,
                    Some(response.request_id),
                    level,
                    "mapping validated",
                );
                flow.current_mapping = Some(mapping.clone());
                Ok(CompletionDisposition::BeginConnect(MappingReady {
                    flow: identity,
                    mapping,
                }))
            }
            TunnelResponseStatus::MappingNotFound => Ok(self.close_and_release(
                flow_id,
                Some(response.request_id),
                level,
                "mapping not found",
            )),
            TunnelResponseStatus::Cancelled => Ok(self.close_and_release(
                flow_id,
                Some(response.request_id),
                level,
                "mapping cancelled",
            )),
            TunnelResponseStatus::TransportError => Ok(self.close_and_release(
                flow_id,
                Some(response.request_id),
                level,
                "transport failure",
            )),
            TunnelResponseStatus::Oversized => Ok(self.close_and_release(
                flow_id,
                Some(response.request_id),
                level,
                "oversized reply",
            )),
            TunnelResponseStatus::InvalidState => Ok(self.close_and_release(
                flow_id,
                Some(response.request_id),
                level,
                "agent rejected completion",
            )),
        }
    }

    /// Marks a validated mapping as connected and publishable.
    pub fn connect_succeeded(
        &mut self,
        flow: FlowIdentity,
        level: ExecutionLevel,
    ) -> Result<(), KernelRelayError> {
        let identity = flow;
        let flow = self
            .flows
            .get_mut(&identity.flow_id)
            .ok_or(KernelRelayError::FlowNotFound {
                flow_id: identity.flow_id,
                generation: identity.generation,
            })?;
        if flow.identity.generation != identity.generation {
            return Err(KernelRelayError::FlowNotFound {
                flow_id: flow.identity.flow_id,
                generation: identity.generation,
            });
        }
        if flow.state != FlowState::Connecting {
            Self::reject_action(
                &self.telemetry,
                flow,
                None,
                level,
                "connect success in wrong state",
            );
            return Err(KernelRelayError::InvalidState(format!(
                "flow {}:{} is {:?}, expected Connecting",
                flow.identity.flow_id, flow.identity.generation, flow.state
            )));
        }
        Self::advance(
            &self.telemetry,
            flow,
            flow.mode.mapped_state(),
            None,
            level,
            "connect succeeded",
        );
        Ok(())
    }

    /// Fails a connect or association setup without affecting unrelated flows.
    pub fn connect_failed(
        &mut self,
        flow: FlowIdentity,
        level: ExecutionLevel,
        reason: &'static str,
    ) -> Result<(), KernelRelayError> {
        let flow_id = self.flow_mut(flow)?.identity.flow_id;
        let _ = self.close_and_release(flow_id, None, level, reason);
        Ok(())
    }

    /// Fails an already mapped relay without affecting unrelated flows.
    pub fn relay_failed(
        &mut self,
        flow: FlowIdentity,
        level: ExecutionLevel,
        reason: &'static str,
    ) -> Result<(), KernelRelayError> {
        let identity = flow;
        let flow = self
            .flows
            .get_mut(&identity.flow_id)
            .ok_or(KernelRelayError::FlowNotFound {
                flow_id: identity.flow_id,
                generation: identity.generation,
            })?;
        if flow.identity.generation != identity.generation {
            return Err(KernelRelayError::FlowNotFound {
                flow_id: flow.identity.flow_id,
                generation: identity.generation,
            });
        }
        if !matches!(flow.state, FlowState::MappedTcp | FlowState::MappedUdp) {
            Self::reject_action(
                &self.telemetry,
                flow,
                None,
                level,
                "relay failure in wrong state",
            );
            return Err(KernelRelayError::InvalidState(format!(
                "flow {}:{} is {:?}, expected mapped state",
                flow.identity.flow_id, flow.identity.generation, flow.state
            )));
        }
        let flow_id = flow.identity.flow_id;
        let _ = self.close_and_release(flow_id, None, level, reason);
        Ok(())
    }

    /// Completes a mapped flow after orderly relay shutdown.
    pub fn release_flow(
        &mut self,
        flow: FlowIdentity,
        level: ExecutionLevel,
        reason: &'static str,
    ) -> Result<(), KernelRelayError> {
        let flow_id = self.flow_mut(flow)?.identity.flow_id;
        let _ = self.close_and_release(flow_id, None, level, reason);
        Ok(())
    }

    /// Cancels one flow and makes later completions stale.
    pub fn cancel_flow(
        &mut self,
        flow: FlowIdentity,
        level: ExecutionLevel,
        reason: &'static str,
    ) -> Result<(), KernelRelayError> {
        let flow_id = self.flow_mut(flow)?.identity.flow_id;
        let _ = self.close_and_release(flow_id, None, level, reason);
        Ok(())
    }

    /// Marks the authenticated channel as disconnected and fails only
    /// unresolved flows from the old epoch.
    pub fn transport_disconnected(&mut self, level: ExecutionLevel) {
        self.epoch = self.epoch.saturating_add(1);
        let pending: Vec<u64> = self
            .flows
            .iter()
            .filter_map(|(flow_id, flow)| {
                (flow.state == FlowState::ResolvingMapping).then_some(*flow_id)
            })
            .collect();
        for flow_id in pending {
            let _ = self.close_and_release(flow_id, None, level, "transport disconnected");
        }
    }

    /// Initiates shutdown, failing unresolved or connecting work while leaving
    /// already-mapped flows individually responsible for their later teardown.
    pub fn begin_shutdown(&mut self, level: ExecutionLevel) {
        self.shutting_down = true;
        let closable: Vec<u64> = self
            .flows
            .iter()
            .filter_map(|(flow_id, flow)| {
                matches!(
                    flow.state,
                    FlowState::ResolvingMapping | FlowState::Connecting
                )
                .then_some(*flow_id)
            })
            .collect();
        for flow_id in closable {
            let _ = self.close_and_release(flow_id, None, level, "shutdown");
        }
    }

    /// Returns the current state of a flow when it still exists.
    pub fn flow_state(&self, flow: FlowIdentity) -> Option<FlowState> {
        self.flows
            .get(&flow.flow_id)
            .filter(|record| record.identity.generation == flow.generation)
            .map(|record| record.state)
    }

    /// Returns the current transport epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the number of active flow records.
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    fn admit(
        &mut self,
        tuple: SocketTuple,
        mode: FlowMode,
        level: ExecutionLevel,
    ) -> Result<FlowAdmission, KernelRelayError> {
        if self.shutting_down {
            return Err(KernelRelayError::Cancelled("shutdown in progress"));
        }
        tuple.validate()?;
        if tuple.protocol != mode.protocol() {
            return Err(KernelRelayError::InvalidTuple(
                "tuple protocol does not match the selected flow mode".into(),
            ));
        }
        if self.flows.len() >= self.limits.max_active_flows {
            return Err(KernelRelayError::ResourceExhausted(
                "active flow table is full",
            ));
        }
        let payload = encode_get_mapping_request(&tuple)?;
        if self.pending_bytes + payload.len() > self.limits.max_pending_request_bytes {
            return Err(KernelRelayError::ResourceExhausted(
                "pending request bytes exceeded the configured bound",
            ));
        }
        let identity = FlowIdentity {
            flow_id: self.next_flow_id,
            generation: 1,
        };
        self.next_flow_id = self.next_flow_id.saturating_add(1);
        let request_key = RequestKey {
            request_id: self.next_request_id,
            generation: identity.generation,
            epoch: self.epoch,
        };
        self.next_request_id = self.next_request_id.saturating_add(1);

        let mut record = FlowRecord {
            identity,
            tuple,
            mode,
            state: FlowState::Admitted,
            current_request: Some(request_key),
            current_request_len: payload.len(),
            current_mapping: None,
        };
        Self::advance(
            &self.telemetry,
            &mut record,
            FlowState::ResolvingMapping,
            Some(request_key.request_id),
            level,
            "mapping requested",
        );
        self.pending_bytes += payload.len();
        self.pending.insert(request_key, identity.flow_id);
        self.flows.insert(identity.flow_id, record);

        Ok(FlowAdmission {
            flow: identity,
            request: TunnelRequest {
                request_id: request_key.request_id,
                generation: request_key.generation,
                epoch: request_key.epoch,
                kind: TunnelRequestKind::GetMapping,
                payload,
            },
        })
    }

    fn flow_mut(&mut self, flow: FlowIdentity) -> Result<&mut FlowRecord, KernelRelayError> {
        let record = self
            .flows
            .get_mut(&flow.flow_id)
            .ok_or(KernelRelayError::FlowNotFound {
                flow_id: flow.flow_id,
                generation: flow.generation,
            })?;
        if record.identity.generation != flow.generation {
            return Err(KernelRelayError::FlowNotFound {
                flow_id: flow.flow_id,
                generation: flow.generation,
            });
        }
        Ok(record)
    }

    fn close_and_release(
        &mut self,
        flow_id: u64,
        request_id: Option<u64>,
        level: ExecutionLevel,
        reason: &'static str,
    ) -> CompletionDisposition {
        let Some(mut flow) = self.flows.remove(&flow_id) else {
            return CompletionDisposition::Rejected {
                request_id: request_id.unwrap_or_default(),
                generation: 0,
                epoch: self.epoch,
                reason: "flow already released",
            };
        };
        if let Some(request) = flow.current_request.take() {
            self.pending.remove(&request);
            self.pending_bytes = self.pending_bytes.saturating_sub(flow.current_request_len);
        }
        flow.current_request_len = 0;
        Self::advance(
            &self.telemetry,
            &mut flow,
            FlowState::Closing,
            request_id,
            level,
            reason,
        );
        Self::advance(
            &self.telemetry,
            &mut flow,
            FlowState::Released,
            request_id,
            level,
            reason,
        );
        CompletionDisposition::Closed {
            flow: flow.identity,
            reason,
        }
    }

    fn advance(
        telemetry: &T,
        flow: &mut FlowRecord,
        next: FlowState,
        request_id: Option<u64>,
        level: ExecutionLevel,
        reason: &'static str,
    ) {
        let previous = flow.state;
        flow.state = next;
        let _ = telemetry.emit(&TransitionEvent {
            flow_id: flow.identity.flow_id,
            request_id,
            generation: flow.identity.generation,
            protocol: flow.tuple.protocol,
            previous,
            outcome: TransitionOutcome::Accepted(next),
            reason,
            execution_level: level,
        });
    }

    fn reject_action(
        telemetry: &T,
        flow: &FlowRecord,
        request_id: Option<u64>,
        level: ExecutionLevel,
        reason: &'static str,
    ) {
        let _ = telemetry.emit(&TransitionEvent {
            flow_id: flow.identity.flow_id,
            request_id,
            generation: flow.identity.generation,
            protocol: flow.tuple.protocol,
            previous: flow.state,
            outcome: TransitionOutcome::Rejected(reason),
            reason,
            execution_level: level,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use prost::Message;

    use super::*;
    use crate::{
        proto,
        telemetry::{FailingTelemetry, NoopTelemetry, RecordingTelemetry},
    };

    fn tcp_tuple(port: u16) -> SocketTuple {
        SocketTuple {
            source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 10), port)),
            destination: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 443)),
            protocol: FlowProtocol::Tcp,
        }
    }

    fn mapping_bytes(tuple: &SocketTuple, destination_port: u16) -> Vec<u8> {
        proto::Mapping {
            synthetic: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 10],
                destination_address: vec![198, 51, 100, 10],
                protocol: tuple.protocol.wire_number() as u32,
                source_port: tuple.source.port() as u32,
                destination_port: tuple.destination.port() as u32,
            }),
            original: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 10],
                destination_address: vec![203, 0, 113, 20],
                protocol: tuple.protocol.wire_number() as u32,
                source_port: tuple.source.port() as u32,
                destination_port: destination_port as u32,
            }),
            last_seen_ns: 55,
            protocol_flags: 1,
            tcp_state_flags: 2,
        }
        .encode_to_vec()
    }

    #[test]
    fn state_machine_advances_from_mapping_to_connecting() {
        let telemetry = RecordingTelemetry::default();
        let mut controller = FlowController::new(telemetry);
        let admission = controller
            .admit_tcp(tcp_tuple(40001), ExecutionLevel::Passive)
            .expect("admission should succeed");

        let outcome = controller
            .handle_tunnel_response(
                TunnelResponse {
                    request_id: admission.request.request_id,
                    generation: admission.request.generation,
                    epoch: admission.request.epoch,
                    status: TunnelResponseStatus::Ok,
                    payload: mapping_bytes(&tcp_tuple(40001), 8443),
                },
                ExecutionLevel::Passive,
            )
            .expect("completion should succeed");

        let CompletionDisposition::BeginConnect(ready) = outcome else {
            panic!("expected a connecting outcome");
        };
        assert_eq!(ready.flow, admission.flow);
        assert_eq!(
            controller.flow_state(admission.flow),
            Some(FlowState::Connecting)
        );
    }

    #[test]
    fn stale_completion_is_rejected_without_mutating_other_flows() {
        let telemetry = RecordingTelemetry::default();
        let mut controller = FlowController::new(telemetry);
        let stale = controller
            .admit_tcp(tcp_tuple(40002), ExecutionLevel::Passive)
            .expect("admission should succeed");
        let active = controller
            .admit_tcp(tcp_tuple(40003), ExecutionLevel::Passive)
            .expect("admission should succeed");
        controller
            .cancel_flow(stale.flow, ExecutionLevel::Passive, "test cancellation")
            .expect("cancellation should succeed");

        let outcome = controller
            .handle_tunnel_response(
                TunnelResponse {
                    request_id: stale.request.request_id,
                    generation: stale.request.generation,
                    epoch: stale.request.epoch,
                    status: TunnelResponseStatus::Ok,
                    payload: mapping_bytes(&tcp_tuple(40002), 9443),
                },
                ExecutionLevel::Passive,
            )
            .expect("completion should be handled");

        assert!(matches!(
            outcome,
            CompletionDisposition::Rejected {
                reason: "stale completion",
                ..
            }
        ));
        assert_eq!(
            controller.flow_state(active.flow),
            Some(FlowState::ResolvingMapping)
        );
    }

    #[test]
    fn request_byte_bound_is_enforced() {
        let limits = ResourceLimits {
            max_active_flows: 16,
            max_pending_request_bytes: 8,
            max_proto_message_len: MAX_PROTO_MESSAGE_LEN,
        };
        let mut controller = FlowController::with_limits(NoopTelemetry, limits);
        let error = controller
            .admit_tcp(tcp_tuple(40004), ExecutionLevel::Passive)
            .expect_err("admission should be bounded");
        assert!(matches!(
            error,
            KernelRelayError::ResourceExhausted(
                "pending request bytes exceeded the configured bound"
            )
        ));
    }

    #[test]
    fn telemetry_failures_do_not_break_state_progression() {
        let mut controller = FlowController::new(FailingTelemetry);
        let admission = controller
            .admit_tcp(tcp_tuple(40005), ExecutionLevel::Dispatch)
            .expect("admission should succeed");
        let outcome = controller
            .handle_tunnel_response(
                TunnelResponse {
                    request_id: admission.request.request_id,
                    generation: admission.request.generation,
                    epoch: admission.request.epoch,
                    status: TunnelResponseStatus::Ok,
                    payload: mapping_bytes(&tcp_tuple(40005), 10443),
                },
                ExecutionLevel::Dispatch,
            )
            .expect("completion should succeed");
        assert!(matches!(outcome, CompletionDisposition::BeginConnect(_)));
        assert_eq!(
            controller.flow_state(admission.flow),
            Some(FlowState::Connecting)
        );
    }

    #[test]
    fn one_flow_failure_does_not_affect_other_connecting_flow() {
        let telemetry = RecordingTelemetry::default();
        let mut controller = FlowController::new(telemetry);
        let failed = controller
            .admit_tcp(tcp_tuple(40006), ExecutionLevel::Passive)
            .expect("admission should succeed");
        let healthy = controller
            .admit_tcp(tcp_tuple(40007), ExecutionLevel::Passive)
            .expect("admission should succeed");

        let failed_outcome = controller
            .handle_tunnel_response(
                TunnelResponse {
                    request_id: failed.request.request_id,
                    generation: failed.request.generation,
                    epoch: failed.request.epoch,
                    status: TunnelResponseStatus::MappingNotFound,
                    payload: Vec::new(),
                },
                ExecutionLevel::Passive,
            )
            .expect("failure should be isolated");
        assert!(matches!(
            failed_outcome,
            CompletionDisposition::Closed { .. }
        ));

        let healthy_outcome = controller
            .handle_tunnel_response(
                TunnelResponse {
                    request_id: healthy.request.request_id,
                    generation: healthy.request.generation,
                    epoch: healthy.request.epoch,
                    status: TunnelResponseStatus::Ok,
                    payload: mapping_bytes(&tcp_tuple(40007), 11443),
                },
                ExecutionLevel::Passive,
            )
            .expect("success should continue");
        assert!(matches!(
            healthy_outcome,
            CompletionDisposition::BeginConnect(_)
        ));
        assert_eq!(
            controller.flow_state(healthy.flow),
            Some(FlowState::Connecting)
        );
    }

    #[test]
    fn transport_disconnect_closes_only_unresolved_flows() {
        let mut controller = FlowController::new(NoopTelemetry);
        let unresolved = controller
            .admit_tcp(tcp_tuple(40008), ExecutionLevel::Passive)
            .expect("admission should succeed");
        let mapped = controller
            .admit_tcp(tcp_tuple(40009), ExecutionLevel::Passive)
            .expect("admission should succeed");
        let mapping = controller
            .handle_tunnel_response(
                TunnelResponse {
                    request_id: mapped.request.request_id,
                    generation: mapped.request.generation,
                    epoch: mapped.request.epoch,
                    status: TunnelResponseStatus::Ok,
                    payload: mapping_bytes(&tcp_tuple(40009), 12443),
                },
                ExecutionLevel::Passive,
            )
            .expect("mapping should succeed");
        let CompletionDisposition::BeginConnect(ready) = mapping else {
            panic!("mapping should begin connect");
        };
        controller
            .connect_succeeded(ready.flow, ExecutionLevel::Passive)
            .expect("connect should succeed");

        controller.transport_disconnected(ExecutionLevel::Passive);

        assert_eq!(controller.flow_state(unresolved.flow), None);
        assert_eq!(
            controller.flow_state(mapped.flow),
            Some(FlowState::MappedTcp)
        );
    }

    #[test]
    fn telemetry_records_transition_fields() {
        let telemetry = RecordingTelemetry::default();
        let mut controller = FlowController::new(telemetry);
        let admission = controller
            .admit_tcp(tcp_tuple(40010), ExecutionLevel::Dispatch)
            .expect("admission should succeed");
        let events = controller.telemetry.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.flow_id, admission.flow.flow_id);
        assert_eq!(event.request_id, Some(admission.request.request_id));
        assert_eq!(event.generation, admission.flow.generation);
        assert_eq!(event.protocol, FlowProtocol::Tcp);
        assert_eq!(event.previous, FlowState::Admitted);
        assert_eq!(event.execution_level, ExecutionLevel::Dispatch);
        assert_eq!(
            event.outcome,
            TransitionOutcome::Accepted(FlowState::ResolvingMapping)
        );
    }
}
