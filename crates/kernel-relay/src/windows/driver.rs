// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! DriverEntry, runtime ownership, device dispatch, ACL, and unload seams for
//! the kernel relay.

use core::{mem, ptr, slice};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
};

use crate::{
    device::{TunnelRequest, TunnelResponse},
    ioctl::{
        CancelTunnelRequest, TransportChannelState, TransportStatusReport,
        IOCTL_SSP_CANCEL_REQUEST, IOCTL_SSP_COMPLETE_RESPONSE, IOCTL_SSP_DEQUEUE_REQUEST,
        IOCTL_SSP_REPORT_TRANSPORT,
    },
    relay::{RelayDirection, TcpRelayOwnership},
    state::{CompletionDisposition, FlowController, FlowIdentity, FlowState, ResourceLimits},
    telemetry::{DbgPrintTelemetry, ExecutionLevel},
    tuple::{FlowProtocol, SocketTuple},
};

#[cfg(ssp_wdk_native)]
use super::wsk::NativeWskDataplane;
use super::{
    ffi,
    locks::{PushLock, SpinLock},
    wsk::{
        ListenerBinding, ListenerCallbacks, ListenerSet, WskDataplane, WskProvider, WskSocketHandle,
    },
};

const MAX_CALLBACK_EVENTS: usize = 128;
const MAX_CALLBACK_PAYLOAD_BYTES: usize = 64 * 1024;

#[cfg(ssp_wdk_native)]
use wdk_sys::{
    ntddk::{ExAllocatePool2, ExFreePool},
    POOL_FLAG_NON_PAGED,
};

/// Administrators-and-system-only SDDL used by `IoCreateDeviceSecure`.
pub const DEVICE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

const DEVICE_NAME: &str = "\\Device\\ShadowSocketProxyKernelRelay";
const SYMBOLIC_LINK_NAME: &str = "\\DosDevices\\ShadowSocketProxyKernelRelay";
const DEVICE_CLASS_GUID: ffi::Guid = ffi::Guid {
    data1: 0xE2BF_0148,
    data2: 0xB2F9,
    data3: 0x49FD,
    data4: [0xA2, 0xC5, 0x74, 0x6E, 0x4D, 0xBE, 0x40, 0x09],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingKey {
    request_id: u64,
    generation: u32,
    epoch: u64,
}

impl PendingKey {
    fn from_request(request: &TunnelRequest) -> Self {
        Self {
            request_id: request.request_id,
            generation: request.generation,
            epoch: request.epoch,
        }
    }

    fn from_response(response: &TunnelResponse) -> Self {
        Self {
            request_id: response.request_id,
            generation: response.generation,
            epoch: response.epoch,
        }
    }

    fn from_cancel(cancel: &CancelTunnelRequest) -> Self {
        Self {
            request_id: cancel.request_id,
            generation: cancel.generation,
            epoch: cancel.epoch,
        }
    }
}

#[derive(Debug, Clone)]
struct QueuedRequest {
    key: PendingKey,
    frame: Vec<u8>,
}

#[derive(Debug)]
struct ActiveTcpRelay {
    inbound: WskSocketHandle,
    outbound: WskSocketHandle,
    ownership: TcpRelayOwnership,
}

#[derive(Debug)]
struct PendingUdpDatagram {
    inbound: WskSocketHandle,
    tuple: SocketTuple,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ActiveUdpAssociation {
    flow: FlowIdentity,
    inbound: WskSocketHandle,
    outbound: WskSocketHandle,
    client: SocketAddr,
    remote: SocketAddr,
    deadline_ns: u64,
}

#[derive(Debug, Clone, Copy)]
/// Startup-only runtime bounds for the native relay path.
pub struct NativeRuntimeConfig {
    pub resource_limits: ResourceLimits,
    pub relay_buffer_bytes: usize,
    pub connect_timeout_ns: u64,
    pub idle_timeout_ns: u64,
    pub shutdown_drain_timeout_ns: u64,
}

impl Default for NativeRuntimeConfig {
    fn default() -> Self {
        Self {
            resource_limits: ResourceLimits::default(),
            relay_buffer_bytes: 64 * 1024,
            connect_timeout_ns: 5_000_000_000,
            idle_timeout_ns: 60_000_000_000,
            shutdown_drain_timeout_ns: 5_000_000_000,
        }
    }
}

struct DriverControlState {
    controller: FlowController<DbgPrintTelemetry>,
    config: NativeRuntimeConfig,
    queued_requests: VecDeque<QueuedRequest>,
    pending_flows: HashMap<PendingKey, FlowIdentity>,
    inbound_tcp: HashMap<u64, WskSocketHandle>,
    tcp_socket_flows: HashMap<WskSocketHandle, FlowIdentity>,
    tcp_directions: HashMap<WskSocketHandle, (FlowIdentity, RelayDirection)>,
    pending_udp: HashMap<PendingKey, PendingUdpDatagram>,
    pending_udp_tuples: HashMap<SocketTuple, PendingKey>,
    tcp_relays: HashMap<u64, ActiveTcpRelay>,
    udp_associations: HashMap<u64, ActiveUdpAssociation>,
    udp_socket_flows: HashMap<WskSocketHandle, FlowIdentity>,
    udp_tuples: HashMap<SocketTuple, FlowIdentity>,
}

impl DriverControlState {
    fn new(config: NativeRuntimeConfig) -> Self {
        Self {
            controller: FlowController::with_limits(DbgPrintTelemetry, config.resource_limits),
            config,
            queued_requests: VecDeque::new(),
            pending_flows: HashMap::new(),
            inbound_tcp: HashMap::new(),
            tcp_socket_flows: HashMap::new(),
            tcp_directions: HashMap::new(),
            pending_udp: HashMap::new(),
            pending_udp_tuples: HashMap::new(),
            tcp_relays: HashMap::new(),
            udp_associations: HashMap::new(),
            udp_socket_flows: HashMap::new(),
            udp_tuples: HashMap::new(),
        }
    }
}

#[derive(Debug)]
enum CallbackEvent {
    TcpAccept {
        socket: WskSocketHandle,
        tuple: SocketTuple,
    },
    TcpPayload {
        socket: WskSocketHandle,
        payload: CallbackPayload,
    },
    UdpPayload {
        socket: WskSocketHandle,
        tuple: SocketTuple,
        payload: CallbackPayload,
    },
    Disconnect {
        socket: WskSocketHandle,
    },
}

#[cfg(ssp_wdk_native)]
#[derive(Debug)]
struct CallbackPayload {
    allocation: *mut u8,
    len: usize,
}

#[cfg(ssp_wdk_native)]
unsafe impl Send for CallbackPayload {}

#[cfg(ssp_wdk_native)]
impl CallbackPayload {
    fn copy_from(bytes: &[u8]) -> Result<Self, crate::KernelRelayError> {
        if bytes.len() > MAX_CALLBACK_PAYLOAD_BYTES {
            return Err(crate::KernelRelayError::PayloadTooLarge {
                actual: bytes.len(),
                max: MAX_CALLBACK_PAYLOAD_BYTES,
            });
        }
        let allocation = unsafe {
            ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                bytes.len().max(1) as u64,
                u32::from_ne_bytes(*b"SspC"),
            )
        };
        if allocation.is_null() {
            return Err(crate::KernelRelayError::ResourceExhausted(
                "native WSK callback payload allocation failed",
            ));
        }
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), allocation.cast(), bytes.len());
        }
        Ok(Self {
            allocation: allocation.cast(),
            len: bytes.len(),
        })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.allocation, self.len) }
    }
}

#[cfg(ssp_wdk_native)]
impl Drop for CallbackPayload {
    fn drop(&mut self) {
        if !self.allocation.is_null() {
            unsafe { ExFreePool(self.allocation.cast()) };
            self.allocation = ptr::null_mut();
        }
    }
}

#[cfg(not(ssp_wdk_native))]
#[derive(Debug)]
struct CallbackPayload {
    bytes: Vec<u8>,
}

#[cfg(not(ssp_wdk_native))]
impl CallbackPayload {
    fn copy_from(bytes: &[u8]) -> Result<Self, crate::KernelRelayError> {
        if bytes.len() > MAX_CALLBACK_PAYLOAD_BYTES {
            return Err(crate::KernelRelayError::PayloadTooLarge {
                actual: bytes.len(),
                max: MAX_CALLBACK_PAYLOAD_BYTES,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
struct CallbackQueue {
    events: VecDeque<CallbackEvent>,
}

impl CallbackQueue {
    fn new() -> Self {
        let mut events = VecDeque::new();
        events.reserve(MAX_CALLBACK_EVENTS);
        Self { events }
    }
}

#[derive(Debug, Default)]
struct FastPathState {
    pending_requests: u32,
    active_relays: u32,
}

/// Driver-owned runtime rooted in the device extension.
pub struct DriverRuntime {
    pub transport_state: PushLock<TransportStatusReport>,
    pub listeners: PushLock<ListenerSet>,
    control: PushLock<DriverControlState>,
    fast_path: SpinLock<FastPathState>,
    callback_queue: SpinLock<CallbackQueue>,
    #[cfg(not(ssp_wdk_native))]
    synthetic_sockets: PushLock<usize>,
    pub wsk: WskProvider,
    #[cfg(ssp_wdk_native)]
    native_device: *mut ffi::DeviceObject,
}

impl DriverRuntime {
    /// Creates the driver runtime with startup-only kernel relay bounds.
    pub fn new(config: NativeRuntimeConfig) -> Self {
        Self {
            transport_state: PushLock::new(TransportStatusReport {
                state: TransportChannelState::Disconnected,
                epoch: 0,
            }),
            listeners: PushLock::new(ListenerSet::default()),
            control: PushLock::new(DriverControlState::new(config)),
            fast_path: SpinLock::new(FastPathState::default()),
            callback_queue: SpinLock::new(CallbackQueue::new()),
            #[cfg(not(ssp_wdk_native))]
            synthetic_sockets: PushLock::new(1),
            wsk: WskProvider::new(),
            #[cfg(ssp_wdk_native)]
            native_device: core::ptr::null_mut(),
        }
    }

    /// Creates, binds, and listens on the configured sockets through the WSK
    /// dataplane abstraction.
    pub fn start_listeners<A: WskDataplane>(
        &self,
        api: &mut A,
        bindings: &[ListenerBinding],
        callbacks: ListenerCallbacks,
    ) -> Result<(), crate::KernelRelayError> {
        self.listeners
            .lock_exclusive()
            .start(api, bindings, callbacks)
    }

    /// Creates the native WSK dataplane view for driver-owned operations.
    #[cfg(ssp_wdk_native)]
    pub unsafe fn native_dataplane(
        &self,
        device: *mut ffi::DeviceObject,
    ) -> Result<NativeWskDataplane<'_>, crate::KernelRelayError> {
        self.wsk.dataplane(device)
    }

    /// Starts configured listeners through the captured native WSK provider.
    #[cfg(ssp_wdk_native)]
    pub unsafe fn start_native_listeners(
        &self,
        device: *mut ffi::DeviceObject,
        bindings: &[ListenerBinding],
        callbacks: ListenerCallbacks,
    ) -> Result<(), crate::KernelRelayError> {
        let mut dataplane = self.native_dataplane(device)?;
        self.start_listeners(&mut dataplane, bindings, callbacks)
    }

    /// Starts native listeners using the driver-owned payload callback table.
    #[cfg(ssp_wdk_native)]
    pub unsafe fn start_native_listeners_with_runtime_callbacks(
        &self,
        device: *mut ffi::DeviceObject,
        bindings: &[ListenerBinding],
    ) -> Result<(), crate::KernelRelayError> {
        self.start_native_listeners(device, bindings, self.callback_table())
    }

    /// Callback entry point for one accepted TCP socket.
    pub fn on_tcp_accept(
        &self,
        inbound: WskSocketHandle,
        tuple: SocketTuple,
    ) -> Result<FlowIdentity, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let admission = control
            .controller
            .admit_tcp(tuple, ExecutionLevel::Dispatch)?;
        let key = PendingKey::from_request(&admission.request);
        control.queued_requests.push_back(QueuedRequest {
            key,
            frame: admission.request.encode()?,
        });
        control.pending_flows.insert(key, admission.flow);
        control.inbound_tcp.insert(admission.flow.flow_id, inbound);
        control.tcp_socket_flows.insert(inbound, admission.flow);
        let mut fast = self.fast_path.lock();
        fast.pending_requests = fast.pending_requests.saturating_add(1);
        Ok(admission.flow)
    }

    /// Callback entry point for one UDP or QUIC datagram.
    pub fn on_udp_datagram(
        &self,
        tuple: SocketTuple,
    ) -> Result<FlowIdentity, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let admission = if tuple.protocol == FlowProtocol::QuicUdp {
            control
                .controller
                .admit_quic(tuple.clone(), ExecutionLevel::Dispatch)?
        } else {
            control
                .controller
                .admit_udp(tuple.clone(), ExecutionLevel::Dispatch)?
        };
        let key = PendingKey::from_request(&admission.request);
        control.queued_requests.push_back(QueuedRequest {
            key,
            frame: admission.request.encode()?,
        });
        control.pending_flows.insert(key, admission.flow);
        control.pending_udp.insert(
            key,
            PendingUdpDatagram {
                inbound: WskSocketHandle(0),
                tuple: tuple.clone(),
                bytes: Vec::new(),
            },
        );
        control.pending_udp_tuples.insert(tuple, key);
        let mut fast = self.fast_path.lock();
        fast.pending_requests = fast.pending_requests.saturating_add(1);
        Ok(admission.flow)
    }

    /// Forwards bytes received on one side of a mapped TCP relay.
    pub fn on_tcp_payload<A: WskDataplane>(
        &self,
        api: &mut A,
        socket: WskSocketHandle,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let max_bytes = control.config.relay_buffer_bytes;
        if bytes.len() > max_bytes {
            if let Some(flow) = control
                .tcp_directions
                .get(&socket)
                .map(|(flow, _)| *flow)
                .or_else(|| control.tcp_socket_flows.get(&socket).copied())
            {
                self.fail_tcp_flow_locked(api, &mut control, flow, "TCP payload exceeded bound")?;
            }
            return Err(crate::KernelRelayError::PayloadTooLarge {
                actual: bytes.len(),
                max: max_bytes,
            });
        }
        let idle_timeout_ns = control.config.idle_timeout_ns;
        let Some((flow, direction)) = control.tcp_directions.get(&socket).copied() else {
            if let Some(flow) = control.tcp_socket_flows.get(&socket).copied() {
                self.fail_tcp_flow_locked(
                    api,
                    &mut control,
                    flow,
                    "TCP payload arrived before mapping",
                )?;
                return Err(crate::KernelRelayError::InvalidState(
                    "TCP payload arrived before mapping".into(),
                ));
            }
            return Err(crate::KernelRelayError::FlowNotFound {
                flow_id: 0,
                generation: 0,
            });
        };
        let (destination, reserve_error) = {
            let Some(relay) = control.tcp_relays.get_mut(&flow.flow_id) else {
                self.fail_tcp_flow_locked(api, &mut control, flow, "TCP relay unavailable")?;
                return Err(crate::KernelRelayError::FlowNotFound {
                    flow_id: flow.flow_id,
                    generation: flow.generation,
                });
            };
            let destination = match direction {
                RelayDirection::ClientToOrigin => relay.outbound,
                RelayDirection::OriginToClient => relay.inbound,
            };
            (
                destination,
                relay.ownership.buffers.reserve(bytes.len()).err(),
            )
        };
        if let Some(error) = reserve_error {
            self.fail_tcp_flow_locked(api, &mut control, flow, "TCP relay buffer exhausted")?;
            return Err(error);
        }
        let result = api.send_stream_bytes(destination, bytes);
        let result = {
            let Some(relay) = control.tcp_relays.get_mut(&flow.flow_id) else {
                self.fail_tcp_flow_locked(api, &mut control, flow, "TCP relay unavailable")?;
                return Err(crate::KernelRelayError::FlowNotFound {
                    flow_id: flow.flow_id,
                    generation: flow.generation,
                });
            };
            relay.ownership.buffers.release(bytes.len());
            if result.as_ref().is_ok_and(|sent| *sent == bytes.len()) {
                relay.ownership.record_activity(now_ns, idle_timeout_ns);
            }
            result
        };
        match result {
            Ok(sent) if sent == bytes.len() => Ok(sent),
            Ok(sent) => {
                self.fail_tcp_flow_locked(
                    api,
                    &mut control,
                    flow,
                    "TCP relay returned a short payload send",
                )?;
                Err(crate::KernelRelayError::Transport(format!(
                    "TCP relay sent {sent} of {} bytes",
                    bytes.len()
                )))
            }
            Err(error) => {
                self.fail_tcp_flow_locked(api, &mut control, flow, "TCP payload send failed")?;
                Err(error)
            }
        }
    }

    /// Alias for callers that describe the callback as an inbound byte event.
    pub fn on_tcp_bytes<A: WskDataplane>(
        &self,
        api: &mut A,
        socket: WskSocketHandle,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        self.on_tcp_payload(api, socket, bytes, now_ns)
    }

    /// Explicit byte-oriented name for TCP receive callback adapters.
    pub fn on_tcp_receive_bytes<A: WskDataplane>(
        &self,
        api: &mut A,
        socket: WskSocketHandle,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        self.on_tcp_payload(api, socket, bytes, now_ns)
    }

    /// Forwards one inbound UDP or QUIC datagram, retaining the first payload
    /// until its mapping completion arrives.
    pub fn on_udp_datagram_payload<A: WskDataplane>(
        &self,
        api: &mut A,
        inbound: WskSocketHandle,
        tuple: SocketTuple,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let max_bytes = control.config.relay_buffer_bytes;
        if bytes.len() > max_bytes {
            if let Some(flow) = control.udp_tuples.get(&tuple).copied().or_else(|| {
                control
                    .pending_udp_tuples
                    .get(&tuple)
                    .and_then(|key| control.pending_flows.get(key))
                    .copied()
            }) {
                self.fail_udp_flow_locked(api, &mut control, flow, "UDP payload exceeded bound")?;
            }
            return Err(crate::KernelRelayError::PayloadTooLarge {
                actual: bytes.len(),
                max: max_bytes,
            });
        }

        let idle_timeout_ns = control.config.idle_timeout_ns;
        if let Some(flow) = control.udp_tuples.get(&tuple).copied() {
            let Some(association) = control.udp_associations.get_mut(&flow.flow_id) else {
                self.fail_udp_flow_locked(api, &mut control, flow, "UDP association unavailable")?;
                return Err(crate::KernelRelayError::FlowNotFound {
                    flow_id: flow.flow_id,
                    generation: flow.generation,
                });
            };
            let result = api.send_datagram_bytes(association.outbound, bytes, association.remote);
            match result {
                Ok(sent) if sent == bytes.len() => {
                    association.deadline_ns = now_ns.saturating_add(idle_timeout_ns);
                    return Ok(sent);
                }
                Ok(sent) => {
                    self.fail_udp_flow_locked(
                        api,
                        &mut control,
                        flow,
                        "UDP relay returned a short payload send",
                    )?;
                    return Err(crate::KernelRelayError::Transport(format!(
                        "UDP relay sent {sent} of {} bytes",
                        bytes.len()
                    )));
                }
                Err(error) => {
                    self.fail_udp_flow_locked(api, &mut control, flow, "UDP payload send failed")?;
                    return Err(error);
                }
            }
        }

        if let Some(key) = control.pending_udp_tuples.get(&tuple).copied() {
            let Some(flow) = control.pending_flows.get(&key).copied() else {
                control.pending_udp_tuples.remove(&tuple);
                return Err(crate::KernelRelayError::RequestNotFound {
                    request_id: key.request_id,
                    generation: key.generation,
                    epoch: key.epoch,
                });
            };
            let pending = control
                .pending_udp
                .get_mut(&key)
                .expect("pending UDP tuple must have payload state");
            if pending.bytes.is_empty() {
                pending.inbound = inbound;
                pending.bytes.extend_from_slice(bytes);
                return Ok(bytes.len());
            }
            self.fail_udp_flow_locked(
                api,
                &mut control,
                flow,
                "multiple UDP datagrams arrived before mapping",
            )?;
            return Err(crate::KernelRelayError::InvalidState(
                "multiple UDP datagrams arrived before mapping".into(),
            ));
        }

        let admission = if tuple.protocol == FlowProtocol::QuicUdp {
            control
                .controller
                .admit_quic(tuple.clone(), ExecutionLevel::Dispatch)?
        } else {
            control
                .controller
                .admit_udp(tuple.clone(), ExecutionLevel::Dispatch)?
        };
        let key = PendingKey::from_request(&admission.request);
        control.queued_requests.push_back(QueuedRequest {
            key,
            frame: admission.request.encode()?,
        });
        control.pending_flows.insert(key, admission.flow);
        control.pending_udp.insert(
            key,
            PendingUdpDatagram {
                inbound,
                tuple: tuple.clone(),
                bytes: bytes.to_vec(),
            },
        );
        control.pending_udp_tuples.insert(tuple, key);
        let mut fast = self.fast_path.lock();
        fast.pending_requests = fast.pending_requests.saturating_add(1);
        Ok(bytes.len())
    }

    /// Explicit byte-oriented name for UDP/QUIC receive callback adapters.
    pub fn on_udp_datagram_bytes<A: WskDataplane>(
        &self,
        api: &mut A,
        inbound: WskSocketHandle,
        tuple: SocketTuple,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        self.on_udp_datagram_payload(api, inbound, tuple, bytes, now_ns)
    }

    /// Forwards one origin-side UDP reply to its owning client.
    pub fn on_udp_reply<A: WskDataplane>(
        &self,
        api: &mut A,
        flow: FlowIdentity,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        if bytes.len() > control.config.relay_buffer_bytes {
            self.fail_udp_flow_locked(api, &mut control, flow, "UDP reply exceeded bound")?;
            return Err(crate::KernelRelayError::PayloadTooLarge {
                actual: bytes.len(),
                max: control.config.relay_buffer_bytes,
            });
        }
        let idle_timeout_ns = control.config.idle_timeout_ns;
        let Some(association) = control.udp_associations.get_mut(&flow.flow_id) else {
            return Err(crate::KernelRelayError::FlowNotFound {
                flow_id: flow.flow_id,
                generation: flow.generation,
            });
        };
        let result = api.send_datagram_bytes(association.inbound, bytes, association.client);
        match result {
            Ok(sent) if sent == bytes.len() => {
                association.deadline_ns = now_ns.saturating_add(idle_timeout_ns);
                Ok(sent)
            }
            Ok(sent) => {
                self.fail_udp_flow_locked(api, &mut control, flow, "UDP reply was short")?;
                Err(crate::KernelRelayError::Transport(format!(
                    "UDP reply sent {sent} of {} bytes",
                    bytes.len()
                )))
            }
            Err(error) => {
                self.fail_udp_flow_locked(api, &mut control, flow, "UDP reply failed")?;
                Err(error)
            }
        }
    }

    /// Routes a UDP reply using the outbound WSK socket callback context.
    pub fn on_udp_reply_from_socket<A: WskDataplane>(
        &self,
        api: &mut A,
        outbound: WskSocketHandle,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        let flow = self
            .control
            .lock_exclusive()
            .udp_socket_flows
            .get(&outbound)
            .copied()
            .ok_or(crate::KernelRelayError::FlowNotFound {
                flow_id: 0,
                generation: 0,
            })?;
        self.on_udp_reply(api, flow, bytes, now_ns)
    }

    /// Returns callbacks whose context is this driver runtime.
    ///
    /// Native WSK callbacks only copy bounded nonpaged indications and route
    /// them into these driver-owned entry points. Payload downcalls are
    /// asynchronous in the native dataplane.
    pub fn callback_table(&self) -> ListenerCallbacks {
        ListenerCallbacks {
            context: self as *const DriverRuntime as usize,
            on_accept: Some(runtime_on_accept),
            on_stream: Some(runtime_on_stream),
            on_datagram: Some(runtime_on_datagram),
            on_disconnect: Some(runtime_on_disconnect),
            on_send_failure: Some(runtime_on_send_failure),
        }
    }

    fn enqueue_callback(&self, event: CallbackEvent) -> Result<(), crate::KernelRelayError> {
        let mut queue = self.callback_queue.lock();
        if queue.events.len() >= MAX_CALLBACK_EVENTS {
            return Err(crate::KernelRelayError::ResourceExhausted(
                "WSK callback queue is full",
            ));
        }
        queue.events.push_back(event);
        Ok(())
    }

    /// Drains bounded WSK callback work at PASSIVE level.
    pub fn drain_callback_events<A: WskDataplane>(
        &self,
        api: &mut A,
        now_ns: u64,
        max_events: usize,
    ) -> Result<usize, crate::KernelRelayError> {
        let mut processed = 0;
        let mut first_error = None;
        while processed < max_events {
            let event = self.callback_queue.lock().events.pop_front();
            let Some(event) = event else {
                break;
            };
            let result = match event {
                CallbackEvent::TcpAccept { socket, tuple } => self
                    .on_tcp_accept(socket, tuple)
                    .map(|_| ())
                    .or_else(|error| {
                        let _ = api.close_socket(socket);
                        Err(error)
                    }),
                CallbackEvent::TcpPayload { socket, payload } => self
                    .on_tcp_payload(api, socket, payload.as_slice(), now_ns)
                    .map(|_| ()),
                CallbackEvent::UdpPayload {
                    socket,
                    tuple,
                    payload,
                } => self
                    .on_datagram_from_socket(api, socket, tuple, payload.as_slice(), now_ns)
                    .map(|_| ()),
                CallbackEvent::Disconnect { socket } => self.on_socket_disconnect(api, socket),
            };
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
            processed += 1;
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(processed),
        }
    }

    fn enqueue_tcp_accept(
        &self,
        socket: WskSocketHandle,
        tuple: SocketTuple,
    ) -> Result<(), crate::KernelRelayError> {
        self.enqueue_callback(CallbackEvent::TcpAccept { socket, tuple })
    }

    fn enqueue_tcp_payload(
        &self,
        socket: WskSocketHandle,
        bytes: &[u8],
    ) -> Result<(), crate::KernelRelayError> {
        self.enqueue_callback(CallbackEvent::TcpPayload {
            socket,
            payload: CallbackPayload::copy_from(bytes)?,
        })
    }

    fn enqueue_udp_payload(
        &self,
        socket: WskSocketHandle,
        tuple: SocketTuple,
        bytes: &[u8],
    ) -> Result<(), crate::KernelRelayError> {
        self.enqueue_callback(CallbackEvent::UdpPayload {
            socket,
            tuple,
            payload: CallbackPayload::copy_from(bytes)?,
        })
    }

    fn on_datagram_from_socket<A: WskDataplane>(
        &self,
        api: &mut A,
        socket: WskSocketHandle,
        tuple: SocketTuple,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        let is_outbound = self
            .control
            .lock_exclusive()
            .udp_socket_flows
            .contains_key(&socket);
        if is_outbound {
            self.on_udp_reply_from_socket(api, socket, bytes, now_ns)
        } else {
            self.on_udp_datagram_payload(api, socket, tuple, bytes, now_ns)
        }
    }

    fn on_socket_disconnect<A: WskDataplane>(
        &self,
        api: &mut A,
        socket: WskSocketHandle,
    ) -> Result<(), crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        if let Some((flow, _)) = control.tcp_directions.get(&socket).copied() {
            return self.fail_tcp_flow_locked(api, &mut control, flow, "WSK TCP disconnect");
        }
        if let Some(flow) = control.tcp_socket_flows.get(&socket).copied() {
            return self.fail_tcp_flow_locked(api, &mut control, flow, "WSK TCP disconnect");
        }
        if let Some(flow) = control.udp_socket_flows.get(&socket).copied() {
            return self.fail_udp_flow_locked(api, &mut control, flow, "WSK UDP disconnect");
        }
        Ok(())
    }

    /// Returns the next pending opaque tunnel frame for `IOCTL_SSP_DEQUEUE_REQUEST`.
    pub fn dequeue_pending_frame(
        &self,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let Some(frame) = control.queued_requests.front() else {
            return Ok(None);
        };
        if frame.frame.len() > max_len {
            return Err(crate::KernelRelayError::PayloadTooLarge {
                actual: frame.frame.len(),
                max: max_len,
            });
        }
        let frame = control
            .queued_requests
            .pop_front()
            .expect("pending queue front must exist");
        Ok(Some(frame.frame))
    }

    /// Applies one correlated tunnel completion using a caller-supplied WSK
    /// dataplane.
    pub fn apply_tunnel_response<A: WskDataplane>(
        &self,
        api: &mut A,
        response: TunnelResponse,
        now_ns: u64,
    ) -> Result<(), crate::KernelRelayError> {
        self.apply_tunnel_response_with(api, response, now_ns)
    }

    /// Cancels one unresolved request and closes only the affected flow.
    pub fn cancel_pending_request<A: WskDataplane>(
        &self,
        api: &mut A,
        cancel: CancelTunnelRequest,
    ) -> Result<bool, crate::KernelRelayError> {
        let key = PendingKey::from_cancel(&cancel);
        let mut control = self.control.lock_exclusive();
        let Some(flow) = control.pending_flows.remove(&key) else {
            return Ok(false);
        };
        control.queued_requests.retain(|queued| queued.key != key);
        if let Some(inbound) = control.inbound_tcp.remove(&flow.flow_id) {
            control.tcp_socket_flows.remove(&inbound);
            api.close_socket(inbound)?;
        }
        if let Some(pending) = control.pending_udp.remove(&key) {
            control.pending_udp_tuples.remove(&pending.tuple);
        }
        control.controller.cancel_flow(
            flow,
            ExecutionLevel::Passive,
            "driver request cancelled",
        )?;
        Ok(true)
    }

    /// Updates transport status and closes only unresolved flows on channel
    /// loss or shutdown.
    pub fn update_transport_state<A: WskDataplane>(
        &self,
        api: &mut A,
        report: TransportStatusReport,
    ) -> Result<(), crate::KernelRelayError> {
        *self.transport_state.lock_exclusive() = report;
        let mut control = self.control.lock_exclusive();
        match report.state {
            TransportChannelState::Connected => {}
            TransportChannelState::Disconnected => {
                self.close_unresolved_flows(api, &mut control, "transport disconnected")?;
                control
                    .controller
                    .transport_disconnected(ExecutionLevel::Passive);
            }
            TransportChannelState::ShuttingDown => {
                self.close_unresolved_flows(api, &mut control, "transport shutting down")?;
                control.controller.begin_shutdown(ExecutionLevel::Passive);
            }
        }
        Ok(())
    }

    /// Drives one TCP half-close and releases the flow after both directions
    /// drain.
    pub fn on_tcp_half_close<A: WskDataplane>(
        &self,
        api: &mut A,
        flow: FlowIdentity,
        direction: RelayDirection,
    ) -> Result<FlowState, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let (_state, closed_sockets) = {
            let Some(relay) = control.tcp_relays.get_mut(&flow.flow_id) else {
                return Err(crate::KernelRelayError::FlowNotFound {
                    flow_id: flow.flow_id,
                    generation: flow.generation,
                });
            };
            let state = relay.ownership.half_close(direction)?;
            let closed_sockets =
                (state == crate::RelayState::Closed).then_some((relay.inbound, relay.outbound));
            (state, closed_sockets)
        };
        if let Some((inbound, outbound)) = closed_sockets {
            control.tcp_directions.remove(&inbound);
            control.tcp_directions.remove(&outbound);
            api.close_socket(inbound)?;
            api.close_socket(outbound)?;
            control.tcp_relays.remove(&flow.flow_id);
            control
                .controller
                .release_flow(flow, ExecutionLevel::Dispatch, "tcp relay drained")?;
            let mut fast = self.fast_path.lock();
            fast.active_relays = fast.active_relays.saturating_sub(1);
        }
        Ok(control
            .controller
            .flow_state(flow)
            .unwrap_or(FlowState::Released))
    }

    /// Returns the current flow state for tests and diagnostics.
    pub fn flow_state(&self, flow: FlowIdentity) -> Option<FlowState> {
        self.control.lock_exclusive().controller.flow_state(flow)
    }

    /// Returns the number of queued pending tunnel requests.
    pub fn queued_request_count(&self) -> usize {
        self.control.lock_exclusive().queued_requests.len()
    }

    /// Returns the number of active TCP relays.
    pub fn active_tcp_relay_count(&self) -> usize {
        self.control.lock_exclusive().tcp_relays.len()
    }

    /// Returns the number of active UDP associations.
    pub fn active_udp_association_count(&self) -> usize {
        self.control.lock_exclusive().udp_associations.len()
    }

    /// Sends one bounded UDP reply and refreshes the idle deadline.
    pub fn send_udp_reply<A: WskDataplane>(
        &self,
        api: &mut A,
        flow: FlowIdentity,
        bytes: usize,
        now_ns: u64,
    ) -> Result<(), crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let idle_timeout_ns = control.config.idle_timeout_ns;
        let association = control.udp_associations.get_mut(&flow.flow_id).ok_or(
            crate::KernelRelayError::FlowNotFound {
                flow_id: flow.flow_id,
                generation: flow.generation,
            },
        )?;
        api.send_datagram(association.outbound, bytes)?;
        association.deadline_ns = now_ns.saturating_add(idle_timeout_ns);
        Ok(())
    }

    /// Expires idle UDP associations and releases only their owning flows.
    pub fn expire_udp_associations<A: WskDataplane>(
        &self,
        api: &mut A,
        now_ns: u64,
    ) -> Result<usize, crate::KernelRelayError> {
        let mut control = self.control.lock_exclusive();
        let expired: Vec<u64> = control
            .udp_associations
            .iter()
            .filter_map(|(flow_id, association)| {
                (association.deadline_ns <= now_ns).then_some(*flow_id)
            })
            .collect();
        for flow_id in &expired {
            if let Some(association) = control.udp_associations.remove(flow_id) {
                control.udp_socket_flows.remove(&association.outbound);
                control
                    .udp_tuples
                    .retain(|_, candidate| candidate.flow_id != *flow_id);
                api.close_socket(association.outbound)?;
                control.controller.release_flow(
                    association.flow,
                    ExecutionLevel::Passive,
                    "udp association expired",
                )?;
            }
        }
        Ok(expired.len())
    }

    fn apply_tunnel_response_with<A: WskDataplane>(
        &self,
        api: &mut A,
        response: TunnelResponse,
        now_ns: u64,
    ) -> Result<(), crate::KernelRelayError> {
        let key = PendingKey::from_response(&response);
        let mut control = self.control.lock_exclusive();
        let disposition = match control
            .controller
            .handle_tunnel_response(response, ExecutionLevel::Passive)
        {
            Ok(disposition) => disposition,
            Err(error) => {
                if let Some(flow) = control.pending_flows.remove(&key) {
                    self.cancel_pending_flow_locked(
                        api,
                        &mut control,
                        key,
                        flow,
                        "malformed mapping response",
                    )?;
                }
                return Err(error);
            }
        };
        match disposition {
            CompletionDisposition::BeginConnect(ready) => {
                let outbound = match api.create_outbound_socket(
                    family_of(ready.mapping.original.destination),
                    ready.mapping.original.protocol,
                ) {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        self.fail_connecting_flow_locked(
                            api,
                            &mut control,
                            ready.flow,
                            key,
                            "outbound socket creation failed",
                        )?;
                        return Err(error);
                    }
                };
                if let Err(error) = api.set_socket_callbacks(outbound, self.callback_table()) {
                    let _ = api.close_socket(outbound);
                    self.fail_connecting_flow_locked(
                        api,
                        &mut control,
                        ready.flow,
                        key,
                        "outbound callback setup failed",
                    )?;
                    return Err(error);
                }
                if let Err(error) = api.connect(outbound, ready.mapping.original.destination) {
                    let _ = api.close_socket(outbound);
                    self.fail_connecting_flow_locked(
                        api,
                        &mut control,
                        ready.flow,
                        key,
                        "outbound connect failed",
                    )?;
                    return Err(error);
                }
                control.pending_flows.remove(&key);
                match ready.mapping.original.protocol {
                    FlowProtocol::Tcp => {
                        let inbound = match control.inbound_tcp.remove(&ready.flow.flow_id) {
                            Some(inbound) => inbound,
                            None => {
                                let _ = api.close_socket(outbound);
                                control.controller.connect_failed(
                                    ready.flow,
                                    ExecutionLevel::Passive,
                                    "accepted TCP socket missing for mapped flow",
                                )?;
                                return Err(crate::KernelRelayError::InvalidState(
                                    "accepted TCP socket missing for mapped flow".into(),
                                ));
                            }
                        };
                        control.tcp_socket_flows.remove(&inbound);
                        let mut ownership = TcpRelayOwnership::new(
                            now_ns.saturating_add(control.config.connect_timeout_ns),
                            control.config.relay_buffer_bytes,
                        );
                        ownership.connected(now_ns, control.config.idle_timeout_ns)?;
                        control.tcp_relays.insert(
                            ready.flow.flow_id,
                            ActiveTcpRelay {
                                inbound,
                                outbound,
                                ownership,
                            },
                        );
                        control
                            .tcp_directions
                            .insert(inbound, (ready.flow, RelayDirection::ClientToOrigin));
                        control
                            .tcp_directions
                            .insert(outbound, (ready.flow, RelayDirection::OriginToClient));
                        control
                            .controller
                            .connect_succeeded(ready.flow, ExecutionLevel::Passive)?;
                        let mut fast = self.fast_path.lock();
                        fast.active_relays = fast.active_relays.saturating_add(1);
                    }
                    FlowProtocol::Udp | FlowProtocol::QuicUdp => {
                        let pending = control.pending_udp.remove(&key);
                        if let Some(pending) = &pending {
                            control.pending_udp_tuples.remove(&pending.tuple);
                            if !pending.bytes.is_empty() {
                                let send_result = api.send_datagram_bytes(
                                    outbound,
                                    &pending.bytes,
                                    ready.mapping.original.destination,
                                );
                                let sent = match send_result {
                                    Ok(sent) => sent,
                                    Err(error) => {
                                        let _ = api.close_socket(outbound);
                                        self.fail_connecting_flow_locked(
                                            api,
                                            &mut control,
                                            ready.flow,
                                            key,
                                            "initial UDP payload send failed",
                                        )?;
                                        return Err(error);
                                    }
                                };
                                if sent != pending.bytes.len() {
                                    let _ = api.close_socket(outbound);
                                    self.fail_connecting_flow_locked(
                                        api,
                                        &mut control,
                                        ready.flow,
                                        key,
                                        "initial UDP payload send was short",
                                    )?;
                                    return Err(crate::KernelRelayError::Transport(format!(
                                        "initial UDP payload sent {sent} of {} bytes",
                                        pending.bytes.len()
                                    )));
                                }
                            }
                        }
                        control
                            .controller
                            .connect_succeeded(ready.flow, ExecutionLevel::Passive)?;
                        let idle_deadline = now_ns.saturating_add(control.config.idle_timeout_ns);
                        let (inbound, client) = pending
                            .as_ref()
                            .map(|pending| (pending.inbound, pending.tuple.source))
                            .unwrap_or((WskSocketHandle(0), ready.mapping.synthetic.source));
                        control.udp_associations.insert(
                            ready.flow.flow_id,
                            ActiveUdpAssociation {
                                flow: ready.flow,
                                inbound,
                                outbound,
                                client,
                                remote: ready.mapping.original.destination,
                                deadline_ns: idle_deadline,
                            },
                        );
                        control.udp_socket_flows.insert(outbound, ready.flow);
                        control
                            .udp_tuples
                            .insert(ready.mapping.synthetic, ready.flow);
                    }
                }
            }
            CompletionDisposition::Rejected { .. } => {}
            CompletionDisposition::Closed { flow, .. } => {
                control.pending_flows.remove(&key);
                if let Some(inbound) = control.inbound_tcp.remove(&flow.flow_id) {
                    control.tcp_socket_flows.remove(&inbound);
                    let _ = api.close_socket(inbound);
                }
                if let Some(pending) = control.pending_udp.remove(&key) {
                    control.pending_udp_tuples.remove(&pending.tuple);
                }
            }
        }
        Ok(())
    }

    fn close_unresolved_flows<A: WskDataplane>(
        &self,
        api: &mut A,
        control: &mut DriverControlState,
        _reason: &'static str,
    ) -> Result<(), crate::KernelRelayError> {
        for (_key, flow) in control.pending_flows.drain() {
            if let Some(inbound) = control.inbound_tcp.remove(&flow.flow_id) {
                control.tcp_socket_flows.remove(&inbound);
                api.close_socket(inbound)?;
            }
        }
        control.pending_udp.clear();
        control.pending_udp_tuples.clear();
        control.queued_requests.clear();
        Ok(())
    }

    fn fail_tcp_flow_locked<A: WskDataplane>(
        &self,
        api: &mut A,
        control: &mut DriverControlState,
        flow: FlowIdentity,
        reason: &'static str,
    ) -> Result<(), crate::KernelRelayError> {
        let relay = control.tcp_relays.remove(&flow.flow_id);
        if let Some(relay) = relay {
            control.tcp_directions.remove(&relay.inbound);
            control.tcp_directions.remove(&relay.outbound);
            let _ = api.close_socket(relay.inbound);
            let _ = api.close_socket(relay.outbound);
            control
                .controller
                .relay_failed(flow, ExecutionLevel::Dispatch, reason)?;
            let mut fast = self.fast_path.lock();
            fast.active_relays = fast.active_relays.saturating_sub(1);
            return Ok(());
        }

        if let Some(inbound) = control.inbound_tcp.remove(&flow.flow_id) {
            control.tcp_socket_flows.remove(&inbound);
            let _ = api.close_socket(inbound);
        }
        let pending = control
            .pending_flows
            .iter()
            .find_map(|(key, candidate)| (*candidate == flow).then_some(*key));
        if let Some(key) = pending {
            control.pending_flows.remove(&key);
            control.queued_requests.retain(|queued| queued.key != key);
        }
        control
            .controller
            .cancel_flow(flow, ExecutionLevel::Dispatch, reason)?;
        Ok(())
    }

    fn fail_connecting_flow_locked<A: WskDataplane>(
        &self,
        api: &mut A,
        control: &mut DriverControlState,
        flow: FlowIdentity,
        key: PendingKey,
        reason: &'static str,
    ) -> Result<(), crate::KernelRelayError> {
        control.pending_flows.remove(&key);
        if let Some(inbound) = control.inbound_tcp.remove(&flow.flow_id) {
            control.tcp_socket_flows.remove(&inbound);
            let _ = api.close_socket(inbound);
        }
        if let Some(pending) = control.pending_udp.remove(&key) {
            control.pending_udp_tuples.remove(&pending.tuple);
        }
        control
            .controller
            .connect_failed(flow, ExecutionLevel::Passive, reason)
    }

    fn cancel_pending_flow_locked<A: WskDataplane>(
        &self,
        api: &mut A,
        control: &mut DriverControlState,
        key: PendingKey,
        flow: FlowIdentity,
        reason: &'static str,
    ) -> Result<(), crate::KernelRelayError> {
        control.queued_requests.retain(|queued| queued.key != key);
        if let Some(inbound) = control.inbound_tcp.remove(&flow.flow_id) {
            control.tcp_socket_flows.remove(&inbound);
            let _ = api.close_socket(inbound);
        }
        if let Some(pending) = control.pending_udp.remove(&key) {
            control.pending_udp_tuples.remove(&pending.tuple);
        }
        control
            .controller
            .cancel_flow(flow, ExecutionLevel::Passive, reason)
    }

    fn fail_udp_flow_locked<A: WskDataplane>(
        &self,
        api: &mut A,
        control: &mut DriverControlState,
        flow: FlowIdentity,
        reason: &'static str,
    ) -> Result<(), crate::KernelRelayError> {
        if let Some(association) = control.udp_associations.remove(&flow.flow_id) {
            control.udp_socket_flows.remove(&association.outbound);
            control.udp_tuples.retain(|_, candidate| *candidate != flow);
            let _ = api.close_socket(association.outbound);
            control
                .controller
                .relay_failed(flow, ExecutionLevel::Dispatch, reason)?;
            return Ok(());
        }

        if let Some(key) = control
            .pending_flows
            .iter()
            .find_map(|(key, candidate)| (*candidate == flow).then_some(*key))
        {
            control.pending_flows.remove(&key);
            control.queued_requests.retain(|queued| queued.key != key);
            if let Some(pending) = control.pending_udp.remove(&key) {
                control.pending_udp_tuples.remove(&pending.tuple);
            }
        }
        control
            .controller
            .cancel_flow(flow, ExecutionLevel::Dispatch, reason)?;
        Ok(())
    }
}

impl Default for DriverRuntime {
    fn default() -> Self {
        Self::new(NativeRuntimeConfig::default())
    }
}

unsafe fn runtime_on_accept(
    context: usize,
    socket: WskSocketHandle,
    tuple: SocketTuple,
) -> Result<(), crate::KernelRelayError> {
    if context == 0 {
        return Err(crate::KernelRelayError::InvalidState(
            "WSK callback context is null".into(),
        ));
    }
    (&*(context as *const DriverRuntime)).enqueue_tcp_accept(socket, tuple)
}

unsafe fn runtime_on_stream(
    context: usize,
    socket: WskSocketHandle,
    bytes: &[u8],
) -> Result<(), crate::KernelRelayError> {
    if context == 0 {
        return Err(crate::KernelRelayError::InvalidState(
            "WSK callback context is null".into(),
        ));
    }
    (&*(context as *const DriverRuntime)).enqueue_tcp_payload(socket, bytes)
}

unsafe fn runtime_on_datagram(
    context: usize,
    socket: WskSocketHandle,
    tuple: SocketTuple,
    bytes: &[u8],
) -> Result<(), crate::KernelRelayError> {
    if context == 0 {
        return Err(crate::KernelRelayError::InvalidState(
            "WSK callback context is null".into(),
        ));
    }
    (&*(context as *const DriverRuntime)).enqueue_udp_payload(socket, tuple, bytes)
}

unsafe fn runtime_on_disconnect(
    context: usize,
    socket: WskSocketHandle,
) -> Result<(), crate::KernelRelayError> {
    if context == 0 {
        return Err(crate::KernelRelayError::InvalidState(
            "WSK callback context is null".into(),
        ));
    }
    (&*(context as *const DriverRuntime)).enqueue_callback(CallbackEvent::Disconnect { socket })
}

unsafe fn runtime_on_send_failure(context: usize, socket: WskSocketHandle, _status: ffi::NtStatus) {
    if context != 0 {
        let _ = (&*(context as *const DriverRuntime))
            .enqueue_callback(CallbackEvent::Disconnect { socket });
    }
}

#[cfg(not(ssp_wdk_native))]
struct SyntheticDataplane<'a> {
    next_handle: &'a mut usize,
}

#[cfg(not(ssp_wdk_native))]
impl WskDataplane for SyntheticDataplane<'_> {
    fn create_listener_socket(
        &mut self,
        _family: u16,
        _protocol: FlowProtocol,
        _callbacks: ListenerCallbacks,
    ) -> Result<WskSocketHandle, crate::KernelRelayError> {
        Err(crate::KernelRelayError::Transport(
            "listener creation requires an external WSK dataplane".into(),
        ))
    }

    fn bind_listener(
        &mut self,
        _socket: WskSocketHandle,
        _local: SocketAddr,
    ) -> Result<(), crate::KernelRelayError> {
        Err(crate::KernelRelayError::Transport(
            "listener bind requires an external WSK dataplane".into(),
        ))
    }

    fn listen(
        &mut self,
        _socket: WskSocketHandle,
        _backlog: u32,
    ) -> Result<(), crate::KernelRelayError> {
        Err(crate::KernelRelayError::Transport(
            "listen requires an external WSK dataplane".into(),
        ))
    }

    fn create_outbound_socket(
        &mut self,
        _family: u16,
        _protocol: FlowProtocol,
    ) -> Result<WskSocketHandle, crate::KernelRelayError> {
        let handle = WskSocketHandle(*self.next_handle);
        *self.next_handle = self.next_handle.saturating_add(1);
        Ok(handle)
    }

    fn connect(
        &mut self,
        _socket: WskSocketHandle,
        _remote: SocketAddr,
    ) -> Result<(), crate::KernelRelayError> {
        Ok(())
    }

    fn send_stream(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: usize,
    ) -> Result<(), crate::KernelRelayError> {
        Ok(())
    }

    fn recv_stream(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: usize,
    ) -> Result<(), crate::KernelRelayError> {
        Ok(())
    }

    fn shutdown_stream_send(
        &mut self,
        _socket: WskSocketHandle,
    ) -> Result<(), crate::KernelRelayError> {
        Ok(())
    }

    fn send_datagram(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: usize,
    ) -> Result<(), crate::KernelRelayError> {
        Ok(())
    }

    fn close_socket(&mut self, _socket: WskSocketHandle) -> Result<(), crate::KernelRelayError> {
        Ok(())
    }
}

unsafe fn runtime<'a>(device: *mut ffi::DeviceObject) -> &'a mut DriverRuntime {
    &mut *((*device).device_extension.cast::<DriverRuntime>())
}

fn family_of(address: SocketAddr) -> u16 {
    if address.is_ipv4() {
        2
    } else {
        23
    }
}

fn wide_null(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

unsafe fn init_unicode(buffer: &[u16]) -> ffi::UnicodeString {
    let mut unicode = ffi::UnicodeString::default();
    ffi::RtlInitUnicodeString(&mut unicode, buffer.as_ptr());
    unicode
}

unsafe fn complete_irp(
    irp: *mut ffi::Irp,
    status: ffi::NtStatus,
    information: usize,
) -> ffi::NtStatus {
    (*irp).io_status.status = status;
    (*irp).io_status.information = information;
    ffi::IoCompleteRequest(irp, ffi::IO_NO_INCREMENT);
    status
}

unsafe fn system_buffer<'a>(irp: *mut ffi::Irp, length: u32) -> &'a [u8] {
    if length == 0 || (*irp).system_buffer.is_null() {
        &[]
    } else {
        slice::from_raw_parts((*irp).system_buffer.cast::<u8>(), length as usize)
    }
}

unsafe fn system_buffer_mut<'a>(irp: *mut ffi::Irp, length: u32) -> &'a mut [u8] {
    if length == 0 || (*irp).system_buffer.is_null() {
        &mut []
    } else {
        slice::from_raw_parts_mut((*irp).system_buffer.cast::<u8>(), length as usize)
    }
}

unsafe fn current_io_control(irp: *mut ffi::Irp) -> Result<(u32, u32, u32), ffi::NtStatus> {
    let stack = ffi::IoGetCurrentIrpStackLocation(irp);
    if stack.is_null() {
        return Err(ffi::STATUS_INVALID_PARAMETER);
    }
    let control = (*stack).parameters.device_io_control;
    Ok((
        control.io_control_code,
        control.input_buffer_length,
        control.output_buffer_length,
    ))
}

/// Exported kernel entry point.
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver: *mut ffi::DriverObject,
    registry_path: *mut ffi::UnicodeString,
) -> ffi::NtStatus {
    driver_entry(driver, registry_path)
}

/// Creates the secure device, registers WSK, and installs dispatch handlers.
pub unsafe fn driver_entry(
    driver: *mut ffi::DriverObject,
    _registry_path: *mut ffi::UnicodeString,
) -> ffi::NtStatus {
    let device_name = wide_null(DEVICE_NAME);
    let symbolic_link = wide_null(SYMBOLIC_LINK_NAME);
    let sddl = wide_null(DEVICE_SDDL);
    let device_name = init_unicode(&device_name);
    let symbolic_link = init_unicode(&symbolic_link);
    let sddl = init_unicode(&sddl);

    let mut device = ptr::null_mut();
    let status = ffi::IoCreateDeviceSecure(
        driver,
        mem::size_of::<DriverRuntime>() as u32,
        &device_name,
        ffi::FILE_DEVICE_NETWORK,
        ffi::FILE_DEVICE_SECURE_OPEN,
        0,
        &sddl,
        &DEVICE_CLASS_GUID,
        &mut device,
    );
    if !ffi::nt_success(status) {
        return status;
    }

    let status = ffi::IoCreateSymbolicLink(&symbolic_link, &device_name);
    if !ffi::nt_success(status) {
        ffi::IoDeleteDevice(device);
        return status;
    }

    ptr::write(
        (*device).device_extension.cast::<DriverRuntime>(),
        DriverRuntime::default(),
    );
    let runtime = runtime(device);
    if let Err(status) = runtime.wsk.register() {
        ffi::IoDeleteSymbolicLink(&symbolic_link);
        ptr::drop_in_place((*device).device_extension.cast::<DriverRuntime>());
        ffi::IoDeleteDevice(device);
        return status;
    }
    #[cfg(ssp_wdk_native)]
    {
        runtime.native_device = device;
        if let Err(status) = runtime.wsk.capture() {
            runtime.wsk.deregister();
            ffi::IoDeleteSymbolicLink(&symbolic_link);
            ptr::drop_in_place((*device).device_extension.cast::<DriverRuntime>());
            ffi::IoDeleteDevice(device);
            return status;
        }
    }
    #[cfg(not(ssp_wdk_native))]
    let _ = runtime.wsk.capture();

    (*device).flags |= ffi::DO_BUFFERED_IO;
    (*driver).driver_unload = Some(driver_unload);
    (*driver).major_function[ffi::IRP_MJ_CREATE] = Some(dispatch_create);
    (*driver).major_function[ffi::IRP_MJ_CLOSE] = Some(dispatch_close);
    (*driver).major_function[ffi::IRP_MJ_CLEANUP] = Some(dispatch_cleanup);
    (*driver).major_function[ffi::IRP_MJ_DEVICE_CONTROL] = Some(dispatch_device_control);
    ffi::STATUS_SUCCESS
}

/// Handles secure opens after `IoCreateDeviceSecure`.
pub unsafe extern "system" fn dispatch_create(
    _device: *mut ffi::DeviceObject,
    irp: *mut ffi::Irp,
) -> ffi::NtStatus {
    complete_irp(irp, ffi::STATUS_SUCCESS, 0)
}

/// Handles close IRPs.
pub unsafe extern "system" fn dispatch_close(
    _device: *mut ffi::DeviceObject,
    irp: *mut ffi::Irp,
) -> ffi::NtStatus {
    complete_irp(irp, ffi::STATUS_SUCCESS, 0)
}

/// Handles cleanup IRPs.
pub unsafe extern "system" fn dispatch_cleanup(
    _device: *mut ffi::DeviceObject,
    irp: *mut ffi::Irp,
) -> ffi::NtStatus {
    complete_irp(irp, ffi::STATUS_SUCCESS, 0)
}

/// Validates the opaque tunnel IOCTL surface and applies driver-owned state
/// transitions for pending mapping requests and completions.
pub unsafe extern "system" fn dispatch_device_control(
    device: *mut ffi::DeviceObject,
    irp: *mut ffi::Irp,
) -> ffi::NtStatus {
    let (code, input_length, output_length) = match current_io_control(irp) {
        Ok(values) => values,
        Err(status) => return complete_irp(irp, status, 0),
    };

    #[cfg(ssp_wdk_native)]
    {
        let runtime = runtime(device);
        if let Ok(mut dataplane) = runtime.native_dataplane(device) {
            let _ = runtime.drain_callback_events(&mut dataplane, 0, MAX_CALLBACK_EVENTS);
        }
    }

    match code {
        IOCTL_SSP_DEQUEUE_REQUEST => {
            let buffer = system_buffer_mut(irp, output_length);
            match runtime(device).dequeue_pending_frame(buffer.len()) {
                Ok(Some(frame)) => {
                    buffer[..frame.len()].copy_from_slice(&frame);
                    complete_irp(irp, ffi::STATUS_SUCCESS, frame.len())
                }
                Ok(None) => complete_irp(irp, ffi::STATUS_SUCCESS, 0),
                Err(crate::KernelRelayError::PayloadTooLarge { .. }) => {
                    complete_irp(irp, ffi::STATUS_BUFFER_TOO_SMALL, 0)
                }
                Err(_) => complete_irp(irp, ffi::STATUS_INVALID_PARAMETER, 0),
            }
        }
        IOCTL_SSP_COMPLETE_RESPONSE => {
            let input = system_buffer(irp, input_length);
            if input.len() < crate::device::TUNNEL_HEADER_LEN {
                return complete_irp(irp, ffi::STATUS_BUFFER_TOO_SMALL, 0);
            }
            let response = match TunnelResponse::decode(input) {
                Ok(response) => response,
                Err(_) => return complete_irp(irp, ffi::STATUS_INVALID_PARAMETER, 0),
            };
            let runtime = runtime(device);
            #[cfg(ssp_wdk_native)]
            let result = match runtime.native_dataplane(device) {
                Ok(mut dataplane) => runtime.apply_tunnel_response(&mut dataplane, response, 0),
                Err(error) => Err(error),
            };
            #[cfg(not(ssp_wdk_native))]
            let result = {
                let mut next_handle = runtime.synthetic_sockets.lock_exclusive();
                let mut dataplane = SyntheticDataplane {
                    next_handle: &mut *next_handle,
                };
                runtime.apply_tunnel_response(&mut dataplane, response, 0)
            };
            match result {
                Ok(()) => complete_irp(irp, ffi::STATUS_SUCCESS, 0),
                Err(crate::KernelRelayError::FlowNotFound { .. })
                | Err(crate::KernelRelayError::RequestNotFound { .. })
                | Err(crate::KernelRelayError::InvalidState(_)) => {
                    complete_irp(irp, ffi::STATUS_INVALID_PARAMETER, 0)
                }
                Err(_) => complete_irp(irp, ffi::STATUS_NOT_SUPPORTED, 0),
            }
        }
        IOCTL_SSP_CANCEL_REQUEST => {
            let input = system_buffer(irp, input_length);
            let cancel = match CancelTunnelRequest::decode(input) {
                Ok(cancel) => cancel,
                Err(_) => return complete_irp(irp, ffi::STATUS_INVALID_PARAMETER, 0),
            };
            let runtime = runtime(device);
            #[cfg(ssp_wdk_native)]
            let result = match runtime.native_dataplane(device) {
                Ok(mut dataplane) => runtime.cancel_pending_request(&mut dataplane, cancel),
                Err(error) => Err(error),
            };
            #[cfg(not(ssp_wdk_native))]
            let result = {
                let mut next_handle = runtime.synthetic_sockets.lock_exclusive();
                let mut dataplane = SyntheticDataplane {
                    next_handle: &mut *next_handle,
                };
                runtime.cancel_pending_request(&mut dataplane, cancel)
            };
            match result {
                Ok(_) => complete_irp(irp, ffi::STATUS_SUCCESS, 0),
                Err(_) => complete_irp(irp, ffi::STATUS_INVALID_PARAMETER, 0),
            }
        }
        IOCTL_SSP_REPORT_TRANSPORT => {
            let input = system_buffer(irp, input_length);
            let report = match TransportStatusReport::decode(input) {
                Ok(report) => report,
                Err(_) => return complete_irp(irp, ffi::STATUS_INVALID_PARAMETER, 0),
            };
            let runtime = runtime(device);
            #[cfg(ssp_wdk_native)]
            let result = match runtime.native_dataplane(device) {
                Ok(mut dataplane) => runtime.update_transport_state(&mut dataplane, report),
                Err(error) => Err(error),
            };
            #[cfg(not(ssp_wdk_native))]
            let result = {
                let mut next_handle = runtime.synthetic_sockets.lock_exclusive();
                let mut dataplane = SyntheticDataplane {
                    next_handle: &mut *next_handle,
                };
                runtime.update_transport_state(&mut dataplane, report)
            };
            match result {
                Ok(()) => complete_irp(irp, ffi::STATUS_SUCCESS, 0),
                Err(_) => complete_irp(irp, ffi::STATUS_INVALID_PARAMETER, 0),
            }
        }
        _ => complete_irp(irp, ffi::STATUS_INVALID_DEVICE_REQUEST, 0),
    }
}

/// Releases listeners, WSK registration, and the secure device object.
pub unsafe extern "system" fn driver_unload(driver: *mut ffi::DriverObject) {
    let symbolic_link = wide_null(SYMBOLIC_LINK_NAME);
    let symbolic_link = init_unicode(&symbolic_link);
    let device = (*driver).device_object;
    if !device.is_null() {
        let runtime = runtime(device);
        #[cfg(ssp_wdk_native)]
        {
            if let Ok(mut dataplane) = runtime.native_dataplane(device) {
                let _ = runtime.listeners.lock_exclusive().close_all(&mut dataplane);
            }
        }
        #[cfg(not(ssp_wdk_native))]
        {
            let mut next_handle = runtime.synthetic_sockets.lock_exclusive();
            let mut dataplane = SyntheticDataplane {
                next_handle: &mut *next_handle,
            };
            let _ = runtime.listeners.lock_exclusive().close_all(&mut dataplane);
        }
        runtime.wsk.deregister();
        ptr::drop_in_place((*device).device_extension.cast::<DriverRuntime>());
        ffi::IoDeleteDevice(device);
    }
    let _ = ffi::IoDeleteSymbolicLink(&symbolic_link);
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        net::{Ipv4Addr, SocketAddr},
    };

    use prost::Message;

    use super::*;
    use crate::proto;

    #[derive(Default)]
    struct MockWsk {
        ops: RefCell<Vec<String>>,
        stream_payloads: RefCell<Vec<(WskSocketHandle, Vec<u8>)>>,
        datagram_payloads: RefCell<Vec<(WskSocketHandle, SocketAddr, Vec<u8>)>>,
        next_socket: usize,
    }

    impl WskDataplane for MockWsk {
        fn create_listener_socket(
            &mut self,
            family: u16,
            protocol: FlowProtocol,
            _callbacks: ListenerCallbacks,
        ) -> Result<WskSocketHandle, crate::KernelRelayError> {
            self.next_socket += 1;
            self.ops
                .borrow_mut()
                .push(format!("listener-{family}-{protocol:?}"));
            Ok(WskSocketHandle(self.next_socket))
        }

        fn bind_listener(
            &mut self,
            socket: WskSocketHandle,
            local: SocketAddr,
        ) -> Result<(), crate::KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("bind-{}-{local}", socket.0));
            Ok(())
        }

        fn listen(
            &mut self,
            socket: WskSocketHandle,
            backlog: u32,
        ) -> Result<(), crate::KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("listen-{}-{backlog}", socket.0));
            Ok(())
        }

        fn create_outbound_socket(
            &mut self,
            family: u16,
            protocol: FlowProtocol,
        ) -> Result<WskSocketHandle, crate::KernelRelayError> {
            self.next_socket += 1;
            self.ops
                .borrow_mut()
                .push(format!("outbound-{family}-{protocol:?}"));
            Ok(WskSocketHandle(self.next_socket))
        }

        fn connect(
            &mut self,
            socket: WskSocketHandle,
            remote: SocketAddr,
        ) -> Result<(), crate::KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("connect-{}-{remote}", socket.0));
            Ok(())
        }

        fn send_stream(
            &mut self,
            socket: WskSocketHandle,
            bytes: usize,
        ) -> Result<(), crate::KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("send-{}-{bytes}", socket.0));
            Ok(())
        }

        fn send_stream_bytes(
            &mut self,
            socket: WskSocketHandle,
            bytes: &[u8],
        ) -> Result<usize, crate::KernelRelayError> {
            self.stream_payloads
                .borrow_mut()
                .push((socket, bytes.to_vec()));
            Ok(bytes.len())
        }

        fn recv_stream(
            &mut self,
            socket: WskSocketHandle,
            bytes: usize,
        ) -> Result<(), crate::KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("recv-{}-{bytes}", socket.0));
            Ok(())
        }

        fn shutdown_stream_send(
            &mut self,
            socket: WskSocketHandle,
        ) -> Result<(), crate::KernelRelayError> {
            self.ops.borrow_mut().push(format!("shutdown-{}", socket.0));
            Ok(())
        }

        fn send_datagram(
            &mut self,
            socket: WskSocketHandle,
            bytes: usize,
        ) -> Result<(), crate::KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("send-dgram-{}-{bytes}", socket.0));
            Ok(())
        }

        fn send_datagram_bytes(
            &mut self,
            socket: WskSocketHandle,
            bytes: &[u8],
            remote: SocketAddr,
        ) -> Result<usize, crate::KernelRelayError> {
            self.datagram_payloads
                .borrow_mut()
                .push((socket, remote, bytes.to_vec()));
            Ok(bytes.len())
        }

        fn close_socket(&mut self, socket: WskSocketHandle) -> Result<(), crate::KernelRelayError> {
            self.ops.borrow_mut().push(format!("close-{}", socket.0));
            Ok(())
        }
    }

    fn tcp_tuple(port: u16) -> SocketTuple {
        SocketTuple {
            source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 7), port)),
            destination: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 44), 443)),
            protocol: FlowProtocol::Tcp,
        }
    }

    fn udp_tuple(port: u16) -> SocketTuple {
        SocketTuple {
            source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 8), port)),
            destination: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 45), 53)),
            protocol: FlowProtocol::Udp,
        }
    }

    fn mapping_reply(tuple: &SocketTuple, request_id: u64) -> TunnelResponse {
        TunnelResponse {
            request_id,
            generation: 1,
            epoch: 1,
            status: crate::TunnelResponseStatus::Ok,
            payload: proto::Mapping {
                synthetic: Some(proto::Tuple {
                    family: 4,
                    source_address: vec![10, 0, 0, 7],
                    destination_address: vec![192, 0, 2, 44],
                    protocol: 6,
                    source_port: tuple.source.port() as u32,
                    destination_port: 443,
                }),
                original: Some(proto::Tuple {
                    family: 4,
                    source_address: vec![10, 1, 1, 1],
                    destination_address: vec![203, 0, 113, 9],
                    protocol: 6,
                    source_port: 50000,
                    destination_port: 8443,
                }),
                last_seen_ns: 0,
                protocol_flags: 0,
                tcp_state_flags: 0,
            }
            .encode_to_vec(),
        }
    }

    fn udp_mapping_reply(tuple: &SocketTuple, request_id: u64) -> TunnelResponse {
        TunnelResponse {
            request_id,
            generation: 1,
            epoch: 1,
            status: crate::TunnelResponseStatus::Ok,
            payload: proto::Mapping {
                synthetic: Some(proto::Tuple {
                    family: 4,
                    source_address: vec![10, 0, 0, 8],
                    destination_address: vec![192, 0, 2, 45],
                    protocol: 17,
                    source_port: tuple.source.port() as u32,
                    destination_port: 53,
                }),
                original: Some(proto::Tuple {
                    family: 4,
                    source_address: vec![10, 2, 2, 2],
                    destination_address: vec![203, 0, 113, 10],
                    protocol: 17,
                    source_port: 55000,
                    destination_port: 5353,
                }),
                last_seen_ns: 0,
                protocol_flags: 0,
                tcp_state_flags: 0,
            }
            .encode_to_vec(),
        }
    }

    #[test]
    fn accepted_tcp_flow_enqueues_a_real_mapping_request_frame() {
        let runtime = DriverRuntime::default();
        let flow = runtime
            .on_tcp_accept(WskSocketHandle(900), tcp_tuple(40100))
            .expect("admission should succeed");
        let frame = runtime
            .dequeue_pending_frame(4096)
            .expect("dequeue should succeed")
            .expect("frame should exist");
        let request = crate::TunnelRequest::decode(&frame).expect("request should decode");
        assert_eq!(flow.flow_id, 1);
        assert_eq!(request.request_id, 1);
        assert_eq!(request.generation, 1);
    }

    #[test]
    fn completion_connects_and_publishes_tcp_relay_ownership() {
        let runtime = DriverRuntime::default();
        let flow = runtime
            .on_tcp_accept(WskSocketHandle(501), tcp_tuple(40101))
            .expect("admission should succeed");
        let _ = runtime
            .dequeue_pending_frame(4096)
            .expect("dequeue should succeed");
        let mut wsk = MockWsk::default();
        runtime
            .apply_tunnel_response(&mut wsk, mapping_reply(&tcp_tuple(40101), 1), 10)
            .expect("completion should succeed");
        assert_eq!(runtime.flow_state(flow), Some(FlowState::MappedTcp));
        assert_eq!(runtime.active_tcp_relay_count(), 1);
        assert_eq!(
            wsk.ops.borrow().as_slice(),
            &[
                "outbound-2-Tcp".to_string(),
                format!(
                    "connect-1-{}",
                    SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 8443))
                ),
            ]
        );
    }

    #[test]
    fn transport_disconnect_clears_only_unresolved_queued_requests() {
        let runtime = DriverRuntime::default();
        let unresolved = runtime
            .on_tcp_accept(WskSocketHandle(601), tcp_tuple(40102))
            .expect("admission should succeed");
        let mapped = runtime
            .on_tcp_accept(WskSocketHandle(602), tcp_tuple(40103))
            .expect("admission should succeed");
        let _first = runtime
            .dequeue_pending_frame(4096)
            .expect("dequeue should succeed");
        let second = runtime
            .dequeue_pending_frame(4096)
            .expect("dequeue should succeed")
            .expect("second frame should exist");
        let second_request =
            crate::TunnelRequest::decode(&second).expect("second request should decode");
        let mut wsk = MockWsk::default();
        runtime
            .apply_tunnel_response(
                &mut wsk,
                mapping_reply(&tcp_tuple(40103), second_request.request_id),
                10,
            )
            .expect("completion should succeed");

        runtime
            .update_transport_state(
                &mut wsk,
                TransportStatusReport {
                    state: TransportChannelState::Disconnected,
                    epoch: 2,
                },
            )
            .expect("disconnect handling should succeed");

        assert_eq!(runtime.flow_state(unresolved), None);
        assert_eq!(runtime.flow_state(mapped), Some(FlowState::MappedTcp));
    }

    #[test]
    fn cancellation_closes_only_the_matching_unresolved_flow() {
        let runtime = DriverRuntime::default();
        runtime
            .on_tcp_accept(WskSocketHandle(701), tcp_tuple(40104))
            .expect("admission should succeed");
        let survivor = runtime
            .on_tcp_accept(WskSocketHandle(702), tcp_tuple(40105))
            .expect("admission should succeed");
        let _ = runtime
            .dequeue_pending_frame(4096)
            .expect("dequeue should succeed");
        let mut wsk = MockWsk::default();
        assert!(runtime
            .cancel_pending_request(
                &mut wsk,
                CancelTunnelRequest {
                    request_id: 1,
                    generation: 1,
                    epoch: 1,
                },
            )
            .expect("cancellation should succeed"));
        assert_eq!(
            runtime.flow_state(survivor),
            Some(FlowState::ResolvingMapping)
        );
        assert!(wsk.ops.borrow().iter().any(|entry| entry == "close-701"));
    }

    #[test]
    fn half_close_drains_then_releases_tcp_flow() {
        let runtime = DriverRuntime::default();
        let flow = runtime
            .on_tcp_accept(WskSocketHandle(801), tcp_tuple(40106))
            .expect("admission should succeed");
        let _ = runtime
            .dequeue_pending_frame(4096)
            .expect("dequeue should succeed");
        let mut wsk = MockWsk::default();
        runtime
            .apply_tunnel_response(&mut wsk, mapping_reply(&tcp_tuple(40106), 1), 10)
            .expect("completion should succeed");
        assert_eq!(
            runtime
                .on_tcp_half_close(&mut wsk, flow, RelayDirection::ClientToOrigin)
                .expect("first half close should succeed"),
            FlowState::MappedTcp
        );
        assert_eq!(
            runtime
                .on_tcp_half_close(&mut wsk, flow, RelayDirection::OriginToClient)
                .expect("second half close should succeed"),
            FlowState::Released
        );
        assert_eq!(runtime.active_tcp_relay_count(), 0);
        assert!(wsk.ops.borrow().iter().any(|entry| entry == "close-801"));
    }

    #[test]
    fn udp_completion_creates_association_and_idle_expiry_releases_it() {
        let runtime = DriverRuntime::default();
        let flow = runtime
            .on_udp_datagram(udp_tuple(40107))
            .expect("udp admission should succeed");
        let frame = runtime
            .dequeue_pending_frame(4096)
            .expect("dequeue should succeed")
            .expect("frame should exist");
        let request = crate::TunnelRequest::decode(&frame).expect("request should decode");
        let mut wsk = MockWsk::default();
        runtime
            .apply_tunnel_response(
                &mut wsk,
                udp_mapping_reply(&udp_tuple(40107), request.request_id),
                20,
            )
            .expect("udp completion should succeed");
        assert_eq!(runtime.flow_state(flow), Some(FlowState::MappedUdp));
        assert_eq!(runtime.active_udp_association_count(), 1);
        runtime
            .send_udp_reply(&mut wsk, flow, 32, 30)
            .expect("udp send should succeed");
        assert_eq!(
            runtime
                .expire_udp_associations(&mut wsk, 60_000_000_100)
                .expect("expiry should succeed"),
            1
        );
        assert_eq!(runtime.flow_state(flow), None);
        assert_eq!(runtime.active_udp_association_count(), 0);
    }

    #[test]
    fn mapped_tcp_payload_is_forwarded_without_length_only_substitution() {
        let runtime = DriverRuntime::default();
        let inbound = WskSocketHandle(910);
        let tuple = tcp_tuple(40108);
        let flow = runtime
            .on_tcp_accept(inbound, tuple.clone())
            .expect("admission should succeed");
        let _ = runtime
            .dequeue_pending_frame(4096)
            .expect("request should dequeue");
        let mut wsk = MockWsk::default();
        runtime
            .apply_tunnel_response(&mut wsk, mapping_reply(&tuple, 1), 10)
            .expect("mapping should apply");

        assert_eq!(
            runtime
                .on_tcp_payload(&mut wsk, inbound, b"tcp-payload", 20)
                .expect("payload should forward"),
            b"tcp-payload".len()
        );
        assert_eq!(
            wsk.stream_payloads.borrow().as_slice(),
            &[(WskSocketHandle(1), b"tcp-payload".to_vec())]
        );
        assert_eq!(runtime.flow_state(flow), Some(FlowState::MappedTcp));
    }

    #[test]
    fn unresolved_tcp_payload_closes_only_the_affected_flow() {
        let runtime = DriverRuntime::default();
        let first = runtime
            .on_tcp_accept(WskSocketHandle(911), tcp_tuple(40109))
            .expect("first admission should succeed");
        let survivor = runtime
            .on_tcp_accept(WskSocketHandle(912), tcp_tuple(40110))
            .expect("second admission should succeed");
        let mut wsk = MockWsk::default();

        let error = runtime
            .on_tcp_payload(&mut wsk, WskSocketHandle(911), b"early", 0)
            .expect_err("unresolved payload must fail");
        assert!(matches!(error, crate::KernelRelayError::InvalidState(_)));
        assert_eq!(runtime.flow_state(first), None);
        assert_eq!(
            runtime.flow_state(survivor),
            Some(FlowState::ResolvingMapping)
        );
        assert!(wsk.ops.borrow().iter().any(|entry| entry == "close-911"));
        assert!(!wsk.ops.borrow().iter().any(|entry| entry == "close-912"));
    }

    #[test]
    fn udp_payload_and_reply_use_one_exact_association() {
        let runtime = DriverRuntime::default();
        let tuple = udp_tuple(40111);
        let inbound = WskSocketHandle(913);
        let first_payload = b"first-datagram";
        let _ = runtime
            .on_udp_datagram_payload(
                &mut MockWsk::default(),
                inbound,
                tuple.clone(),
                first_payload,
                1,
            )
            .expect("UDP admission should succeed");
        let flow = FlowIdentity {
            flow_id: 1,
            generation: 1,
        };
        let frame = runtime
            .dequeue_pending_frame(4096)
            .expect("request should dequeue")
            .expect("request should exist");
        let request = crate::TunnelRequest::decode(&frame).expect("request should decode");
        let mut wsk = MockWsk::default();
        runtime
            .apply_tunnel_response(&mut wsk, udp_mapping_reply(&tuple, request.request_id), 2)
            .expect("UDP mapping should apply");

        assert_eq!(
            wsk.datagram_payloads.borrow().as_slice(),
            &[(
                WskSocketHandle(1),
                SocketAddr::from(([203, 0, 113, 10], 5353)),
                first_payload.to_vec()
            )]
        );
        runtime
            .on_udp_reply(&mut wsk, flow, b"reply", 3)
            .expect("UDP reply should forward");
        assert_eq!(
            wsk.datagram_payloads.borrow().as_slice(),
            &[
                (
                    WskSocketHandle(1),
                    SocketAddr::from(([203, 0, 113, 10], 5353)),
                    first_payload.to_vec()
                ),
                (
                    inbound,
                    SocketAddr::from(([10, 0, 0, 8], 40111)),
                    b"reply".to_vec()
                )
            ]
        );
    }

    #[test]
    fn tcp_payload_bound_rejects_without_forwarding() {
        let runtime = DriverRuntime::new(NativeRuntimeConfig {
            relay_buffer_bytes: 3,
            ..NativeRuntimeConfig::default()
        });
        let tuple = tcp_tuple(40112);
        let inbound = WskSocketHandle(914);
        runtime
            .on_tcp_accept(inbound, tuple.clone())
            .expect("admission should succeed");
        let _ = runtime
            .dequeue_pending_frame(4096)
            .expect("request should dequeue");
        let mut wsk = MockWsk::default();
        runtime
            .apply_tunnel_response(&mut wsk, mapping_reply(&tuple, 1), 1)
            .expect("mapping should apply");

        assert!(matches!(
            runtime.on_tcp_payload(&mut wsk, inbound, b"four", 2),
            Err(crate::KernelRelayError::PayloadTooLarge { .. })
        ));
        assert!(wsk.stream_payloads.borrow().is_empty());
    }

    #[test]
    fn runtime_callback_table_defers_payload_work_until_passive_drain() {
        let runtime = DriverRuntime::default();
        let callbacks = runtime.callback_table();
        unsafe {
            (callbacks.on_accept.expect("accept callback"))(
                callbacks.context,
                WskSocketHandle(915),
                tcp_tuple(40113),
            )
            .expect("callback admission should enqueue");
            (callbacks.on_stream.expect("stream callback"))(
                callbacks.context,
                WskSocketHandle(915),
                b"queued",
            )
            .expect("callback payload should enqueue");
        }
        let mut wsk = MockWsk::default();
        assert_eq!(
            runtime
                .drain_callback_events(&mut wsk, 1, 1)
                .expect("accept should drain"),
            1
        );
        assert_eq!(runtime.queued_request_count(), 1);
        assert_eq!(
            runtime
                .drain_callback_events(&mut wsk, 1, 1)
                .expect_err("unresolved TCP payload should fail the flow"),
            crate::KernelRelayError::InvalidState("TCP payload arrived before mapping".into())
        );
        assert!(wsk.ops.borrow().iter().any(|entry| entry == "close-915"));
    }
}
