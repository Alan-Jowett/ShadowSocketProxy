// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! WSK registration, listener setup, callback ownership, and relay-operation
//! seams.

use core::mem::MaybeUninit;
use std::net::SocketAddr;

use crate::{
    error::KernelRelayError,
    tuple::{FlowProtocol, SocketTuple},
};

use super::ffi;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Opaque handle used by host-independent tests and the native socket record.
pub struct WskSocketHandle(pub usize);

#[derive(Debug, Clone, Copy)]
/// Listener callbacks wired into WSK accept and datagram events.
pub struct ListenerCallbacks {
    /// Opaque context returned by the driver runtime.
    pub context: usize,
    /// Called for accepted TCP sockets.
    pub on_accept:
        Option<unsafe fn(usize, WskSocketHandle, SocketTuple) -> Result<(), KernelRelayError>>,
    /// Called for bounded TCP receive indications.
    pub on_stream: Option<unsafe fn(usize, WskSocketHandle, &[u8]) -> Result<(), KernelRelayError>>,
    /// Called for UDP datagrams.
    pub on_datagram: Option<
        unsafe fn(usize, WskSocketHandle, SocketTuple, &[u8]) -> Result<(), KernelRelayError>,
    >,
    /// Called when a listener or relay socket disconnects or is torn down.
    pub on_disconnect: Option<unsafe fn(usize, WskSocketHandle) -> Result<(), KernelRelayError>>,
    /// Called after an asynchronous native payload send completes with an
    /// error.
    pub on_send_failure: Option<unsafe fn(usize, WskSocketHandle, ffi::NtStatus)>,
}

impl Default for ListenerCallbacks {
    fn default() -> Self {
        Self {
            context: 0,
            on_accept: None,
            on_stream: None,
            on_datagram: None,
            on_disconnect: None,
            on_send_failure: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Immutable listener configuration validated before WSK setup.
pub struct ListenerBinding {
    /// Address family (AF_INET or AF_INET6).
    pub family: u16,
    /// Bound local socket address.
    pub local: SocketAddr,
    /// Transport protocol served by this listener.
    pub protocol: FlowProtocol,
    /// Native listen backlog for TCP listeners.
    pub backlog: u32,
}

/// Host-independent wrapper for the WSK socket operations needed by the
/// kernel-relay runtime.
pub trait WskDataplane {
    /// Creates one inbound listener socket.
    fn create_listener_socket(
        &mut self,
        family: u16,
        protocol: FlowProtocol,
        callbacks: ListenerCallbacks,
    ) -> Result<WskSocketHandle, KernelRelayError>;

    /// Binds one inbound socket to a local address.
    fn bind_listener(
        &mut self,
        socket: WskSocketHandle,
        local: SocketAddr,
    ) -> Result<(), KernelRelayError>;

    /// Starts listening on a TCP listener socket.
    fn listen(&mut self, socket: WskSocketHandle, backlog: u32) -> Result<(), KernelRelayError>;

    /// Creates one outbound relay socket.
    fn create_outbound_socket(
        &mut self,
        family: u16,
        protocol: FlowProtocol,
    ) -> Result<WskSocketHandle, KernelRelayError>;

    /// Connects one outbound relay socket.
    fn connect(
        &mut self,
        socket: WskSocketHandle,
        remote: SocketAddr,
    ) -> Result<(), KernelRelayError>;

    /// Installs callbacks on an outbound socket.
    ///
    /// Host-independent implementations may ignore this seam. Native WSK
    /// sockets use it to route origin-side payloads back through the runtime.
    fn set_socket_callbacks(
        &mut self,
        _socket: WskSocketHandle,
        _callbacks: ListenerCallbacks,
    ) -> Result<(), KernelRelayError> {
        Ok(())
    }

    /// Sends one bounded TCP relay buffer.
    fn send_stream(
        &mut self,
        socket: WskSocketHandle,
        bytes: usize,
    ) -> Result<(), KernelRelayError>;

    /// Sends caller-owned bounded TCP bytes.
    ///
    /// The length-only operation remains for the host-independent state
    /// machine. Implementations must override this method to accept payload
    /// bytes; the default rejects rather than manufacturing a success.
    fn send_stream_bytes(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: &[u8],
    ) -> Result<usize, KernelRelayError> {
        Err(KernelRelayError::InvalidState(
            "caller-owned stream payload operation is unavailable".into(),
        ))
    }

    /// Receives one bounded TCP relay buffer.
    fn recv_stream(
        &mut self,
        socket: WskSocketHandle,
        bytes: usize,
    ) -> Result<(), KernelRelayError>;

    /// Receives bounded TCP bytes into caller-owned storage.
    fn recv_stream_into(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: &mut [u8],
    ) -> Result<usize, KernelRelayError> {
        Err(KernelRelayError::InvalidState(
            "caller-owned stream receive operation is unavailable".into(),
        ))
    }

    /// Shuts down the TCP send path after half-close.
    fn shutdown_stream_send(&mut self, socket: WskSocketHandle) -> Result<(), KernelRelayError>;

    /// Sends one bounded UDP datagram.
    fn send_datagram(
        &mut self,
        socket: WskSocketHandle,
        bytes: usize,
    ) -> Result<(), KernelRelayError>;

    /// Sends one caller-owned bounded UDP datagram to its peer.
    fn send_datagram_bytes(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: &[u8],
        _remote: SocketAddr,
    ) -> Result<usize, KernelRelayError> {
        Err(KernelRelayError::InvalidState(
            "caller-owned datagram payload operation is unavailable".into(),
        ))
    }

    /// Closes one listener or relay socket.
    fn close_socket(&mut self, socket: WskSocketHandle) -> Result<(), KernelRelayError>;
}

#[derive(Debug)]
/// Registered WSK client/provider pairing.
pub struct WskProvider {
    registration: ffi::WskRegistration,
    client_dispatch: ffi::WskClientDispatch,
    client_npi: ffi::WskClientNpi,
    provider_npi: MaybeUninit<ffi::WskProviderNpi>,
    registered: bool,
    captured: bool,
}

impl WskProvider {
    /// Creates the WSK registration state for the driver.
    pub fn new() -> Self {
        #[cfg(ssp_wdk_native)]
        let client_dispatch = ffi::WskClientDispatch {
            Version: 0x0100,
            Reserved: 0,
            WskClientEvent: None,
        };
        #[cfg(not(ssp_wdk_native))]
        let client_dispatch = ffi::WskClientDispatch {
            version: 1,
            reserved: 0,
            wsk_client_event: None,
        };
        Self {
            registration: unsafe { core::mem::zeroed() },
            client_dispatch,
            #[cfg(ssp_wdk_native)]
            client_npi: ffi::WskClientNpi {
                ClientContext: core::ptr::null_mut(),
                Dispatch: core::ptr::null_mut(),
            },
            #[cfg(not(ssp_wdk_native))]
            client_npi: ffi::WskClientNpi {
                client_context: core::ptr::null_mut(),
                dispatch: core::ptr::null(),
            },
            provider_npi: MaybeUninit::uninit(),
            registered: false,
            captured: false,
        }
    }

    /// Registers the driver as a WSK client.
    pub unsafe fn register(&mut self) -> Result<(), ffi::NtStatus> {
        #[cfg(ssp_wdk_native)]
        {
            self.client_npi.Dispatch = &self.client_dispatch;
        }
        #[cfg(not(ssp_wdk_native))]
        {
            self.client_npi.dispatch = &self.client_dispatch;
        }
        let status = ffi::WskRegister(&mut self.client_npi, &mut self.registration);
        if ffi::nt_success(status) {
            self.registered = true;
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Captures the provider NPI so listeners and relay sockets can be opened.
    pub unsafe fn capture(&mut self) -> Result<&ffi::WskProviderNpi, ffi::NtStatus> {
        let status = ffi::WskCaptureProviderNPI(
            &mut self.registration,
            ffi::WSK_INFINITE_WAIT,
            self.provider_npi.as_mut_ptr(),
        );
        if ffi::nt_success(status) {
            self.captured = true;
            Ok(self.provider_npi.assume_init_ref())
        } else {
            Err(status)
        }
    }

    /// Creates the native dataplane view over the captured provider NPI.
    #[cfg(ssp_wdk_native)]
    pub unsafe fn dataplane(
        &self,
        device: *mut ffi::DeviceObject,
    ) -> Result<NativeWskDataplane<'_>, KernelRelayError> {
        if !self.captured {
            return Err(KernelRelayError::InvalidState(
                "WSK provider must be captured before creating its dataplane".into(),
            ));
        }
        Ok(NativeWskDataplane::new(
            self.provider_npi.assume_init_ref(),
            device,
        ))
    }

    /// Releases the captured provider NPI.
    pub unsafe fn release(&mut self) {
        if self.captured {
            ffi::WskReleaseProviderNPI(&mut self.registration);
            self.captured = false;
        }
    }

    /// Deregisters the driver from WSK.
    pub unsafe fn deregister(&mut self) {
        self.release();
        if self.registered {
            ffi::WskDeregister(&mut self.registration);
            self.registered = false;
        }
    }
}

impl Default for WskProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(ssp_wdk_native)]
const MAX_NATIVE_OPERATION_BYTES: usize = 64 * 1024;
#[cfg(ssp_wdk_native)]
const NATIVE_POOL_TAG: u32 = u32::from_ne_bytes(*b"SspW");
#[cfg(ssp_wdk_native)]
const SO_WSK_EVENT_CALLBACK: u32 = 0x4002;
#[cfg(ssp_wdk_native)]
const SOL_SOCKET: u32 = 0xffff;
#[cfg(ssp_wdk_native)]
const NATIVE_IRP_TIMEOUT_100NS: i64 = -5 * 10_000_000;

#[cfg(ssp_wdk_native)]
use core::{
    ffi::c_void,
    mem,
    ptr::{self, null_mut},
    slice,
};
#[cfg(ssp_wdk_native)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(ssp_wdk_native)]
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePool, IoAllocateIrp, IoAllocateMdl, IoCancelIrp, IoFreeIrp,
        IoFreeMdl, IoSetCompletionRoutineEx, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
        MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache, MmUnmapLockedPages,
    },
    KEVENT, LARGE_INTEGER, PDEVICE_OBJECT, PIRP, PMDL, POOL_FLAG_NON_PAGED, PVOID,
};

#[cfg(ssp_wdk_native)]
#[repr(C)]
struct NativeSocketRecord {
    magic: u32,
    socket: crate::wsk_bindings::PWSK_SOCKET,
    provider: *const ffi::WskProviderNpi,
    device: PDEVICE_OBJECT,
    family: u16,
    protocol: FlowProtocol,
    callbacks: ListenerCallbacks,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    bound: bool,
    listener: bool,
}

#[cfg(ssp_wdk_native)]
const NATIVE_SOCKET_MAGIC: u32 = 0x5353_5057;

#[cfg(ssp_wdk_native)]
static NATIVE_LISTEN_DISPATCH: crate::wsk_bindings::WSK_CLIENT_LISTEN_DISPATCH =
    crate::wsk_bindings::WSK_CLIENT_LISTEN_DISPATCH {
        WskAcceptEvent: Some(native_accept_event),
        WskInspectEvent: None,
        WskAbortEvent: None,
    };

#[cfg(ssp_wdk_native)]
static NATIVE_DATAGRAM_DISPATCH: crate::wsk_bindings::WSK_CLIENT_DATAGRAM_DISPATCH =
    crate::wsk_bindings::WSK_CLIENT_DATAGRAM_DISPATCH {
        WskReceiveFromEvent: Some(native_receive_from_event),
    };

#[cfg(ssp_wdk_native)]
static NATIVE_CONNECTION_DISPATCH: crate::wsk_bindings::WSK_CLIENT_CONNECTION_DISPATCH =
    crate::wsk_bindings::WSK_CLIENT_CONNECTION_DISPATCH {
        WskReceiveEvent: Some(native_receive_event),
        WskDisconnectEvent: Some(native_disconnect_event),
        WskSendBacklogEvent: None,
    };

#[cfg(ssp_wdk_native)]
#[derive(Debug)]
/// Native WSK dataplane backed by the captured provider NPI.
///
/// Socket handles are owned records rather than raw provider pointers. This
/// keeps callback context, the provider lifetime, and close-time ownership
/// together without exposing WSK ABI details to the host-independent runtime.
pub struct NativeWskDataplane<'a> {
    provider: &'a ffi::WskProviderNpi,
    device: PDEVICE_OBJECT,
}

#[cfg(ssp_wdk_native)]
impl<'a> NativeWskDataplane<'a> {
    unsafe fn new(provider: &'a ffi::WskProviderNpi, device: *mut ffi::DeviceObject) -> Self {
        Self {
            provider,
            device: device.cast(),
        }
    }

    /// Sends caller-owned stream bytes through a provider-owned WSK buffer.
    pub fn send_stream_buffer(
        &mut self,
        socket: WskSocketHandle,
        bytes: &[u8],
    ) -> Result<usize, KernelRelayError> {
        let record = self.record(socket)?;
        if record.protocol != FlowProtocol::Tcp {
            return Err(KernelRelayError::InvalidTuple(
                "stream send requires a TCP socket".into(),
            ));
        }
        let buffer = OwnedMdlBuffer::from_bytes(bytes)?;
        let dispatch = connection_dispatch(record)?;
        let send = unsafe { (*dispatch).WskSend }.ok_or_else(|| {
            native_error("WskSend dispatch is unavailable", ffi::STATUS_NOT_SUPPORTED)
        })?;
        submit_async_send(
            record.device,
            record.socket,
            buffer,
            None,
            record.callbacks,
            socket,
            |irp, buffer, _remote| unsafe { send(record.socket, buffer, 0, as_wsk_irp(irp)) },
        )?;
        Ok(bytes.len())
    }

    /// Receives bounded stream bytes into caller-owned storage.
    pub fn recv_stream_buffer(
        &mut self,
        socket: WskSocketHandle,
        bytes: &mut [u8],
    ) -> Result<usize, KernelRelayError> {
        if bytes.len() > MAX_NATIVE_OPERATION_BYTES {
            return Err(KernelRelayError::ResourceExhausted(
                "native WSK receive exceeded the configured byte bound",
            ));
        }
        let record = self.record(socket)?;
        if record.protocol != FlowProtocol::Tcp {
            return Err(KernelRelayError::InvalidTuple(
                "stream receive requires a TCP socket".into(),
            ));
        }
        let mut buffer = OwnedMdlBuffer::empty(bytes.len())?;
        let dispatch = connection_dispatch(record)?;
        let receive = unsafe { (*dispatch).WskReceive }.ok_or_else(|| {
            native_error(
                "WskReceive dispatch is unavailable",
                ffi::STATUS_NOT_SUPPORTED,
            )
        })?;
        let (status, information) = sync_wsk_call(record.device, |irp| unsafe {
            receive(record.socket, &mut buffer.wsk, 0, as_wsk_irp(irp))
        })?;
        if ffi::nt_success(status) {
            let count = information.min(bytes.len());
            unsafe {
                ptr::copy_nonoverlapping(buffer.allocation.cast::<u8>(), bytes.as_mut_ptr(), count);
            }
            buffer.free();
            Ok(count)
        } else {
            buffer.free();
            Err(native_error("WskReceive", status))
        }
    }

    /// Sends one UDP datagram to the supplied peer.
    pub fn send_datagram_buffer(
        &mut self,
        socket: WskSocketHandle,
        bytes: &[u8],
        remote: SocketAddr,
    ) -> Result<usize, KernelRelayError> {
        let record = self.record(socket)?;
        if !matches!(record.protocol, FlowProtocol::Udp | FlowProtocol::QuicUdp) {
            return Err(KernelRelayError::InvalidTuple(
                "datagram send requires a UDP socket".into(),
            ));
        }
        if remote.is_ipv4() != (record.family as u32 == crate::wsk_bindings::AF_INET) {
            return Err(KernelRelayError::InvalidTuple(
                "datagram peer family does not match the socket".into(),
            ));
        }
        let buffer = OwnedMdlBuffer::from_bytes(bytes)?;
        let address = NativeSockAddr::new(remote)?;
        let dispatch = datagram_dispatch(record)?;
        let send_to = unsafe { (*dispatch).WskSendTo }.ok_or_else(|| {
            native_error(
                "WskSendTo dispatch is unavailable",
                ffi::STATUS_NOT_SUPPORTED,
            )
        })?;
        submit_async_send(
            record.device,
            record.socket,
            buffer,
            Some(address),
            record.callbacks,
            socket,
            |irp, buffer, remote| unsafe {
                send_to(
                    record.socket,
                    buffer,
                    0,
                    remote.expect("datagram send requires a remote address"),
                    0,
                    null_mut(),
                    as_wsk_irp(irp),
                )
            },
        )?;
        Ok(bytes.len())
    }

    fn record(&self, handle: WskSocketHandle) -> Result<&mut NativeSocketRecord, KernelRelayError> {
        let record = handle.0 as *mut NativeSocketRecord;
        if record.is_null() {
            return Err(KernelRelayError::InvalidState(
                "native WSK handle is null".into(),
            ));
        }
        let record = unsafe { &mut *record };
        if record.magic != NATIVE_SOCKET_MAGIC {
            return Err(KernelRelayError::InvalidState(
                "native WSK handle is not owned by this adapter".into(),
            ));
        }
        Ok(record)
    }

    fn allocate_record(
        &self,
        family: u16,
        protocol: FlowProtocol,
        callbacks: ListenerCallbacks,
        listener: bool,
    ) -> Result<WskSocketHandle, KernelRelayError> {
        let allocation = unsafe {
            ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                mem::size_of::<NativeSocketRecord>() as u64,
                NATIVE_POOL_TAG,
            )
        };
        if allocation.is_null() {
            return Err(KernelRelayError::ResourceExhausted(
                "native WSK socket context allocation failed",
            ));
        }
        let record = allocation.cast::<NativeSocketRecord>();
        unsafe {
            record.write(NativeSocketRecord {
                magic: NATIVE_SOCKET_MAGIC,
                socket: null_mut(),
                provider: self.provider,
                device: self.device,
                family,
                protocol,
                callbacks,
                remote: None,
                local: None,
                bound: false,
                listener,
            });
        }
        Ok(WskSocketHandle(record as usize))
    }

    fn create_socket(
        &mut self,
        handle: WskSocketHandle,
        socket_type: u16,
        flags: u32,
        dispatch: *const c_void,
    ) -> Result<(), KernelRelayError> {
        let record = self.record(handle)?;
        let provider_dispatch = self.provider_dispatch()?;
        let create = unsafe { (*provider_dispatch).WskSocket }.ok_or_else(|| {
            native_error(
                "WskSocket dispatch is unavailable",
                ffi::STATUS_NOT_SUPPORTED,
            )
        })?;
        let (status, information) = sync_wsk_call(record.device, |irp| unsafe {
            create(
                self.provider.Client,
                record.family,
                socket_type,
                protocol_number(record.protocol),
                flags,
                (record as *mut NativeSocketRecord).cast(),
                dispatch,
                null_mut(),
                null_mut(),
                null_mut(),
                as_wsk_irp(irp),
            )
        })?;
        if !ffi::nt_success(status) || information == 0 {
            return Err(native_error("WskSocket", status));
        }
        record.socket = information as crate::wsk_bindings::PWSK_SOCKET;
        Ok(())
    }

    fn provider_dispatch(
        &self,
    ) -> Result<*const crate::wsk_bindings::WSK_PROVIDER_DISPATCH, KernelRelayError> {
        if self.provider.Dispatch.is_null() {
            Err(native_error(
                "WSK provider dispatch is null",
                ffi::STATUS_NOT_SUPPORTED,
            ))
        } else {
            Ok(self.provider.Dispatch)
        }
    }

    fn bind_record(
        &mut self,
        handle: WskSocketHandle,
        local: SocketAddr,
    ) -> Result<(), KernelRelayError> {
        let record = self.record(handle)?;
        if record.socket.is_null() {
            return Err(KernelRelayError::InvalidState(
                "cannot bind a WSK socket before creation".into(),
            ));
        }
        if local.is_ipv4() != (record.family as u32 == crate::wsk_bindings::AF_INET) {
            return Err(KernelRelayError::InvalidTuple(
                "WSK bind address family does not match the socket".into(),
            ));
        }
        let mut address = NativeSockAddr::new(local)?;
        let status = unsafe {
            if record.protocol == FlowProtocol::Tcp {
                let dispatch = listen_dispatch(record)?;
                let bind = (*dispatch).WskBind.ok_or_else(|| {
                    native_error("WskBind dispatch is unavailable", ffi::STATUS_NOT_SUPPORTED)
                })?;
                sync_wsk_call(record.device, |irp| {
                    bind(record.socket, address.as_mut_ptr(), 0, as_wsk_irp(irp))
                })?
            } else {
                let dispatch = datagram_dispatch(record)?;
                let bind = (*dispatch).WskBind.ok_or_else(|| {
                    native_error("WskBind dispatch is unavailable", ffi::STATUS_NOT_SUPPORTED)
                })?;
                sync_wsk_call(record.device, |irp| {
                    bind(record.socket, address.as_mut_ptr(), 0, as_wsk_irp(irp))
                })?
            }
        };
        if !ffi::nt_success(status.0) {
            return Err(native_error("WskBind", status.0));
        }
        record.bound = true;
        record.local = Some(local);
        Ok(())
    }

    fn set_socket_events(
        &self,
        record: &NativeSocketRecord,
        event_mask: u32,
    ) -> Result<(), KernelRelayError> {
        if event_mask == 0 || record.socket.is_null() {
            return Err(native_error(
                "invalid WSK event registration request",
                ffi::STATUS_INVALID_PARAMETER,
            ));
        }
        let dispatch = basic_dispatch(record)?;
        let control = unsafe { (*dispatch).WskControlSocket }.ok_or_else(|| {
            native_error(
                "WskControlSocket dispatch is unavailable",
                ffi::STATUS_NOT_SUPPORTED,
            )
        })?;
        let mut callbacks = crate::wsk_bindings::WSK_EVENT_CALLBACK_CONTROL {
            NpiId: ptr::addr_of!(crate::wsk_bindings::NPI_WSK_INTERFACE_ID),
            EventMask: event_mask,
        };
        let (status, _) = sync_wsk_call(record.device, |irp| unsafe {
            control(
                record.socket,
                crate::wsk_bindings::WSK_CONTROL_SOCKET_TYPE::WskSetOption,
                SO_WSK_EVENT_CALLBACK,
                SOL_SOCKET,
                mem::size_of::<crate::wsk_bindings::WSK_EVENT_CALLBACK_CONTROL>() as u64,
                (&mut callbacks as *mut crate::wsk_bindings::WSK_EVENT_CALLBACK_CONTROL)
                    .cast::<c_void>(),
                0,
                null_mut(),
                null_mut(),
                as_wsk_irp(irp),
            )
        })?;
        if ffi::nt_success(status) {
            Ok(())
        } else {
            Err(native_error("WskControlSocket", status))
        }
    }

    fn register_static_events(&self) -> Result<(), KernelRelayError> {
        let provider_dispatch = self.provider_dispatch()?;
        let control = unsafe { (*provider_dispatch).WskControlClient }.ok_or_else(|| {
            native_error(
                "WskControlClient dispatch is unavailable",
                ffi::STATUS_NOT_SUPPORTED,
            )
        })?;
        let mut callbacks = crate::wsk_bindings::WSK_EVENT_CALLBACK_CONTROL {
            NpiId: ptr::addr_of!(crate::wsk_bindings::NPI_WSK_INTERFACE_ID),
            EventMask: crate::wsk_bindings::WSK_EVENT_ACCEPT
                | crate::wsk_bindings::WSK_EVENT_RECEIVE_FROM,
        };
        let (status, _) = sync_wsk_call(self.device, |irp| unsafe {
            control(
                self.provider.Client,
                crate::wsk_bindings::WSK_SET_STATIC_EVENT_CALLBACKS,
                mem::size_of::<crate::wsk_bindings::WSK_EVENT_CALLBACK_CONTROL>() as u64,
                (&mut callbacks as *mut crate::wsk_bindings::WSK_EVENT_CALLBACK_CONTROL)
                    .cast::<c_void>(),
                0,
                null_mut(),
                null_mut(),
                as_wsk_irp(irp),
            )
        })?;
        if ffi::nt_success(status) {
            Ok(())
        } else {
            Err(native_error("WskControlClient", status))
        }
    }
}

#[cfg(ssp_wdk_native)]
impl WskDataplane for NativeWskDataplane<'_> {
    fn create_listener_socket(
        &mut self,
        family: u16,
        protocol: FlowProtocol,
        callbacks: ListenerCallbacks,
    ) -> Result<WskSocketHandle, KernelRelayError> {
        validate_family(family)?;
        let protocol = normalize_protocol(protocol)?;
        self.register_static_events()?;
        let handle = self.allocate_record(family, protocol, callbacks, true)?;
        let (socket_type, flags, dispatch): (u16, u32, *const c_void) = if protocol
            == FlowProtocol::Tcp
        {
            (
                crate::wsk_bindings::SOCK_STREAM as u16,
                crate::wsk_bindings::WSK_FLAG_LISTEN_SOCKET,
                (&NATIVE_LISTEN_DISPATCH as *const crate::wsk_bindings::WSK_CLIENT_LISTEN_DISPATCH)
                    .cast(),
            )
        } else {
            (
                crate::wsk_bindings::SOCK_DGRAM as u16,
                crate::wsk_bindings::WSK_FLAG_DATAGRAM_SOCKET,
                (&NATIVE_DATAGRAM_DISPATCH
                    as *const crate::wsk_bindings::WSK_CLIENT_DATAGRAM_DISPATCH)
                    .cast(),
            )
        };
        if let Err(error) = self.create_socket(handle, socket_type, flags, dispatch) {
            let _ = self.close_socket(handle);
            return Err(error);
        }
        Ok(handle)
    }

    fn bind_listener(
        &mut self,
        socket: WskSocketHandle,
        local: SocketAddr,
    ) -> Result<(), KernelRelayError> {
        self.bind_record(socket, local)?;
        let record = self.record(socket)?;
        self.set_socket_events(
            record,
            if record.protocol == FlowProtocol::Tcp {
                crate::wsk_bindings::WSK_EVENT_ACCEPT
            } else {
                crate::wsk_bindings::WSK_EVENT_RECEIVE_FROM
            },
        )
    }

    fn listen(&mut self, socket: WskSocketHandle, backlog: u32) -> Result<(), KernelRelayError> {
        if backlog == 0 {
            return Err(KernelRelayError::InvalidTuple(
                "WSK listen backlog must be non-zero".into(),
            ));
        }
        let record = self.record(socket)?;
        if record.protocol != FlowProtocol::Tcp || !record.listener || !record.bound {
            return Err(KernelRelayError::InvalidState(
                "WSK listen requires a bound TCP listener".into(),
            ));
        }
        // WSK_FLAG_LISTEN_SOCKET makes WskBind publish the listening socket;
        // WSK has no separate downcall for this socket dispatch.
        Ok(())
    }

    fn create_outbound_socket(
        &mut self,
        family: u16,
        protocol: FlowProtocol,
    ) -> Result<WskSocketHandle, KernelRelayError> {
        validate_family(family)?;
        let protocol = normalize_protocol(protocol)?;
        let handle = self.allocate_record(family, protocol, ListenerCallbacks::default(), false)?;
        if protocol != FlowProtocol::Tcp {
            if let Err(error) = self.create_socket(
                handle,
                crate::wsk_bindings::SOCK_DGRAM as u16,
                crate::wsk_bindings::WSK_FLAG_DATAGRAM_SOCKET,
                (&NATIVE_DATAGRAM_DISPATCH
                    as *const crate::wsk_bindings::WSK_CLIENT_DATAGRAM_DISPATCH)
                    .cast(),
            ) {
                let _ = self.close_socket(handle);
                return Err(error);
            }
            let wildcard = if family as u32 == crate::wsk_bindings::AF_INET {
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            };
            if let Err(error) = self.bind_record(handle, wildcard) {
                let _ = self.close_socket(handle);
                return Err(error);
            }
        }
        Ok(handle)
    }

    fn connect(
        &mut self,
        socket: WskSocketHandle,
        remote: SocketAddr,
    ) -> Result<(), KernelRelayError> {
        let record = self.record(socket)?;
        if remote.is_ipv4() != (record.family as u32 == crate::wsk_bindings::AF_INET) {
            return Err(KernelRelayError::InvalidTuple(
                "WSK connect address family does not match the socket".into(),
            ));
        }
        if record.protocol != FlowProtocol::Tcp {
            record.remote = Some(remote);
            return self.set_socket_events(record, crate::wsk_bindings::WSK_EVENT_RECEIVE_FROM);
        }
        if !record.socket.is_null() {
            return Err(KernelRelayError::InvalidState(
                "WSK socket was connected more than once".into(),
            ));
        }
        let provider_dispatch = self.provider_dispatch()?;
        let connect = unsafe { (*provider_dispatch).WskSocketConnect }.ok_or_else(|| {
            native_error(
                "WskSocketConnect dispatch is unavailable",
                ffi::STATUS_NOT_SUPPORTED,
            )
        })?;
        let mut local = NativeSockAddr::wildcard(remote)?;
        let mut destination = NativeSockAddr::new(remote)?;
        let (status, information) = sync_wsk_call(record.device, |irp| unsafe {
            connect(
                self.provider.Client,
                crate::wsk_bindings::SOCK_STREAM as u16,
                protocol_number(record.protocol),
                local.as_mut_ptr(),
                destination.as_mut_ptr(),
                0,
                (record as *mut NativeSocketRecord).cast(),
                &NATIVE_CONNECTION_DISPATCH,
                null_mut(),
                null_mut(),
                null_mut(),
                as_wsk_irp(irp),
            )
        })?;
        if !ffi::nt_success(status) || information == 0 {
            return Err(native_error("WskSocketConnect", status));
        }
        record.socket = information as crate::wsk_bindings::PWSK_SOCKET;
        if let Err(error) = self.set_socket_events(
            record,
            crate::wsk_bindings::WSK_EVENT_RECEIVE | crate::wsk_bindings::WSK_EVENT_DISCONNECT,
        ) {
            let _ = close_raw_socket(record);
            record.socket = null_mut();
            return Err(error);
        }
        Ok(())
    }

    fn set_socket_callbacks(
        &mut self,
        socket: WskSocketHandle,
        callbacks: ListenerCallbacks,
    ) -> Result<(), KernelRelayError> {
        self.record(socket)?.callbacks = callbacks;
        Ok(())
    }

    fn send_stream(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: usize,
    ) -> Result<(), KernelRelayError> {
        Err(KernelRelayError::InvalidState(
            "native stream send requires caller-owned payload bytes; use send_stream_buffer".into(),
        ))
    }

    fn send_stream_bytes(
        &mut self,
        socket: WskSocketHandle,
        bytes: &[u8],
    ) -> Result<usize, KernelRelayError> {
        NativeWskDataplane::send_stream_buffer(self, socket, bytes)
    }

    fn recv_stream(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: usize,
    ) -> Result<(), KernelRelayError> {
        Err(KernelRelayError::InvalidState(
            "native stream receive requires caller-owned storage; use recv_stream_buffer".into(),
        ))
    }

    fn recv_stream_into(
        &mut self,
        socket: WskSocketHandle,
        bytes: &mut [u8],
    ) -> Result<usize, KernelRelayError> {
        NativeWskDataplane::recv_stream_buffer(self, socket, bytes)
    }

    fn shutdown_stream_send(&mut self, socket: WskSocketHandle) -> Result<(), KernelRelayError> {
        let record = self.record(socket)?;
        let dispatch = connection_dispatch(record)?;
        let disconnect = unsafe { (*dispatch).WskDisconnect }.ok_or_else(|| {
            native_error(
                "WskDisconnect dispatch is unavailable",
                ffi::STATUS_NOT_SUPPORTED,
            )
        })?;
        let (status, _) = sync_wsk_call(record.device, |irp| unsafe {
            disconnect(
                record.socket,
                null_mut(),
                crate::wsk_bindings::WSK_FLAG_DRAIN,
                as_wsk_irp(irp),
            )
        })?;
        if ffi::nt_success(status) {
            Ok(())
        } else {
            Err(native_error("WskDisconnect", status))
        }
    }

    fn send_datagram(
        &mut self,
        _socket: WskSocketHandle,
        _bytes: usize,
    ) -> Result<(), KernelRelayError> {
        Err(KernelRelayError::InvalidState(
            "native datagram send requires caller-owned payload bytes and a peer; use send_datagram_buffer"
                .into(),
        ))
    }

    fn send_datagram_bytes(
        &mut self,
        socket: WskSocketHandle,
        bytes: &[u8],
        remote: SocketAddr,
    ) -> Result<usize, KernelRelayError> {
        NativeWskDataplane::send_datagram_buffer(self, socket, bytes, remote)
    }

    fn close_socket(&mut self, socket: WskSocketHandle) -> Result<(), KernelRelayError> {
        let record = self.record(socket)?;
        record.callbacks = ListenerCallbacks::default();
        if record.socket.is_null() {
            unsafe { free_record(record) };
            return Ok(());
        }
        close_raw_socket(record)?;
        unsafe { free_record(record) };
        Ok(())
    }
}

#[cfg(ssp_wdk_native)]
struct OwnedMdlBuffer {
    allocation: PVOID,
    mdl: PMDL,
    wsk: crate::wsk_bindings::WSK_BUF,
}

#[cfg(ssp_wdk_native)]
impl OwnedMdlBuffer {
    fn empty(length: usize) -> Result<Self, KernelRelayError> {
        if length > MAX_NATIVE_OPERATION_BYTES || length > u32::MAX as usize {
            return Err(KernelRelayError::ResourceExhausted(
                "native WSK operation exceeded the configured byte bound",
            ));
        }
        let allocation =
            unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, length.max(1) as u64, NATIVE_POOL_TAG) };
        if allocation.is_null() {
            return Err(KernelRelayError::ResourceExhausted(
                "native WSK payload allocation failed",
            ));
        }
        let mdl = unsafe { IoAllocateMdl(allocation, length.max(1) as u32, 0, 0, null_mut()) };
        if mdl.is_null() {
            unsafe { ExFreePool(allocation) };
            return Err(KernelRelayError::ResourceExhausted(
                "native WSK MDL allocation failed",
            ));
        }
        unsafe { MmBuildMdlForNonPagedPool(mdl) };
        Ok(Self {
            allocation,
            mdl,
            wsk: crate::wsk_bindings::WSK_BUF {
                Mdl: mdl.cast(),
                Offset: 0,
                Length: length as u64,
            },
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KernelRelayError> {
        let buffer = Self::empty(bytes.len())?;
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.allocation.cast::<u8>(), bytes.len());
        }
        Ok(buffer)
    }

    fn free(&mut self) {
        unsafe {
            if !self.mdl.is_null() {
                IoFreeMdl(self.mdl);
                self.mdl = null_mut();
            }
            if !self.allocation.is_null() {
                ExFreePool(self.allocation);
                self.allocation = null_mut();
            }
        }
    }
}

#[cfg(ssp_wdk_native)]
#[repr(C)]
struct AsyncSendContext {
    buffer: OwnedMdlBuffer,
    remote: Option<NativeSockAddr>,
    callbacks: ListenerCallbacks,
    socket: WskSocketHandle,
}

#[cfg(ssp_wdk_native)]
unsafe extern "C" fn async_send_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: PVOID,
) -> ffi::NtStatus {
    if !context.is_null() {
        let context = context.cast::<AsyncSendContext>();
        let status = if irp.is_null() {
            ffi::STATUS_INVALID_PARAMETER
        } else {
            (*irp).IoStatus.__bindgen_anon_1.Status
        };
        if !ffi::nt_success(status) {
            if let Some(on_send_failure) = (*context).callbacks.on_send_failure {
                on_send_failure((*context).callbacks.context, (*context).socket, status);
            }
        }
        (*context).buffer.free();
        ExFreePool(context.cast());
    }
    if !irp.is_null() {
        IoFreeIrp(irp);
    }
    ffi::STATUS_MORE_PROCESSING_REQUIRED
}

#[cfg(ssp_wdk_native)]
fn submit_async_send<F>(
    device: PDEVICE_OBJECT,
    socket: crate::wsk_bindings::PWSK_SOCKET,
    buffer: OwnedMdlBuffer,
    remote: Option<NativeSockAddr>,
    callbacks: ListenerCallbacks,
    socket_handle: WskSocketHandle,
    operation: F,
) -> Result<(), KernelRelayError>
where
    F: FnOnce(
        PIRP,
        *mut crate::wsk_bindings::WSK_BUF,
        Option<crate::wsk_bindings::PSOCKADDR>,
    ) -> ffi::NtStatus,
{
    if device.is_null() || socket.is_null() {
        let mut buffer = buffer;
        buffer.free();
        return Err(native_error(
            "WSK payload send has no socket or device",
            ffi::STATUS_INVALID_PARAMETER,
        ));
    }
    let irp = unsafe { IoAllocateIrp(1, 0) };
    if irp.is_null() {
        let mut buffer = buffer;
        buffer.free();
        return Err(KernelRelayError::ResourceExhausted(
            "native WSK payload send IRP allocation failed",
        ));
    }
    let allocation = unsafe {
        ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            mem::size_of::<AsyncSendContext>() as u64,
            NATIVE_POOL_TAG,
        )
    };
    if allocation.is_null() {
        unsafe {
            IoFreeIrp(irp);
        }
        let mut buffer = buffer;
        buffer.free();
        return Err(KernelRelayError::ResourceExhausted(
            "native WSK payload send context allocation failed",
        ));
    }
    let context = allocation.cast::<AsyncSendContext>();
    unsafe {
        context.write(AsyncSendContext {
            buffer,
            remote,
            callbacks,
            socket: socket_handle,
        });
    }
    let completion_status = unsafe {
        IoSetCompletionRoutineEx(
            device,
            irp,
            Some(async_send_completion),
            context.cast(),
            1,
            1,
            1,
        )
    };
    if !ffi::nt_success(completion_status) {
        unsafe {
            (*context).buffer.free();
            ExFreePool(context.cast());
            IoFreeIrp(irp);
        }
        return Err(native_error("IoSetCompletionRoutineEx", completion_status));
    }

    let remote = unsafe { (*context).remote.as_mut().map(|remote| remote.as_mut_ptr()) };
    let status = operation(irp, unsafe { &mut (*context).buffer.wsk }, remote);
    if !ffi::nt_success(status) && status != ffi::STATUS_PENDING {
        unsafe {
            (*context).buffer.free();
            ExFreePool(context.cast());
            IoFreeIrp(irp);
        }
        return Err(native_error("WSK payload send", status));
    }
    Ok(())
}

#[cfg(ssp_wdk_native)]
unsafe fn free_record(record: &mut NativeSocketRecord) {
    record.magic = 0;
    ExFreePool((record as *mut NativeSocketRecord).cast());
}

#[cfg(ssp_wdk_native)]
fn native_error(stage: &str, status: ffi::NtStatus) -> KernelRelayError {
    KernelRelayError::Transport(format!(
        "{stage} failed with NTSTATUS 0x{:08X}",
        status as u32
    ))
}

#[cfg(ssp_wdk_native)]
fn as_wsk_irp(irp: PIRP) -> crate::wsk_bindings::PIRP {
    irp.cast()
}

#[cfg(ssp_wdk_native)]
fn validate_family(family: u16) -> Result<(), KernelRelayError> {
    if family as u32 == crate::wsk_bindings::AF_INET
        || family as u32 == crate::wsk_bindings::AF_INET6
    {
        Ok(())
    } else {
        Err(KernelRelayError::InvalidTuple(format!(
            "unsupported WSK address family {family}"
        )))
    }
}

#[cfg(ssp_wdk_native)]
fn normalize_protocol(protocol: FlowProtocol) -> Result<FlowProtocol, KernelRelayError> {
    match protocol {
        FlowProtocol::Tcp | FlowProtocol::Udp | FlowProtocol::QuicUdp => Ok(protocol),
    }
}

#[cfg(ssp_wdk_native)]
fn protocol_number(protocol: FlowProtocol) -> u32 {
    match protocol {
        FlowProtocol::Tcp => 6,
        FlowProtocol::Udp | FlowProtocol::QuicUdp => 17,
    }
}

#[cfg(ssp_wdk_native)]
fn basic_dispatch(
    record: &NativeSocketRecord,
) -> Result<*const crate::wsk_bindings::WSK_PROVIDER_BASIC_DISPATCH, KernelRelayError> {
    if record.socket.is_null() || unsafe { (*record.socket).Dispatch.is_null() } {
        return Err(native_error(
            "WSK socket dispatch is null",
            ffi::STATUS_NOT_SUPPORTED,
        ));
    }
    Ok(unsafe {
        (*record.socket).Dispatch as *const crate::wsk_bindings::WSK_PROVIDER_BASIC_DISPATCH
    })
}

#[cfg(ssp_wdk_native)]
fn listen_dispatch(
    record: &NativeSocketRecord,
) -> Result<*const crate::wsk_bindings::WSK_PROVIDER_LISTEN_DISPATCH, KernelRelayError> {
    if record.socket.is_null() || unsafe { (*record.socket).Dispatch.is_null() } {
        return Err(native_error(
            "WSK listener dispatch is null",
            ffi::STATUS_NOT_SUPPORTED,
        ));
    }
    Ok(unsafe {
        (*record.socket).Dispatch as *const crate::wsk_bindings::WSK_PROVIDER_LISTEN_DISPATCH
    })
}

#[cfg(ssp_wdk_native)]
fn datagram_dispatch(
    record: &NativeSocketRecord,
) -> Result<*const crate::wsk_bindings::WSK_PROVIDER_DATAGRAM_DISPATCH, KernelRelayError> {
    if record.socket.is_null() || unsafe { (*record.socket).Dispatch.is_null() } {
        return Err(native_error(
            "WSK datagram dispatch is null",
            ffi::STATUS_NOT_SUPPORTED,
        ));
    }
    Ok(unsafe {
        (*record.socket).Dispatch as *const crate::wsk_bindings::WSK_PROVIDER_DATAGRAM_DISPATCH
    })
}

#[cfg(ssp_wdk_native)]
fn connection_dispatch(
    record: &NativeSocketRecord,
) -> Result<*const crate::wsk_bindings::WSK_PROVIDER_CONNECTION_DISPATCH, KernelRelayError> {
    if record.socket.is_null() || unsafe { (*record.socket).Dispatch.is_null() } {
        return Err(native_error(
            "WSK connection dispatch is null",
            ffi::STATUS_NOT_SUPPORTED,
        ));
    }
    Ok(unsafe {
        (*record.socket).Dispatch as *const crate::wsk_bindings::WSK_PROVIDER_CONNECTION_DISPATCH
    })
}

#[cfg(ssp_wdk_native)]
fn close_raw_socket(record: &NativeSocketRecord) -> Result<(), KernelRelayError> {
    let dispatch = basic_dispatch(record)?;
    let close = unsafe { (*dispatch).WskCloseSocket }.ok_or_else(|| {
        native_error(
            "WskCloseSocket dispatch is unavailable",
            ffi::STATUS_NOT_SUPPORTED,
        )
    })?;
    let (status, _) = sync_wsk_call(record.device, |irp| unsafe {
        close(record.socket, as_wsk_irp(irp))
    })?;
    if ffi::nt_success(status) {
        Ok(())
    } else {
        Err(native_error("WskCloseSocket", status))
    }
}

#[cfg(ssp_wdk_native)]
struct NativeSockAddr {
    storage: NativeSockAddrStorage,
}

#[cfg(ssp_wdk_native)]
enum NativeSockAddrStorage {
    V4(crate::wsk_bindings::SOCKADDR_IN),
    V6(crate::wsk_bindings::SOCKADDR_IN6),
}

#[cfg(ssp_wdk_native)]
impl NativeSockAddr {
    fn new(address: SocketAddr) -> Result<Self, KernelRelayError> {
        match address {
            SocketAddr::V4(address) => Ok(Self {
                storage: NativeSockAddrStorage::V4(crate::wsk_bindings::SOCKADDR_IN {
                    sin_family: crate::wsk_bindings::AF_INET as _,
                    sin_port: address.port().to_be(),
                    sin_addr: crate::wsk_bindings::IN_ADDR {
                        S_un: crate::wsk_bindings::in_addr__bindgen_ty_1 {
                            S_addr: u32::from_ne_bytes(address.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                }),
            }),
            SocketAddr::V6(address) => Ok(Self {
                storage: NativeSockAddrStorage::V6(crate::wsk_bindings::SOCKADDR_IN6 {
                    sin6_family: crate::wsk_bindings::AF_INET6 as _,
                    sin6_port: address.port().to_be(),
                    sin6_flowinfo: address.flowinfo(),
                    sin6_addr: crate::wsk_bindings::IN6_ADDR {
                        u: crate::wsk_bindings::in6_addr__bindgen_ty_1 {
                            Byte: address.ip().octets(),
                        },
                    },
                    __bindgen_anon_1: crate::wsk_bindings::sockaddr_in6__bindgen_ty_1 {
                        sin6_scope_id: address.scope_id(),
                    },
                }),
            }),
        }
    }

    fn wildcard(address: SocketAddr) -> Result<Self, KernelRelayError> {
        if address.is_ipv4() {
            Self::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        } else {
            Self::new(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        }
    }

    fn as_mut_ptr(&mut self) -> crate::wsk_bindings::PSOCKADDR {
        match &mut self.storage {
            NativeSockAddrStorage::V4(address) => {
                address as *mut crate::wsk_bindings::SOCKADDR_IN as _
            }
            NativeSockAddrStorage::V6(address) => {
                address as *mut crate::wsk_bindings::SOCKADDR_IN6 as _
            }
        }
    }
}

#[cfg(ssp_wdk_native)]
unsafe fn socket_addr_from_ptr(address: crate::wsk_bindings::PSOCKADDR) -> Option<SocketAddr> {
    if address.is_null() {
        return None;
    }
    match (*address).sa_family as u32 {
        crate::wsk_bindings::AF_INET => {
            let address = &*(address.cast::<crate::wsk_bindings::SOCKADDR_IN>());
            let bytes = address.sin_addr.S_un.S_addr.to_ne_bytes();
            Some(SocketAddr::from((
                Ipv4Addr::from(bytes),
                u16::from_be(address.sin_port),
            )))
        }
        crate::wsk_bindings::AF_INET6 => {
            let address = &*(address.cast::<crate::wsk_bindings::SOCKADDR_IN6>());
            let bytes = address.sin6_addr.u.Byte;
            let scope_id = address.__bindgen_anon_1.sin6_scope_id;
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(bytes),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(ssp_wdk_native)]
unsafe extern "C" fn sync_completion(
    _device: PDEVICE_OBJECT,
    _irp: PIRP,
    context: PVOID,
) -> ffi::NtStatus {
    if !context.is_null() {
        KeSetEvent(context.cast::<KEVENT>(), 0, 0);
    }
    ffi::STATUS_MORE_PROCESSING_REQUIRED
}

#[cfg(ssp_wdk_native)]
fn sync_wsk_call<F>(
    device: PDEVICE_OBJECT,
    operation: F,
) -> Result<(ffi::NtStatus, usize), KernelRelayError>
where
    F: FnOnce(PIRP) -> ffi::NtStatus,
{
    if device.is_null() {
        return Err(native_error(
            "WSK operation has no device object for IRP completion",
            ffi::STATUS_INVALID_PARAMETER,
        ));
    }
    let mut event = unsafe { mem::MaybeUninit::<KEVENT>::zeroed().assume_init() };
    unsafe { KeInitializeEvent(&mut event, 1, 0) };
    let irp = unsafe { IoAllocateIrp(1, 0) };
    if irp.is_null() {
        return Err(KernelRelayError::ResourceExhausted(
            "native WSK IRP allocation failed",
        ));
    }
    let completion_status = unsafe {
        IoSetCompletionRoutineEx(
            device,
            irp,
            Some(sync_completion),
            (&mut event as *mut KEVENT).cast(),
            1,
            1,
            1,
        )
    };
    if !ffi::nt_success(completion_status) {
        unsafe { IoFreeIrp(irp) };
        return Err(native_error("IoSetCompletionRoutineEx", completion_status));
    }
    let _dispatch_status = operation(irp);
    let mut timeout = LARGE_INTEGER::default();
    timeout.QuadPart = NATIVE_IRP_TIMEOUT_100NS;
    let wait_status =
        unsafe { KeWaitForSingleObject((&mut event as *mut KEVENT).cast(), 0, 0, 0, &mut timeout) };
    if wait_status != ffi::STATUS_SUCCESS {
        unsafe {
            let _ = IoCancelIrp(irp);
            let _ = KeWaitForSingleObject((&mut event as *mut KEVENT).cast(), 0, 0, 0, null_mut());
        }
        unsafe { IoFreeIrp(irp) };
        return Err(native_error("WSK IRP wait", ffi::STATUS_TIMEOUT));
    }
    let status = unsafe { (*irp).IoStatus.__bindgen_anon_1.Status };
    let information = unsafe { (*irp).IoStatus.Information as usize };
    unsafe { IoFreeIrp(irp) };
    Ok((status, information))
}

#[cfg(ssp_wdk_native)]
unsafe fn mapped_mdl_address(mdl: PMDL) -> (*mut u8, bool) {
    if mdl.is_null() {
        return (null_mut(), false);
    }
    let flags = (*mdl).MdlFlags as u32;
    if flags & (wdk_sys::MDL_MAPPED_TO_SYSTEM_VA | wdk_sys::MDL_SOURCE_IS_NONPAGED_POOL) != 0 {
        return ((*mdl).MappedSystemVa.cast(), false);
    }
    let address = MmMapLockedPagesSpecifyCache(mdl, 0, 1, null_mut(), 0, 16);
    (address.cast(), !address.is_null())
}

#[cfg(ssp_wdk_native)]
fn copy_wsk_buffer(
    source: &crate::wsk_bindings::WSK_BUF,
) -> Result<OwnedMdlBuffer, KernelRelayError> {
    let length = source.Length as usize;
    if length > MAX_NATIVE_OPERATION_BYTES {
        return Err(KernelRelayError::ResourceExhausted(
            "native WSK indication exceeded the configured byte bound",
        ));
    }
    let mut buffer = OwnedMdlBuffer::empty(length)?;
    let mut mdl = source.Mdl;
    let mut offset = source.Offset as usize;
    let mut copied = 0usize;
    while copied < length {
        if mdl.is_null() {
            buffer.free();
            return Err(KernelRelayError::Transport(
                "WSK indication MDL chain ended before the declared length".into(),
            ));
        }
        let byte_count = unsafe { (*mdl).ByteCount as usize };
        if byte_count == 0 {
            mdl = unsafe { (*mdl).Next };
            continue;
        }
        if offset >= byte_count {
            offset -= byte_count;
            mdl = unsafe { (*mdl).Next };
            continue;
        }
        let (address, mapped) = unsafe { mapped_mdl_address(mdl.cast()) };
        if address.is_null() {
            buffer.free();
            return Err(KernelRelayError::Transport(
                "WSK indication MDL could not be mapped".into(),
            ));
        }
        let amount = (byte_count - offset).min(length - copied);
        unsafe {
            ptr::copy_nonoverlapping(
                address.add(offset),
                buffer.allocation.cast::<u8>().add(copied),
                amount,
            );
            if mapped {
                MmUnmapLockedPages(address.cast(), mdl.cast());
            }
        }
        copied += amount;
        offset = 0;
        mdl = unsafe { (*mdl).Next };
    }
    Ok(buffer)
}

#[cfg(ssp_wdk_native)]
unsafe extern "C" fn native_accept_event(
    socket_context: PVOID,
    _flags: u32,
    local_address: crate::wsk_bindings::PSOCKADDR,
    remote_address: crate::wsk_bindings::PSOCKADDR,
    accept_socket: crate::wsk_bindings::PWSK_SOCKET,
    accept_socket_context: *mut PVOID,
    accept_socket_dispatch: *mut *const crate::wsk_bindings::WSK_CLIENT_CONNECTION_DISPATCH,
) -> ffi::NtStatus {
    if socket_context.is_null() || accept_socket.is_null() {
        return ffi::STATUS_INVALID_PARAMETER;
    }
    let listener = &*(socket_context.cast::<NativeSocketRecord>());
    let Some(remote) = socket_addr_from_ptr(remote_address) else {
        return ffi::STATUS_INVALID_PARAMETER;
    };
    let Some(local) = socket_addr_from_ptr(local_address).or(listener.local) else {
        return ffi::STATUS_INVALID_PARAMETER;
    };
    let handle = match allocate_accepted_record(listener, accept_socket, local, remote) {
        Ok(handle) => handle,
        Err(_) => return ffi::STATUS_INSUFFICIENT_RESOURCES,
    };
    if accept_socket_context.is_null() || accept_socket_dispatch.is_null() {
        let record = &mut *(handle.0 as *mut NativeSocketRecord);
        let _ = close_raw_socket(record);
        free_record(record);
        return ffi::STATUS_INVALID_PARAMETER;
    }
    *accept_socket_context = (handle.0 as *mut NativeSocketRecord).cast();
    *accept_socket_dispatch = &NATIVE_CONNECTION_DISPATCH;
    let record = &*(handle.0 as *mut NativeSocketRecord);
    if let Some(on_accept) = record.callbacks.on_accept {
        let result = on_accept(
            record.callbacks.context,
            handle,
            SocketTuple {
                source: remote,
                destination: local,
                protocol: FlowProtocol::Tcp,
            },
        );
        if result.is_ok() {
            ffi::STATUS_SUCCESS
        } else {
            let record = &mut *(handle.0 as *mut NativeSocketRecord);
            let _ = close_raw_socket(record);
            free_record(record);
            ffi::STATUS_INVALID_PARAMETER
        }
    } else {
        let record = &mut *(handle.0 as *mut NativeSocketRecord);
        let _ = close_raw_socket(record);
        free_record(record);
        ffi::STATUS_NOT_SUPPORTED
    }
}

#[cfg(ssp_wdk_native)]
unsafe fn allocate_accepted_record(
    listener: &NativeSocketRecord,
    socket: crate::wsk_bindings::PWSK_SOCKET,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<WskSocketHandle, KernelRelayError> {
    let allocation = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        mem::size_of::<NativeSocketRecord>() as u64,
        NATIVE_POOL_TAG,
    );
    if allocation.is_null() {
        return Err(KernelRelayError::ResourceExhausted(
            "accepted WSK socket context allocation failed",
        ));
    }
    let record = allocation.cast::<NativeSocketRecord>();
    record.write(NativeSocketRecord {
        magic: NATIVE_SOCKET_MAGIC,
        socket,
        provider: listener.provider,
        device: listener.device,
        family: listener.family,
        protocol: FlowProtocol::Tcp,
        callbacks: listener.callbacks,
        remote: Some(remote),
        local: Some(local),
        bound: true,
        listener: false,
    });
    Ok(WskSocketHandle(record as usize))
}

#[cfg(ssp_wdk_native)]
unsafe extern "C" fn native_receive_from_event(
    socket_context: PVOID,
    _flags: u32,
    indication: crate::wsk_bindings::PWSK_DATAGRAM_INDICATION,
) -> ffi::NtStatus {
    if socket_context.is_null() || indication.is_null() {
        return ffi::STATUS_INVALID_PARAMETER;
    }
    let record = &*(socket_context.cast::<NativeSocketRecord>());
    let Some(on_datagram) = record.callbacks.on_datagram else {
        return ffi::STATUS_NOT_SUPPORTED;
    };
    let Some(local) = record.local else {
        return ffi::STATUS_INVALID_PARAMETER;
    };
    let handle = WskSocketHandle(record as *const NativeSocketRecord as usize);
    let mut current = indication;
    let mut total = 0usize;
    while !current.is_null() {
        let Some(remote) = socket_addr_from_ptr((*current).RemoteAddress) else {
            return ffi::STATUS_INVALID_PARAMETER;
        };
        let mut buffer = match copy_wsk_buffer(&(*current).Buffer) {
            Ok(buffer) => buffer,
            Err(KernelRelayError::ResourceExhausted(_)) => {
                return ffi::STATUS_INSUFFICIENT_RESOURCES
            }
            Err(_) => return ffi::STATUS_INVALID_PARAMETER,
        };
        let length = buffer.wsk.Length as usize;
        let Some(next_total) = total.checked_add(length) else {
            buffer.free();
            return ffi::STATUS_BUFFER_TOO_SMALL;
        };
        if next_total > MAX_NATIVE_OPERATION_BYTES {
            buffer.free();
            return ffi::STATUS_BUFFER_TOO_SMALL;
        }
        let bytes = slice::from_raw_parts(buffer.allocation.cast::<u8>(), length);
        let tuple = SocketTuple {
            source: remote,
            destination: local,
            protocol: record.protocol,
        };
        let result = on_datagram(record.callbacks.context, handle, tuple, bytes);
        buffer.free();
        if result.is_err() {
            return ffi::STATUS_INVALID_PARAMETER;
        }
        total = next_total;
        current = (*current).Next;
    }
    ffi::STATUS_SUCCESS
}

#[cfg(ssp_wdk_native)]
unsafe extern "C" fn native_receive_event(
    socket_context: PVOID,
    _flags: u32,
    indication: crate::wsk_bindings::PWSK_DATA_INDICATION,
    bytes_indicated: u64,
    bytes_accepted: *mut u64,
) -> ffi::NtStatus {
    if !bytes_accepted.is_null() {
        *bytes_accepted = 0;
    }
    if socket_context.is_null() || indication.is_null() {
        return ffi::STATUS_INVALID_PARAMETER;
    }
    let record = &*(socket_context.cast::<NativeSocketRecord>());
    let Some(on_stream) = record.callbacks.on_stream else {
        return ffi::STATUS_NOT_SUPPORTED;
    };
    if bytes_indicated as usize > MAX_NATIVE_OPERATION_BYTES {
        return ffi::STATUS_BUFFER_TOO_SMALL;
    }
    let handle = WskSocketHandle(record as *const NativeSocketRecord as usize);
    let mut current = indication;
    let mut total = 0usize;
    while !current.is_null() {
        let mut buffer = match copy_wsk_buffer(&(*current).Buffer) {
            Ok(buffer) => buffer,
            Err(KernelRelayError::ResourceExhausted(_)) => {
                return ffi::STATUS_INSUFFICIENT_RESOURCES
            }
            Err(_) => return ffi::STATUS_INVALID_PARAMETER,
        };
        let length = buffer.wsk.Length as usize;
        let Some(next_total) = total.checked_add(length) else {
            buffer.free();
            return ffi::STATUS_BUFFER_TOO_SMALL;
        };
        if next_total > MAX_NATIVE_OPERATION_BYTES {
            buffer.free();
            return ffi::STATUS_BUFFER_TOO_SMALL;
        }
        let bytes = slice::from_raw_parts(buffer.allocation.cast::<u8>(), length);
        let result = on_stream(record.callbacks.context, handle, bytes);
        buffer.free();
        if result.is_err() {
            return ffi::STATUS_INVALID_PARAMETER;
        }
        total = next_total;
        current = (*current).Next;
    }
    if !bytes_accepted.is_null() {
        *bytes_accepted = total.min(bytes_indicated as usize) as u64;
    }
    ffi::STATUS_SUCCESS
}

#[cfg(ssp_wdk_native)]
unsafe extern "C" fn native_disconnect_event(socket_context: PVOID, _flags: u32) -> ffi::NtStatus {
    if !socket_context.is_null() {
        let record = &*(socket_context.cast::<NativeSocketRecord>());
        if let Some(on_disconnect) = record.callbacks.on_disconnect {
            return match on_disconnect(
                record.callbacks.context,
                WskSocketHandle(record as *const NativeSocketRecord as usize),
            ) {
                Ok(()) => ffi::STATUS_SUCCESS,
                Err(_) => ffi::STATUS_INVALID_PARAMETER,
            };
        }
    }
    ffi::STATUS_SUCCESS
}

#[derive(Debug, Clone, Copy)]
/// One configured WSK listener with its bound socket handle.
pub struct WskListener {
    /// Bound family (AF_INET/AF_INET6).
    pub family: u16,
    /// Bound local socket address.
    pub local: SocketAddr,
    /// Transport protocol served by this listener.
    pub protocol: FlowProtocol,
    /// Provider-owned listener socket once started.
    pub socket: Option<WskSocketHandle>,
    /// Callback table published with the listener.
    pub callbacks: ListenerCallbacks,
}

impl WskListener {
    /// Creates a listener plan for one family/protocol pair.
    pub const fn new(
        family: u16,
        local: SocketAddr,
        protocol: FlowProtocol,
        callbacks: ListenerCallbacks,
    ) -> Self {
        Self {
            family,
            local,
            protocol,
            socket: None,
            callbacks,
        }
    }

    /// Indicates whether the listener owns a live provider socket.
    pub fn is_bound(&self) -> bool {
        self.socket.is_some()
    }

    /// Releases the listener handle.
    pub fn close<A: WskDataplane>(&mut self, api: &mut A) -> Result<(), KernelRelayError> {
        let socket = self.socket.take();
        if let Some(socket) = socket {
            api.close_socket(socket)?;
        }
        if let Some(on_disconnect) = self.callbacks.on_disconnect {
            unsafe {
                let _ = on_disconnect(self.callbacks.context, socket.unwrap_or(WskSocketHandle(0)));
            };
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
/// Set of TCP and UDP listeners owned by the driver runtime.
pub struct ListenerSet {
    pub tcp_v4: Option<WskListener>,
    pub tcp_v6: Option<WskListener>,
    pub udp_v4: Option<WskListener>,
    pub udp_v6: Option<WskListener>,
}

impl ListenerSet {
    /// Creates, binds, and listens on the configured listeners through the WSK
    /// dataplane abstraction.
    pub fn start<A: WskDataplane>(
        &mut self,
        api: &mut A,
        bindings: &[ListenerBinding],
        callbacks: ListenerCallbacks,
    ) -> Result<(), KernelRelayError> {
        for binding in bindings {
            let socket = api.create_listener_socket(binding.family, binding.protocol, callbacks)?;
            api.bind_listener(socket, binding.local)?;
            if binding.protocol == FlowProtocol::Tcp {
                api.listen(socket, binding.backlog)?;
            }
            let listener = WskListener {
                family: binding.family,
                local: binding.local,
                protocol: binding.protocol,
                socket: Some(socket),
                callbacks,
            };
            *self.slot_mut(binding.family, binding.protocol)? = Some(listener);
        }
        Ok(())
    }

    /// Releases all listener seams during driver unload.
    pub fn close_all<A: WskDataplane>(&mut self, api: &mut A) -> Result<(), KernelRelayError> {
        if let Some(listener) = self.tcp_v4.as_mut() {
            listener.close(api)?;
        }
        if let Some(listener) = self.tcp_v6.as_mut() {
            listener.close(api)?;
        }
        if let Some(listener) = self.udp_v4.as_mut() {
            listener.close(api)?;
        }
        if let Some(listener) = self.udp_v6.as_mut() {
            listener.close(api)?;
        }
        Ok(())
    }

    fn slot_mut(
        &mut self,
        family: u16,
        protocol: FlowProtocol,
    ) -> Result<&mut Option<WskListener>, KernelRelayError> {
        match (family, protocol) {
            (2, FlowProtocol::Tcp) => Ok(&mut self.tcp_v4),
            (23, FlowProtocol::Tcp) => Ok(&mut self.tcp_v6),
            (2, FlowProtocol::Udp | FlowProtocol::QuicUdp) => Ok(&mut self.udp_v4),
            (23, FlowProtocol::Udp | FlowProtocol::QuicUdp) => Ok(&mut self.udp_v6),
            _ => Err(KernelRelayError::InvalidTuple(format!(
                "unsupported listener family/protocol pair {family}/{protocol:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Typed send/receive/half-close seam for one TCP relay operation.
pub struct TcpRelayOperation {
    pub socket: WskSocketHandle,
    pub max_bytes: usize,
}

impl TcpRelayOperation {
    /// Sends one bounded stream buffer.
    pub fn send<A: WskDataplane>(&self, api: &mut A, bytes: usize) -> Result<(), KernelRelayError> {
        self.validate_bytes(bytes)?;
        api.send_stream(self.socket, bytes)
    }

    /// Sends one caller-owned bounded stream buffer.
    pub fn send_buffer<A: WskDataplane>(
        &self,
        api: &mut A,
        bytes: &[u8],
    ) -> Result<usize, KernelRelayError> {
        self.validate_bytes(bytes.len())?;
        api.send_stream_bytes(self.socket, bytes)
    }

    /// Receives one bounded stream buffer.
    pub fn receive<A: WskDataplane>(
        &self,
        api: &mut A,
        bytes: usize,
    ) -> Result<(), KernelRelayError> {
        self.validate_bytes(bytes)?;
        api.recv_stream(self.socket, bytes)
    }

    /// Receives one bounded stream buffer into caller-owned storage.
    pub fn receive_into<A: WskDataplane>(
        &self,
        api: &mut A,
        bytes: &mut [u8],
    ) -> Result<usize, KernelRelayError> {
        self.validate_bytes(bytes.len())?;
        api.recv_stream_into(self.socket, bytes)
    }

    /// Marks the operation as a half-close send shutdown seam.
    pub fn shutdown_send<A: WskDataplane>(&self, api: &mut A) -> Result<(), KernelRelayError> {
        api.shutdown_stream_send(self.socket)
    }

    fn validate_bytes(&self, bytes: usize) -> Result<(), KernelRelayError> {
        if bytes > self.max_bytes {
            return Err(KernelRelayError::ResourceExhausted(
                "TCP relay operation exceeded the configured byte bound",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
/// Typed send seam for one UDP relay association operation.
pub struct UdpRelayOperation {
    pub socket: WskSocketHandle,
    pub max_bytes: usize,
}

impl UdpRelayOperation {
    /// Sends one bounded datagram.
    pub fn send<A: WskDataplane>(&self, api: &mut A, bytes: usize) -> Result<(), KernelRelayError> {
        if bytes > self.max_bytes {
            return Err(KernelRelayError::ResourceExhausted(
                "UDP relay operation exceeded the configured byte bound",
            ));
        }
        api.send_datagram(self.socket, bytes)
    }

    /// Sends one caller-owned bounded datagram.
    pub fn send_buffer<A: WskDataplane>(
        &self,
        api: &mut A,
        bytes: &[u8],
        remote: SocketAddr,
    ) -> Result<usize, KernelRelayError> {
        if bytes.len() > self.max_bytes {
            return Err(KernelRelayError::ResourceExhausted(
                "UDP relay operation exceeded the configured byte bound",
            ));
        }
        api.send_datagram_bytes(self.socket, bytes, remote)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        net::{Ipv4Addr, SocketAddr},
    };

    use super::*;

    #[derive(Default)]
    struct MockApi {
        ops: RefCell<Vec<String>>,
        next_socket: usize,
    }

    impl WskDataplane for MockApi {
        fn create_listener_socket(
            &mut self,
            family: u16,
            protocol: FlowProtocol,
            _callbacks: ListenerCallbacks,
        ) -> Result<WskSocketHandle, KernelRelayError> {
            self.next_socket += 1;
            self.ops
                .borrow_mut()
                .push(format!("create-listener-{family}-{protocol:?}"));
            Ok(WskSocketHandle(self.next_socket))
        }

        fn bind_listener(
            &mut self,
            socket: WskSocketHandle,
            local: SocketAddr,
        ) -> Result<(), KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("bind-{}-{local}", socket.0));
            Ok(())
        }

        fn listen(
            &mut self,
            socket: WskSocketHandle,
            backlog: u32,
        ) -> Result<(), KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("listen-{}-{backlog}", socket.0));
            Ok(())
        }

        fn create_outbound_socket(
            &mut self,
            _family: u16,
            _protocol: FlowProtocol,
        ) -> Result<WskSocketHandle, KernelRelayError> {
            self.next_socket += 1;
            Ok(WskSocketHandle(self.next_socket))
        }

        fn connect(
            &mut self,
            socket: WskSocketHandle,
            remote: SocketAddr,
        ) -> Result<(), KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("connect-{}-{remote}", socket.0));
            Ok(())
        }

        fn send_stream(
            &mut self,
            socket: WskSocketHandle,
            bytes: usize,
        ) -> Result<(), KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("send-stream-{}-{bytes}", socket.0));
            Ok(())
        }

        fn send_stream_bytes(
            &mut self,
            socket: WskSocketHandle,
            bytes: &[u8],
        ) -> Result<usize, KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("send-stream-payload-{}-{}", socket.0, bytes.len()));
            Ok(bytes.len())
        }

        fn recv_stream(
            &mut self,
            socket: WskSocketHandle,
            bytes: usize,
        ) -> Result<(), KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("recv-stream-{}-{bytes}", socket.0));
            Ok(())
        }

        fn shutdown_stream_send(
            &mut self,
            socket: WskSocketHandle,
        ) -> Result<(), KernelRelayError> {
            self.ops.borrow_mut().push(format!("shutdown-{}", socket.0));
            Ok(())
        }

        fn send_datagram(
            &mut self,
            socket: WskSocketHandle,
            bytes: usize,
        ) -> Result<(), KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("send-dgram-{}-{bytes}", socket.0));
            Ok(())
        }

        fn send_datagram_bytes(
            &mut self,
            socket: WskSocketHandle,
            bytes: &[u8],
            _remote: SocketAddr,
        ) -> Result<usize, KernelRelayError> {
            self.ops
                .borrow_mut()
                .push(format!("send-dgram-payload-{}-{}", socket.0, bytes.len()));
            Ok(bytes.len())
        }

        fn close_socket(&mut self, socket: WskSocketHandle) -> Result<(), KernelRelayError> {
            self.ops.borrow_mut().push(format!("close-{}", socket.0));
            Ok(())
        }
    }

    #[test]
    fn listener_setup_creates_binds_and_listens() {
        let mut api = MockApi::default();
        let mut listeners = ListenerSet::default();
        listeners
            .start(
                &mut api,
                &[
                    ListenerBinding {
                        family: 2,
                        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 5000)),
                        protocol: FlowProtocol::Tcp,
                        backlog: 32,
                    },
                    ListenerBinding {
                        family: 2,
                        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 5001)),
                        protocol: FlowProtocol::Udp,
                        backlog: 0,
                    },
                ],
                ListenerCallbacks::default(),
            )
            .expect("listener start should succeed");
        assert!(listeners.tcp_v4.expect("tcp listener").is_bound());
        assert!(listeners.udp_v4.expect("udp listener").is_bound());
        assert_eq!(
            api.ops.borrow().as_slice(),
            &[
                "create-listener-2-Tcp".to_string(),
                format!("bind-1-{}", SocketAddr::from((Ipv4Addr::LOCALHOST, 5000))),
                "listen-1-32".to_string(),
                "create-listener-2-Udp".to_string(),
                format!("bind-2-{}", SocketAddr::from((Ipv4Addr::LOCALHOST, 5001))),
            ]
        );
    }

    #[test]
    fn payload_operations_keep_existing_bounds() {
        let mut api = MockApi::default();
        let tcp = TcpRelayOperation {
            socket: WskSocketHandle(7),
            max_bytes: 3,
        };
        assert_eq!(
            tcp.send_buffer(&mut api, &[1, 2])
                .expect("bounded payload should send"),
            2
        );
        assert!(matches!(
            tcp.send_buffer(&mut api, &[1, 2, 3, 4]),
            Err(KernelRelayError::ResourceExhausted(_))
        ));

        let udp = UdpRelayOperation {
            socket: WskSocketHandle(8),
            max_bytes: 2,
        };
        assert_eq!(
            udp.send_buffer(&mut api, &[9], "192.0.2.1:53".parse().expect("valid peer"))
                .expect("bounded datagram should send"),
            1
        );
    }
}
