// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! WDM device boundary, WSK listener ownership, and the bounded mapping plane.
//!
//! The driver owns fixed loopback TCP/UDP listeners on port 15000. A flow is
//! admitted only while the broker has posted an inverted-call wait IRP. The
//! driver then completes that IRP once with one observed synthetic tuple and
//! accepts the matching validated mapping completion.
#![allow(static_mut_refs)]

use core::{
    ffi::c_void,
    mem::{size_of, MaybeUninit},
    ptr::{copy_nonoverlapping, null_mut},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering},
};

use crate::{
    abi,
    flow_table::{FlowKey, FlowState, FlowTable, ReserveResult, FLOW_TABLE_CAPACITY},
    wsk_bindings as wsk,
};
use wdk_sys::{
    ntddk::{
        DbgPrintEx, IoAcquireCancelSpinLock, IoAllocateIrp, IoCreateDevice, IoCreateSymbolicLink,
        IoDeleteDevice, IoDeleteSymbolicLink, IoFreeIrp, IoReleaseCancelSpinLock,
        IoSetCompletionRoutineEx, IofCompleteRequest, KeCancelTimer, KeFlushQueuedDpcs,
        KeInitializeDpc, KeInitializeEvent, KeInitializeTimerEx, KeQueryInterruptTimePrecise,
        KeSetEvent, KeSetTimerEx, KeWaitForSingleObject, RtlRandomEx,
    },
    DRIVER_OBJECT, KDPC, KEVENT, KIRQL, KTIMER, LARGE_INTEGER, NTSTATUS, PDEVICE_OBJECT, PIRP,
    PUNICODE_STRING, PVOID,
};

const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_PENDING: NTSTATUS = 0x0000_0103;
const STATUS_CANCELLED: NTSTATUS = 0xC000_0120_u32 as NTSTATUS;
const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000D_u32 as NTSTATUS;
const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000_009A_u32 as NTSTATUS;
const STATUS_NOT_SUPPORTED: NTSTATUS = 0xC000_00BB_u32 as NTSTATUS;
const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023_u32 as NTSTATUS;
const STATUS_REQUEST_NOT_ACCEPTED: NTSTATUS = 0xC000_00D0_u32 as NTSTATUS;
const STATUS_MORE_PROCESSING_REQUIRED: NTSTATUS = 0xC000_0016_u32 as NTSTATUS;
const DPFLTR_IHVDRIVER_ID: u32 = 77;
const DPFLTR_ERROR_LEVEL: u32 = 0;
const DPFLTR_INFO_LEVEL: u32 = 4;

const FILE_DEVICE_NETWORK: u32 = 0x12;
const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;
const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;
const IRP_MJ_CREATE: usize = 0;
const IRP_MJ_CLOSE: usize = 2;
const IRP_MJ_CLEANUP: usize = 18;
const IRP_MJ_DEVICE_CONTROL: usize = 14;

const AF_INET: u16 = wsk::AF_INET as u16;
const AF_INET6: u16 = wsk::AF_INET6 as u16;
const SOCK_STREAM: u16 = wsk::SOCK_STREAM as u16;
const SOCK_DGRAM: u16 = wsk::SOCK_DGRAM as u16;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const WSK_FLAG_LISTEN_SOCKET: u32 = wsk::WSK_FLAG_LISTEN_SOCKET;
const WSK_FLAG_DATAGRAM_SOCKET: u32 = wsk::WSK_FLAG_DATAGRAM_SOCKET;
const WSK_EVENT_ACCEPT: u32 = wsk::WSK_EVENT_ACCEPT;
const WSK_EVENT_RECEIVE_FROM: u32 = wsk::WSK_EVENT_RECEIVE_FROM;
const WSK_EVENT_RECEIVE: u32 = wsk::WSK_EVENT_RECEIVE;
const WSK_EVENT_DISCONNECT: u32 = wsk::WSK_EVENT_DISCONNECT;
const WSK_SET_STATIC_EVENT_CALLBACKS: u32 = wsk::WSK_SET_STATIC_EVENT_CALLBACKS;
const WSK_SET_OPTION: i32 = wsk::WSK_CONTROL_SOCKET_TYPE::WskSetOption;
const SO_WSK_EVENT_CALLBACK: u32 = 0x4002;
const SOL_SOCKET: u32 = 0xffff;
const WSK_INFINITE_WAIT: u32 = wsk::WSK_INFINITE_WAIT;
const TIMER_PERIOD_MS: i32 = 1_000;
const TIMER_PERIOD_100NS: i64 = 10_000_000;
const MAPPING_TIMEOUT_100NS: u64 = abi::MAPPING_TIMEOUT_MS * 10_000;
const FLOW_IDLE_TIMEOUT_100NS: u64 = 60 * 10_000_000;

const fn wide<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut output = [0u16; N];
    let mut index = 0;
    while index < N {
        output[index] = bytes[index] as u16;
        index += 1;
    }
    output
}

const DEVICE_NAME: [u16; 25] = wide(b"\\Device\\ShadowSocketProxy");
const DOS_DEVICE_NAME: [u16; 29] = wide(b"\\DosDevices\\ShadowSocketProxy");

fn debug_status(stage: &[u8], status: NTSTATUS) {
    let format = b"ShadowSocketProxy: %s failed with status 0x%08X\0";
    unsafe {
        let _ = DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            format.as_ptr().cast::<i8>(),
            stage.as_ptr().cast::<i8>(),
            status as u32,
        );
    }
}

fn debug_connect_attempt(original: &abi::MappingTuple, index: usize, socket_type: u16) {
    unsafe {
        if original.address_family == 4 {
            let format = b"ShadowSocketProxy: WskSocketConnect attempt slot=%u protocol=%u family=%u type=%u local=wildcard:0 remote=%02X.%02X.%02X.%02X:%u\0";
            let _ = DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                format.as_ptr().cast::<i8>(),
                index as u32,
                original.protocol as u32,
                original.address_family as u32,
                socket_type as u32,
                original.destination_address[0] as u32,
                original.destination_address[1] as u32,
                original.destination_address[2] as u32,
                original.destination_address[3] as u32,
                original.destination_port as u32,
            );
        } else {
            let format = b"ShadowSocketProxy: WskSocketConnect attempt slot=%u protocol=%u family=%u type=%u local=wildcard:0 remote=%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%u\0";
            let _ = DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                format.as_ptr().cast::<i8>(),
                index as u32,
                original.protocol as u32,
                original.address_family as u32,
                socket_type as u32,
                original.destination_address[0] as u32,
                original.destination_address[1] as u32,
                original.destination_address[2] as u32,
                original.destination_address[3] as u32,
                original.destination_address[4] as u32,
                original.destination_address[5] as u32,
                original.destination_address[6] as u32,
                original.destination_address[7] as u32,
                original.destination_address[8] as u32,
                original.destination_address[9] as u32,
                original.destination_address[10] as u32,
                original.destination_address[11] as u32,
                original.destination_address[12] as u32,
                original.destination_address[13] as u32,
                original.destination_address[14] as u32,
                original.destination_address[15] as u32,
                original.destination_port as u32,
            );
        }
    }
}

fn debug_connect_result(stage: &[u8], status: NTSTATUS, information: u64) {
    let format = b"ShadowSocketProxy: %s status=0x%08X information=%llu\0";
    unsafe {
        let _ = DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            format.as_ptr().cast::<i8>(),
            stage.as_ptr().cast::<i8>(),
            status as u32,
            information,
        );
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flow_info: u32,
    address: [u8; 16],
    scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ListenerContext {
    family: u8,
    protocol: u8,
    port: u16,
    address: [u8; 16],
}

static WSK_CLIENT_DISPATCH: wsk::WSK_CLIENT_DISPATCH = wsk::WSK_CLIENT_DISPATCH {
    Version: 0x0100,
    Reserved: 0,
    WskClientEvent: Some(wsk_client_event),
};
static WSK_CLIENT_LISTEN_DISPATCH: wsk::WSK_CLIENT_LISTEN_DISPATCH =
    wsk::WSK_CLIENT_LISTEN_DISPATCH {
        WskAcceptEvent: Some(wsk_accept_event),
        WskInspectEvent: None,
        WskAbortEvent: None,
    };
static WSK_CLIENT_DATAGRAM_DISPATCH: wsk::WSK_CLIENT_DATAGRAM_DISPATCH =
    wsk::WSK_CLIENT_DATAGRAM_DISPATCH {
        WskReceiveFromEvent: Some(wsk_receive_from_event),
    };
static WSK_CLIENT_CONNECTION_DISPATCH: wsk::WSK_CLIENT_CONNECTION_DISPATCH =
    wsk::WSK_CLIENT_CONNECTION_DISPATCH {
        WskReceiveEvent: Some(wsk_receive_event),
        WskDisconnectEvent: Some(wsk_disconnect_event),
        WskSendBacklogEvent: None,
    };

static TCP_CONTEXT_V4: ListenerContext = ListenerContext {
    family: 4,
    protocol: IPPROTO_TCP as u8,
    port: 15_000,
    address: [0; 16],
};
static TCP_CONTEXT_V6: ListenerContext = ListenerContext {
    family: 6,
    protocol: IPPROTO_TCP as u8,
    port: 15_000,
    address: [0; 16],
};
static UDP_CONTEXT_V4: ListenerContext = ListenerContext {
    family: 4,
    protocol: IPPROTO_UDP as u8,
    port: 15_000,
    address: [0; 16],
};
static UDP_CONTEXT_V6: ListenerContext = ListenerContext {
    family: 6,
    protocol: IPPROTO_UDP as u8,
    port: 15_000,
    address: [0; 16],
};
static mut WSK_REGISTRATION: MaybeUninit<wsk::WSK_REGISTRATION> = MaybeUninit::uninit();
static mut WSK_PROVIDER_NPI: MaybeUninit<wsk::WSK_PROVIDER_NPI> = MaybeUninit::uninit();
static mut WSK_REGISTERED: bool = false;
static mut WSK_PROVIDER_CAPTURED: bool = false;
static mut DEVICE_OBJECT: PDEVICE_OBJECT = null_mut();

static mut TCP_LISTENER_V4: wsk::PWSK_SOCKET = null_mut();
static mut TCP_LISTENER_V6: wsk::PWSK_SOCKET = null_mut();
static mut UDP_LISTENER_V4: wsk::PWSK_SOCKET = null_mut();
static mut UDP_LISTENER_V6: wsk::PWSK_SOCKET = null_mut();

static mut MAPPING_TIMER: MaybeUninit<KTIMER> = MaybeUninit::uninit();
static mut MAPPING_DPC: MaybeUninit<KDPC> = MaybeUninit::uninit();
static TIMER_INITIALIZED: AtomicBool = AtomicBool::new(false);

static SESSION_LOCK: AtomicBool = AtomicBool::new(false);
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);
static STATIC_EVENT_CALLBACKS_ENABLED: AtomicBool = AtomicBool::new(false);
static SESSION_NONCE: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static SESSION_REQUEST_ID: AtomicU64 = AtomicU64::new(0);
static SESSION_GENERATION: AtomicU64 = AtomicU64::new(0);
static NONCE_SEED: AtomicU32 = AtomicU32::new(0x9E37_79B9);

static PENDING_MAPPING_IRP: AtomicPtr<wdk_sys::IRP> = AtomicPtr::new(null_mut());
static PENDING_MAPPING_DEADLINE: AtomicU64 = AtomicU64::new(0);
static FLOW_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static FLOW_NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
struct StreamForwardContext {
    source: wsk::PWSK_SOCKET,
    indication: wsk::PWSK_DATA_INDICATION,
    busy: AtomicBool,
}

impl StreamForwardContext {
    const fn new() -> Self {
        Self {
            source: null_mut(),
            indication: null_mut(),
            busy: AtomicBool::new(false),
        }
    }
}

#[repr(C)]
struct DatagramForwardContext {
    source: wsk::PWSK_SOCKET,
    indication: wsk::PWSK_DATAGRAM_INDICATION,
    busy: AtomicBool,
}

impl DatagramForwardContext {
    const fn new() -> Self {
        Self {
            source: null_mut(),
            indication: null_mut(),
            busy: AtomicBool::new(false),
        }
    }
}

#[repr(C)]
struct FlowSocketSlot {
    socket: wsk::PWSK_SOCKET,
    outbound: wsk::PWSK_SOCKET,
    udp_listener: wsk::PWSK_SOCKET,
    client_address: [u8; 28],
    client_len: u8,
    close_pending: u8,
    inbound_context: FlowCallbackContext,
    outbound_context: FlowCallbackContext,
    inbound_close: FlowCloseContext,
    outbound_close: FlowCloseContext,
    inbound_forward: StreamForwardContext,
    outbound_forward: StreamForwardContext,
    udp_inbound_forward: DatagramForwardContext,
    udp_outbound_forward: DatagramForwardContext,
}

#[repr(C)]
struct FlowCallbackContext {
    slot: *mut FlowSocketSlot,
    inbound: bool,
}

#[repr(C)]
struct FlowCloseContext {
    slot: *mut FlowSocketSlot,
    outbound: bool,
}

impl FlowSocketSlot {
    const fn new() -> Self {
        Self {
            socket: null_mut(),
            outbound: null_mut(),
            udp_listener: null_mut(),
            client_address: [0; 28],
            client_len: 0,
            close_pending: 0,
            inbound_context: FlowCallbackContext {
                slot: null_mut(),
                inbound: true,
            },
            outbound_context: FlowCallbackContext {
                slot: null_mut(),
                inbound: false,
            },
            inbound_close: FlowCloseContext {
                slot: null_mut(),
                outbound: false,
            },
            outbound_close: FlowCloseContext {
                slot: null_mut(),
                outbound: true,
            },
            inbound_forward: StreamForwardContext::new(),
            outbound_forward: StreamForwardContext::new(),
            udp_inbound_forward: DatagramForwardContext::new(),
            udp_outbound_forward: DatagramForwardContext::new(),
        }
    }
}

static FLOW_TABLE_LOCK: AtomicBool = AtomicBool::new(false);
static mut FLOW_TABLE: FlowTable<FLOW_TABLE_CAPACITY> = FlowTable::new();
static mut FLOW_SLOTS: [FlowSocketSlot; FLOW_TABLE_CAPACITY] =
    [const { FlowSocketSlot::new() }; FLOW_TABLE_CAPACITY];

// The WDK declares this identifier as an extern, but keep the value local so
// callback control requests do not depend on resolving the UUID import symbol.
static WSK_INTERFACE_ID: wsk::NPIID = wsk::NPIID {
    Data1: 0x2227_e803,
    Data2: 0x8d8b,
    Data3: 0x11d4,
    Data4: [0xab, 0xad, 0x00, 0x90, 0x27, 0x71, 0x9e, 0x09],
};

/// The WDM entry point exported by the cdylib.
///
/// # Safety
///
/// Windows invokes this entry point with a valid driver object and registry
/// path during driver initialization. The function validates the driver
/// object before installing any callbacks.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: *mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    if driver.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut device_name = unicode_string(&DEVICE_NAME);
    let mut device = null_mut();
    let status = unsafe {
        IoCreateDevice(
            driver,
            0,
            &mut device_name,
            FILE_DEVICE_NETWORK,
            FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device,
        )
    };
    if status != STATUS_SUCCESS || device.is_null() {
        debug_status(b"IoCreateDevice\0", status);
        return if status == STATUS_SUCCESS {
            STATUS_INSUFFICIENT_RESOURCES
        } else {
            status
        };
    }

    let mut dos_device_name = unicode_string(&DOS_DEVICE_NAME);
    let status = unsafe { IoCreateSymbolicLink(&mut dos_device_name, &mut device_name) };
    if status != STATUS_SUCCESS {
        debug_status(b"IoCreateSymbolicLink\0", status);
        unsafe {
            IoDeleteDevice(device);
        }
        return status;
    }

    unsafe {
        DEVICE_OBJECT = device;
        (*driver).DriverUnload = Some(driver_unload);
        (*driver).MajorFunction[IRP_MJ_CREATE] = Some(dispatch_create);
        (*driver).MajorFunction[IRP_MJ_CLOSE] = Some(dispatch_close);
        (*driver).MajorFunction[IRP_MJ_CLEANUP] = Some(dispatch_cleanup);
        (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL] = Some(dispatch_device_control);
        (*device).Flags &= !DO_DEVICE_INITIALIZING;
    }

    let status = register_wsk();
    if status != STATUS_SUCCESS {
        debug_status(b"register_wsk\0", status);
        unsafe {
            let _ = IoDeleteSymbolicLink(&mut dos_device_name);
            IoDeleteDevice(device);
            DEVICE_OBJECT = null_mut();
        }
        return status;
    }
    STATUS_SUCCESS
}

unsafe extern "C" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    clear_session();
    unregister_wsk();
    let mut dos_device_name = unicode_string(&DOS_DEVICE_NAME);
    unsafe {
        let _ = IoDeleteSymbolicLink(&mut dos_device_name);
        if !DEVICE_OBJECT.is_null() {
            IoDeleteDevice(DEVICE_OBJECT);
            DEVICE_OBJECT = null_mut();
        }
    }
}

unsafe extern "C" fn dispatch_create(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    complete_irp(irp, STATUS_SUCCESS, 0)
}

unsafe extern "C" fn dispatch_close(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    clear_session();
    complete_irp(irp, STATUS_SUCCESS, 0)
}

unsafe extern "C" fn dispatch_cleanup(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    clear_session();
    complete_irp(irp, STATUS_SUCCESS, 0)
}

unsafe extern "C" fn dispatch_device_control(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let stack = unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    };
    if stack.is_null() {
        return complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
    }

    let control = unsafe { (*stack).Parameters.DeviceIoControl };
    let control_code = control.IoControlCode;
    let input_length = control.InputBufferLength as usize;
    let output_length = control.OutputBufferLength as usize;
    let buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer as *mut u8 };
    if buffer.is_null() && (input_length != 0 || output_length != 0) {
        return complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
    }

    match control_code {
        abi::ioctl::OPEN_SESSION => dispatch_open_session(irp, buffer, input_length, output_length),
        abi::ioctl::CLOSE_SESSION => {
            dispatch_close_session(irp, buffer, input_length, output_length)
        }
        abi::ioctl::SUBMIT_REQUEST => {
            dispatch_mapping_wait(irp, buffer, input_length, output_length)
        }
        abi::ioctl::COMPLETE_REQUEST => {
            dispatch_mapping_completion(irp, buffer, input_length, output_length)
        }
        _ => complete_irp(irp, STATUS_INVALID_PARAMETER, 0),
    }
}

unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, information: usize) -> NTSTATUS {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = information as u64;
        IofCompleteRequest(irp, 0);
    }
    status
}

fn dispatch_open_session(
    irp: PIRP,
    buffer: *mut u8,
    input_length: usize,
    output_length: usize,
) -> NTSTATUS {
    let expected_output = size_of::<abi::OpenSessionResponse>();
    if output_length < expected_output {
        return unsafe { complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }

    let request = read_value::<abi::OpenSessionRequest>(buffer, input_length);
    let (request_header, validation) = match request {
        Some(request) => {
            let validation = validate_open_request(&request);
            (request.header, validation)
        }
        None => (
            abi::AbiHeader::response(
                abi::Opcode::OpenSession,
                abi::Status::InvalidAbi,
                abi::SessionNonce::zero(),
                abi::RequestId(0),
                abi::Generation(0),
                expected_output,
            ),
            Err(abi::AbiError::InvalidAbi),
        ),
    };

    let _lock = lock_session();
    let mut status = if validation.is_ok() {
        Some(abi::Status::Ok)
    } else {
        None
    };
    let mut nonce = abi::SessionNonce::zero();
    if status == Some(abi::Status::Ok) {
        if SESSION_ACTIVE.load(Ordering::Acquire) {
            status = Some(abi::Status::InvalidState);
        } else {
            nonce = generate_nonce();
            store_nonce(nonce);
            SESSION_REQUEST_ID.store(request_header.request_id.0, Ordering::Release);
            SESSION_GENERATION.store(request_header.generation.0, Ordering::Release);
            SESSION_ACTIVE.store(true, Ordering::Release);
        }
    }
    let status = status.unwrap_or_else(|| {
        validation
            .err()
            .map(abi::AbiError::status)
            .unwrap_or(abi::Status::InternalError)
    });
    let response = abi::OpenSessionResponse {
        header: abi::AbiHeader::response(
            abi::Opcode::OpenSession,
            status,
            nonce,
            request_header.request_id,
            request_header.generation,
            expected_output,
        ),
        session_nonce: nonce,
    };
    unsafe { write_value(buffer, &response) };
    unsafe { complete_irp(irp, STATUS_SUCCESS, expected_output) }
}

fn dispatch_close_session(
    irp: PIRP,
    buffer: *mut u8,
    input_length: usize,
    output_length: usize,
) -> NTSTATUS {
    let expected_output = size_of::<abi::AbiHeader>();
    if output_length < expected_output {
        return unsafe { complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }

    let request = read_value::<abi::CloseSessionRequest>(buffer, input_length);
    let request_header = request.map(|request| request.header).unwrap_or_else(|| {
        abi::AbiHeader::response(
            abi::Opcode::CloseSession,
            abi::Status::InvalidAbi,
            abi::SessionNonce::zero(),
            abi::RequestId(0),
            abi::Generation(0),
            expected_output,
        )
    });
    let _lock = lock_session();
    let validation = request
        .ok_or(abi::AbiError::InvalidAbi)
        .and_then(|request| validate_close_request(&request));
    let mut status = if validation.is_ok() {
        Some(abi::Status::Ok)
    } else {
        None
    };
    let active_nonce = load_nonce();
    if status == Some(abi::Status::Ok) {
        if !SESSION_ACTIVE.load(Ordering::Acquire) {
            status = Some(abi::Status::InvalidState);
        } else if request_header.session_nonce != active_nonce {
            status = Some(abi::Status::InvalidSession);
        } else {
            let previous_request_id = abi::RequestId(SESSION_REQUEST_ID.load(Ordering::Acquire));
            let previous_generation = abi::Generation(SESSION_GENERATION.load(Ordering::Acquire));
            if request_header
                .validate_next_identity(previous_request_id, previous_generation)
                .is_err()
            {
                status = Some(abi::Status::InvalidIdentity);
            } else {
                fail_active_flow_sync();
                cancel_pending_mapping(abi::Status::Cancelled);
                SESSION_ACTIVE.store(false, Ordering::Release);
                store_nonce(abi::SessionNonce::zero());
                SESSION_REQUEST_ID.store(0, Ordering::Release);
                SESSION_GENERATION.store(0, Ordering::Release);
            }
        }
    }
    let status = status.unwrap_or_else(|| {
        validation
            .err()
            .map(abi::AbiError::status)
            .unwrap_or(abi::Status::InternalError)
    });
    let response = abi::AbiHeader::response(
        abi::Opcode::CloseSession,
        status,
        if status == abi::Status::Ok {
            active_nonce
        } else {
            request_header.session_nonce
        },
        request_header.request_id,
        request_header.generation,
        expected_output,
    );
    unsafe { write_value(buffer, &response) };
    unsafe { complete_irp(irp, STATUS_SUCCESS, expected_output) }
}

fn dispatch_mapping_wait(
    irp: PIRP,
    buffer: *mut u8,
    input_length: usize,
    output_length: usize,
) -> NTSTATUS {
    let expected_output = size_of::<abi::MappingRequest>();
    let request = read_value::<abi::MappingWaitRequest>(buffer, input_length);
    let request_header = request.map(|request| request.header).unwrap_or_else(|| {
        abi::AbiHeader::response(
            abi::Opcode::SubmitRequest,
            abi::Status::InvalidAbi,
            abi::SessionNonce::zero(),
            abi::RequestId(0),
            abi::Generation(0),
            expected_output,
        )
    });

    if output_length < expected_output {
        return unsafe { complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    let validation = request
        .ok_or(abi::AbiError::InvalidAbi)
        .and_then(|request| request.validate(load_nonce()));
    if !SESSION_ACTIVE.load(Ordering::Acquire) {
        return complete_mapping_wait_response(
            irp,
            buffer,
            request_header,
            abi::Status::InvalidSession,
        );
    }
    if let Err(error) = validation {
        return complete_mapping_wait_response(irp, buffer, request_header, error.status());
    }
    if !PENDING_MAPPING_IRP.load(Ordering::Acquire).is_null() {
        return complete_mapping_wait_response(
            irp,
            buffer,
            request_header,
            abi::Status::InvalidState,
        );
    }
    if !pend_mapping_irp(irp) {
        return complete_mapping_wait_response(irp, buffer, request_header, abi::Status::Cancelled);
    }
    PENDING_MAPPING_DEADLINE.store(
        now_100ns().saturating_add(MAPPING_TIMEOUT_100NS),
        Ordering::Release,
    );
    unsafe {
        (*irp).PendingReturned = 1;
    }
    STATUS_PENDING
}

fn dispatch_mapping_completion(
    irp: PIRP,
    buffer: *mut u8,
    input_length: usize,
    output_length: usize,
) -> NTSTATUS {
    let expected_output = size_of::<abi::AbiHeader>();
    if output_length < expected_output {
        return unsafe { complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0) };
    }
    let completion = read_value::<abi::MappingCompletion>(buffer, input_length);
    let request_header = completion
        .map(|completion| completion.header)
        .unwrap_or_else(|| {
            abi::AbiHeader::response(
                abi::Opcode::CompleteRequest,
                abi::Status::InvalidAbi,
                abi::SessionNonce::zero(),
                abi::RequestId(0),
                abi::Generation(0),
                expected_output,
            )
        });
    let status = match completion {
        None => abi::Status::InvalidAbi,
        Some(completion) => handle_mapping_completion(&completion),
    };
    let response = abi::AbiHeader::response(
        abi::Opcode::CompleteRequest,
        status,
        if SESSION_ACTIVE.load(Ordering::Acquire) {
            load_nonce()
        } else {
            request_header.session_nonce
        },
        request_header.request_id,
        request_header.generation,
        expected_output,
    );
    unsafe { write_value(buffer, &response) };
    unsafe { complete_irp(irp, STATUS_SUCCESS, expected_output) }
}

fn complete_mapping_wait_response(
    irp: PIRP,
    buffer: *mut u8,
    request_header: abi::AbiHeader,
    status: abi::Status,
) -> NTSTATUS {
    let response = abi::MappingRequest {
        header: abi::AbiHeader::response(
            abi::Opcode::SubmitRequest,
            status,
            request_header.session_nonce,
            request_header.request_id,
            request_header.generation,
            size_of::<abi::MappingRequest>(),
        ),
        synthetic: zero_mapping_tuple(),
    };
    unsafe { write_value(buffer, &response) };
    unsafe { complete_irp(irp, STATUS_SUCCESS, size_of::<abi::MappingRequest>()) }
}

fn validate_open_request(request: &abi::OpenSessionRequest) -> Result<(), abi::AbiError> {
    request.header.validate_envelope(
        abi::Opcode::OpenSession,
        size_of::<abi::OpenSessionRequest>(),
    )?;
    if !request.header.session_nonce.is_zero() || request.client_nonce.is_zero() {
        return Err(abi::AbiError::InvalidSession);
    }
    if request.header.request_id.0 == 0 || request.header.generation.0 == 0 {
        return Err(abi::AbiError::InvalidIdentity);
    }
    Ok(())
}

fn validate_close_request(request: &abi::CloseSessionRequest) -> Result<(), abi::AbiError> {
    request.header.validate_envelope(
        abi::Opcode::CloseSession,
        size_of::<abi::CloseSessionRequest>(),
    )?;
    if request.header.request_id.0 == 0 || request.header.generation.0 == 0 {
        return Err(abi::AbiError::InvalidIdentity);
    }
    if request.header.session_nonce.is_zero() {
        return Err(abi::AbiError::InvalidSession);
    }
    Ok(())
}

fn read_value<T: Copy>(buffer: *const u8, length: usize) -> Option<T> {
    if buffer.is_null() || length != size_of::<T>() {
        return None;
    }
    let mut value = MaybeUninit::<T>::uninit();
    unsafe {
        copy_nonoverlapping(buffer, value.as_mut_ptr().cast::<u8>(), size_of::<T>());
        Some(value.assume_init())
    }
}

unsafe fn write_value<T: Copy>(buffer: *mut u8, value: &T) {
    unsafe {
        copy_nonoverlapping(value as *const T as *const u8, buffer, size_of::<T>());
    }
}

struct SessionGuard;

struct FlowTableGuard;

fn lock_flow_table() -> FlowTableGuard {
    while FLOW_TABLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    FlowTableGuard
}

impl Drop for FlowTableGuard {
    fn drop(&mut self) {
        FLOW_TABLE_LOCK.store(false, Ordering::Release);
    }
}

fn flow_slot_ptr(index: usize) -> *mut FlowSocketSlot {
    if index >= FLOW_TABLE_CAPACITY {
        return null_mut();
    }
    unsafe { core::ptr::addr_of_mut!(FLOW_SLOTS[index]) }
}

fn flow_slot_index(slot: *mut FlowSocketSlot) -> usize {
    for index in 0..FLOW_TABLE_CAPACITY {
        if flow_slot_ptr(index) == slot {
            return index;
        }
    }
    FLOW_TABLE_CAPACITY
}

unsafe fn flow_slot(index: usize) -> Option<&'static mut FlowSocketSlot> {
    if index >= FLOW_TABLE_CAPACITY {
        None
    } else {
        Some(&mut FLOW_SLOTS[index])
    }
}

fn flow_key(synthetic: abi::MappingTuple, client: &[u8; 28], client_len: u8) -> FlowKey {
    if synthetic.protocol == IPPROTO_UDP as u8 {
        FlowKey::udp(synthetic, *client, client_len)
    } else {
        FlowKey::tcp(synthetic)
    }
}

fn lock_session() -> SessionGuard {
    while SESSION_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    SessionGuard
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        SESSION_LOCK.store(false, Ordering::Release);
    }
}

fn load_nonce() -> abi::SessionNonce {
    let mut bytes = [0u8; abi::SESSION_NONCE_SIZE];
    for (index, word) in SESSION_NONCE.iter().enumerate() {
        bytes[index * 8..(index + 1) * 8]
            .copy_from_slice(&word.load(Ordering::Acquire).to_ne_bytes());
    }
    abi::SessionNonce::new(bytes)
}

fn store_nonce(nonce: abi::SessionNonce) {
    for (index, word) in SESSION_NONCE.iter().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&nonce.bytes[index * 8..(index + 1) * 8]);
        word.store(u64::from_ne_bytes(bytes), Ordering::Release);
    }
}

fn clear_session() {
    let _lock = lock_session();
    cancel_pending_mapping(abi::Status::Cancelled);
    fail_active_flow_sync();
    SESSION_ACTIVE.store(false, Ordering::Release);
    store_nonce(abi::SessionNonce::zero());
    SESSION_REQUEST_ID.store(0, Ordering::Release);
    SESSION_GENERATION.store(0, Ordering::Release);
}

fn generate_nonce() -> abi::SessionNonce {
    let counter = now_100ns();
    let address_entropy = (&counter as *const u64 as usize) as u64;
    let mut seed = NONCE_SEED.fetch_add(
        (counter as u32)
            .wrapping_add(address_entropy as u32)
            .wrapping_add(0xA5A5_5A5A),
        Ordering::Relaxed,
    ) ^ counter as u32
        ^ (counter >> 32) as u32
        ^ address_entropy as u32;
    if seed == 0 {
        seed = 1;
    }
    let mut nonce = [0u8; abi::SESSION_NONCE_SIZE];
    for chunk in nonce.chunks_exact_mut(size_of::<u32>()) {
        let value = unsafe { RtlRandomEx(&mut seed) };
        chunk.copy_from_slice(&value.to_ne_bytes());
    }
    if nonce.iter().all(|byte| *byte == 0) {
        nonce[0] = 1;
    }
    abi::SessionNonce::new(nonce)
}

fn unicode_string(buffer: &[u16]) -> wdk_sys::UNICODE_STRING {
    wdk_sys::UNICODE_STRING {
        Length: (buffer.len() * 2) as u16,
        MaximumLength: (buffer.len() * 2) as u16,
        Buffer: buffer.as_ptr() as *mut u16,
    }
}

unsafe extern "C" fn wsk_client_event(
    _client_context: *mut c_void,
    _event_type: u32,
    _information: *mut c_void,
    _information_length: u64,
) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "C" fn sync_irp_completion(
    _device: PDEVICE_OBJECT,
    _irp: PIRP,
    context: PVOID,
) -> NTSTATUS {
    if !context.is_null() {
        unsafe {
            KeSetEvent(context.cast::<KEVENT>(), 2, 0);
        }
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

unsafe extern "C" fn close_irp_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: PVOID,
) -> NTSTATUS {
    if !context.is_null() {
        let close = unsafe { &*context.cast::<FlowCloseContext>() };
        if !close.slot.is_null() {
            let index = flow_slot_index(close.slot);
            finish_flow_close(index, close.outbound);
        }
    }
    unsafe {
        IoFreeIrp(irp);
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

fn now_100ns() -> u64 {
    let mut qpc_timestamp = 0u64;
    unsafe { KeQueryInterruptTimePrecise(&mut qpc_timestamp) }
}

fn synchronous_wsk_call<F>(operation: F) -> Result<(NTSTATUS, u64), NTSTATUS>
where
    F: FnOnce(PIRP) -> NTSTATUS,
{
    let mut event = unsafe { MaybeUninit::<KEVENT>::zeroed().assume_init() };
    unsafe {
        KeInitializeEvent(&mut event, 1, 0);
    }
    let irp = unsafe { IoAllocateIrp(1, 0) };
    if irp.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let device = unsafe { DEVICE_OBJECT };
    let set_status = unsafe {
        IoSetCompletionRoutineEx(
            device,
            irp,
            Some(sync_irp_completion),
            (&mut event as *mut KEVENT).cast(),
            1,
            1,
            1,
        )
    };
    if set_status != STATUS_SUCCESS {
        unsafe {
            IoFreeIrp(irp);
        }
        return Err(set_status);
    }
    let _ = operation(irp);
    unsafe {
        let _ = KeWaitForSingleObject((&mut event as *mut KEVENT).cast(), 0, 0, 0, null_mut());
        let status = (*irp).IoStatus.__bindgen_anon_1.Status;
        let information = (*irp).IoStatus.Information as u64;
        IoFreeIrp(irp);
        Ok((status, information))
    }
}

fn provider_npi() -> Option<&'static wsk::WSK_PROVIDER_NPI> {
    unsafe {
        if !WSK_PROVIDER_CAPTURED {
            None
        } else {
            Some(&*core::ptr::addr_of!(WSK_PROVIDER_NPI).cast::<wsk::WSK_PROVIDER_NPI>())
        }
    }
}

fn set_static_event_callbacks() -> NTSTATUS {
    let Some(provider) = provider_npi() else {
        return STATUS_NOT_SUPPORTED;
    };
    if provider.Dispatch.is_null() {
        return STATUS_NOT_SUPPORTED;
    }

    let Some(control_client) = (unsafe { (*provider.Dispatch).WskControlClient }) else {
        return STATUS_NOT_SUPPORTED;
    };
    let mut control = wsk::WSK_EVENT_CALLBACK_CONTROL {
        NpiId: core::ptr::addr_of!(WSK_INTERFACE_ID),
        EventMask: WSK_EVENT_ACCEPT | WSK_EVENT_RECEIVE_FROM,
    };
    let status = unsafe {
        control_client(
            provider.Client,
            WSK_SET_STATIC_EVENT_CALLBACKS,
            size_of::<wsk::WSK_EVENT_CALLBACK_CONTROL>() as u64,
            (&mut control as *mut wsk::WSK_EVENT_CALLBACK_CONTROL).cast(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };
    STATIC_EVENT_CALLBACKS_ENABLED.store(status == STATUS_SUCCESS, Ordering::Release);
    status
}

fn enable_socket_event_callbacks(socket: wsk::PWSK_SOCKET, event_mask: u32) -> bool {
    if socket.is_null() || event_mask == 0 {
        return false;
    }
    if STATIC_EVENT_CALLBACKS_ENABLED.load(Ordering::Acquire) {
        return true;
    }
    let dispatch = unsafe {
        if (*socket).Dispatch.is_null() {
            return false;
        }
        &*((*socket).Dispatch as *const wsk::WSK_PROVIDER_BASIC_DISPATCH)
    };
    let Some(control_socket) = dispatch.WskControlSocket else {
        return false;
    };
    let mut control = wsk::WSK_EVENT_CALLBACK_CONTROL {
        NpiId: core::ptr::addr_of!(WSK_INTERFACE_ID),
        EventMask: event_mask,
    };
    let status = unsafe {
        control_socket(
            socket,
            WSK_SET_OPTION,
            SO_WSK_EVENT_CALLBACK,
            SOL_SOCKET,
            size_of::<wsk::WSK_EVENT_CALLBACK_CONTROL>() as u64,
            (&mut control as *mut wsk::WSK_EVENT_CALLBACK_CONTROL).cast(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };
    if status != STATUS_SUCCESS {
        debug_status(b"WskControlSocket\0", status);
    }
    status == STATUS_SUCCESS
}

fn create_wsk_socket(
    family: u16,
    socket_type: u16,
    protocol: u32,
    flags: u32,
    context: PVOID,
    dispatch: *const c_void,
) -> Option<wsk::PWSK_SOCKET> {
    let provider = provider_npi()?;
    if provider.Dispatch.is_null() {
        return None;
    }
    let create = unsafe { (*provider.Dispatch).WskSocket }?;
    let result = synchronous_wsk_call(|irp| unsafe {
        create(
            provider.Client,
            family,
            socket_type,
            protocol,
            flags,
            context,
            dispatch,
            null_mut(),
            null_mut(),
            null_mut(),
            irp.cast(),
        )
    })
    .ok()?;
    if result.0 != STATUS_SUCCESS || result.1 == 0 {
        return None;
    }
    Some(result.1 as usize as wsk::PWSK_SOCKET)
}

fn bind_socket(socket: wsk::PWSK_SOCKET, family: u16, protocol: u32) -> bool {
    if socket.is_null() {
        return false;
    }
    if unsafe { (*socket).Dispatch.is_null() } {
        return false;
    }
    let result = if protocol == IPPROTO_TCP {
        let dispatch = unsafe { (*socket).Dispatch as *const wsk::WSK_PROVIDER_LISTEN_DISPATCH };
        let Some(bind) = (unsafe { (*dispatch).WskBind }) else {
            return false;
        };
        if family == AF_INET {
            let mut address = SockAddrIn {
                family,
                port: 15_000u16.to_be(),
                address: [0, 0, 0, 0],
                zero: [0; 8],
            };
            synchronous_wsk_call(|irp| unsafe {
                bind(
                    socket,
                    (&mut address as *mut SockAddrIn).cast(),
                    0,
                    irp.cast(),
                )
            })
        } else {
            let mut address = SockAddrIn6 {
                family,
                port: 15_000u16.to_be(),
                flow_info: 0,
                address: [0; 16],
                scope_id: 0,
            };
            synchronous_wsk_call(|irp| unsafe {
                bind(
                    socket,
                    (&mut address as *mut SockAddrIn6).cast(),
                    0,
                    irp.cast(),
                )
            })
        }
    } else {
        let dispatch = unsafe { (*socket).Dispatch as *const wsk::WSK_PROVIDER_DATAGRAM_DISPATCH };
        let Some(bind) = (unsafe { (*dispatch).WskBind }) else {
            return false;
        };
        if family == AF_INET {
            let mut address = SockAddrIn {
                family,
                port: 15_000u16.to_be(),
                address: [0, 0, 0, 0],
                zero: [0; 8],
            };
            synchronous_wsk_call(|irp| unsafe {
                bind(
                    socket,
                    (&mut address as *mut SockAddrIn).cast(),
                    0,
                    irp.cast(),
                )
            })
        } else {
            let mut address = SockAddrIn6 {
                family,
                port: 15_000u16.to_be(),
                flow_info: 0,
                address: [0; 16],
                scope_id: 0,
            };
            synchronous_wsk_call(|irp| unsafe {
                bind(
                    socket,
                    (&mut address as *mut SockAddrIn6).cast(),
                    0,
                    irp.cast(),
                )
            })
        }
    };
    matches!(result, Ok((STATUS_SUCCESS, _)))
}

fn setup_listener(
    family: u16,
    protocol: u32,
    context: &'static ListenerContext,
) -> Option<wsk::PWSK_SOCKET> {
    let (socket_type, flags, dispatch) = if protocol == IPPROTO_TCP {
        (
            SOCK_STREAM,
            WSK_FLAG_LISTEN_SOCKET,
            (&WSK_CLIENT_LISTEN_DISPATCH as *const wsk::WSK_CLIENT_LISTEN_DISPATCH)
                .cast::<c_void>(),
        )
    } else {
        (
            SOCK_DGRAM,
            WSK_FLAG_DATAGRAM_SOCKET,
            (&WSK_CLIENT_DATAGRAM_DISPATCH as *const wsk::WSK_CLIENT_DATAGRAM_DISPATCH)
                .cast::<c_void>(),
        )
    };
    let socket = create_wsk_socket(
        family,
        socket_type,
        protocol,
        flags,
        (context as *const ListenerContext).cast_mut().cast(),
        dispatch,
    )?;
    if !bind_socket(socket, family, protocol) {
        let _ = close_socket_sync(socket);
        return None;
    }
    let event_mask = if protocol == IPPROTO_TCP {
        WSK_EVENT_ACCEPT
    } else {
        WSK_EVENT_RECEIVE_FROM
    };
    if !enable_socket_event_callbacks(socket, event_mask) {
        let _ = close_socket_sync(socket);
        return None;
    }
    Some(socket)
}

fn close_socket_sync(socket: wsk::PWSK_SOCKET) -> bool {
    if socket.is_null() {
        return true;
    }
    if unsafe { (*socket).Dispatch.is_null() } {
        return false;
    }
    let dispatch = unsafe { (*socket).Dispatch as *const wsk::WSK_PROVIDER_BASIC_DISPATCH };
    let Some(close) = (unsafe { (*dispatch).WskCloseSocket }) else {
        return false;
    };
    matches!(
        synchronous_wsk_call(|irp| unsafe { close(socket, irp.cast()) }),
        Ok((STATUS_SUCCESS, _))
    )
}

fn close_socket_async(socket: wsk::PWSK_SOCKET, context: &mut FlowCloseContext) -> bool {
    if socket.is_null() {
        return true;
    }
    if unsafe { (*socket).Dispatch.is_null() } {
        return false;
    }
    let dispatch = unsafe { (*socket).Dispatch as *const wsk::WSK_PROVIDER_BASIC_DISPATCH };
    let Some(close) = (unsafe { (*dispatch).WskCloseSocket }) else {
        return false;
    };
    let irp = unsafe { IoAllocateIrp(1, 0) };
    if irp.is_null() {
        return false;
    }
    let device = unsafe { DEVICE_OBJECT };
    let set_status = unsafe {
        IoSetCompletionRoutineEx(
            device,
            irp,
            Some(close_irp_completion),
            (context as *mut FlowCloseContext).cast(),
            1,
            1,
            1,
        )
    };
    if set_status != STATUS_SUCCESS {
        unsafe {
            IoFreeIrp(irp);
        }
        return false;
    }
    let status = unsafe { close(socket, irp.cast()) };
    if status != STATUS_SUCCESS && status != STATUS_PENDING {
        unsafe {
            IoFreeIrp(irp);
        }
        return false;
    }
    true
}

fn close_listener_slot(slot: *mut wsk::PWSK_SOCKET) {
    let socket = unsafe { *slot };
    if !socket.is_null() {
        let _ = close_socket_sync(socket);
        unsafe {
            *slot = null_mut();
        }
    }
}

fn close_all_listeners() {
    close_listener_slot(core::ptr::addr_of_mut!(TCP_LISTENER_V4));
    close_listener_slot(core::ptr::addr_of_mut!(TCP_LISTENER_V6));
    close_listener_slot(core::ptr::addr_of_mut!(UDP_LISTENER_V4));
    close_listener_slot(core::ptr::addr_of_mut!(UDP_LISTENER_V6));
}

fn initialize_mapping_timer() {
    unsafe {
        KeInitializeTimerEx(core::ptr::addr_of_mut!(MAPPING_TIMER).cast(), 0);
        KeInitializeDpc(
            core::ptr::addr_of_mut!(MAPPING_DPC).cast(),
            Some(mapping_timer_dpc),
            null_mut(),
        );
        let due = LARGE_INTEGER {
            QuadPart: -TIMER_PERIOD_100NS,
        };
        KeSetTimerEx(
            core::ptr::addr_of_mut!(MAPPING_TIMER).cast(),
            due,
            TIMER_PERIOD_MS,
            core::ptr::addr_of_mut!(MAPPING_DPC).cast(),
        );
    }
    TIMER_INITIALIZED.store(true, Ordering::Release);
}

fn stop_mapping_timer() {
    if TIMER_INITIALIZED.swap(false, Ordering::AcqRel) {
        unsafe {
            KeCancelTimer(core::ptr::addr_of_mut!(MAPPING_TIMER).cast());
            KeFlushQueuedDpcs();
        }
    }
}

unsafe extern "C" fn mapping_timer_dpc(
    _dpc: *mut KDPC,
    _context: PVOID,
    _system_argument1: PVOID,
    _system_argument2: PVOID,
) {
    expire_mapping_state();
}

fn expire_mapping_state() {
    let now = now_100ns();
    let pending = PENDING_MAPPING_IRP.load(Ordering::Acquire);
    if !pending.is_null()
        && PENDING_MAPPING_DEADLINE.load(Ordering::Acquire) != 0
        && now >= PENDING_MAPPING_DEADLINE.load(Ordering::Acquire)
    {
        if let Some(irp) = take_pending_mapping_irp() {
            complete_mapping_wait_irp(irp, abi::Status::Timeout);
        }
    }

    let mut expired = [false; FLOW_TABLE_CAPACITY];
    {
        let _lock = lock_flow_table();
        for index in 0..FLOW_TABLE_CAPACITY {
            if unsafe { FLOW_TABLE.is_expired(index, now) } {
                expired[index] = true;
            }
        }
    }
    for (index, is_expired) in expired.iter().enumerate() {
        if *is_expired {
            begin_flow_close_async(index);
        }
    }
}

fn pend_mapping_irp(irp: PIRP) -> bool {
    let mut old_irql: KIRQL = 0;
    unsafe {
        IoAcquireCancelSpinLock(&mut old_irql);
        if (*irp).Cancel != 0 || !PENDING_MAPPING_IRP.load(Ordering::Acquire).is_null() {
            IoReleaseCancelSpinLock(old_irql);
            return false;
        }
        (*irp).CancelRoutine = Some(mapping_cancel_routine);
        PENDING_MAPPING_IRP.store(irp, Ordering::Release);
        IoReleaseCancelSpinLock(old_irql);
    }
    true
}

fn take_pending_mapping_irp() -> Option<PIRP> {
    let mut old_irql: KIRQL = 0;
    unsafe {
        IoAcquireCancelSpinLock(&mut old_irql);
        let irp = PENDING_MAPPING_IRP.swap(null_mut(), Ordering::AcqRel);
        if !irp.is_null() {
            (*irp).CancelRoutine = None;
        }
        IoReleaseCancelSpinLock(old_irql);
        PENDING_MAPPING_DEADLINE.store(0, Ordering::Release);
        (!irp.is_null()).then_some(irp)
    }
}

unsafe extern "C" fn mapping_cancel_routine(_device: PDEVICE_OBJECT, irp: PIRP) {
    if PENDING_MAPPING_IRP
        .compare_exchange(irp, null_mut(), Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        PENDING_MAPPING_DEADLINE.store(0, Ordering::Release);
    }
    let cancel_irql = unsafe { (*irp).CancelIrql };
    unsafe {
        IoReleaseCancelSpinLock(cancel_irql);
        complete_irp(irp, STATUS_CANCELLED, 0);
    }
}

fn cancel_pending_mapping(status: abi::Status) {
    if let Some(irp) = take_pending_mapping_irp() {
        complete_mapping_wait_irp(irp, status);
    }
}

fn complete_mapping_wait_irp(irp: PIRP, status: abi::Status) {
    let buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer as *mut u8 };
    let request_header =
        read_value::<abi::MappingWaitRequest>(buffer, size_of::<abi::MappingWaitRequest>())
            .map(|request| request.header)
            .unwrap_or_else(|| {
                abi::AbiHeader::response(
                    abi::Opcode::SubmitRequest,
                    status,
                    load_nonce(),
                    abi::RequestId(0),
                    abi::Generation(0),
                    size_of::<abi::MappingRequest>(),
                )
            });
    let _ = complete_mapping_wait_response(irp, buffer, request_header, status);
}

fn zero_mapping_tuple() -> abi::MappingTuple {
    abi::MappingTuple {
        protocol: 0,
        address_family: 0,
        reserved: 0,
        source_port: 0,
        destination_port: 0,
        source_address: [0; 16],
        destination_address: [0; 16],
    }
}

enum FlowReservation {
    New(usize),
    Existing(usize),
    Full,
}

fn initialize_flow_slots() {
    let _lock = lock_flow_table();
    unsafe {
        for index in 0..FLOW_TABLE_CAPACITY {
            let slot = &mut FLOW_SLOTS[index];
            slot.inbound_context.slot = flow_slot_ptr(index);
            slot.outbound_context.slot = flow_slot_ptr(index);
            slot.inbound_close.slot = flow_slot_ptr(index);
            slot.outbound_close.slot = flow_slot_ptr(index);
        }
    }
}

fn reserve_flow(
    socket: wsk::PWSK_SOCKET,
    synthetic: abi::MappingTuple,
    client_address: [u8; 28],
    client_len: u8,
    udp_listener: wsk::PWSK_SOCKET,
) -> FlowReservation {
    if !SESSION_ACTIVE.load(Ordering::Acquire) {
        return FlowReservation::Full;
    }
    let key = flow_key(synthetic, &client_address, client_len);
    let result = {
        let _lock = lock_flow_table();
        let request_id = abi::RequestId(FLOW_NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let generation = abi::Generation(FLOW_NEXT_GENERATION.fetch_add(1, Ordering::Relaxed));
        let deadline = now_100ns().saturating_add(MAPPING_TIMEOUT_100NS);
        let result = unsafe { FLOW_TABLE.reserve(key, request_id, generation, deadline) };
        if let ReserveResult::New(index) = result {
            if PENDING_MAPPING_IRP.load(Ordering::Acquire).is_null() {
                unsafe {
                    FLOW_TABLE.release(index);
                }
                return FlowReservation::Full;
            }
            unsafe {
                let slot = &mut FLOW_SLOTS[index];
                slot.socket = if synthetic.protocol as u32 == IPPROTO_UDP {
                    null_mut()
                } else {
                    socket
                };
                slot.outbound = null_mut();
                slot.udp_listener = udp_listener;
                slot.client_address = client_address;
                slot.client_len = client_len;
                slot.close_pending = 0;
                slot.inbound_forward = StreamForwardContext::new();
                slot.outbound_forward = StreamForwardContext::new();
                slot.udp_inbound_forward = DatagramForwardContext::new();
                slot.udp_outbound_forward = DatagramForwardContext::new();
            }
        }
        result
    };
    match result {
        ReserveResult::New(index) => {
            if publish_mapping_request(index) {
                FlowReservation::New(index)
            } else {
                close_slot_sync(index);
                FlowReservation::Full
            }
        }
        ReserveResult::Existing(index) => FlowReservation::Existing(index),
        ReserveResult::Full => FlowReservation::Full,
    }
}

fn publish_mapping_request(index: usize) -> bool {
    let Some(irp) = take_pending_mapping_irp() else {
        return false;
    };
    let Some(entry) = ({
        let _lock = lock_flow_table();
        unsafe { FLOW_TABLE.get(index) }
    }) else {
        complete_mapping_wait_irp(irp, abi::Status::Cancelled);
        return false;
    };
    if entry.state != FlowState::AwaitingMapping {
        complete_mapping_wait_irp(irp, abi::Status::Cancelled);
        return false;
    }
    let request = abi::MappingRequest {
        header: abi::AbiHeader::response(
            abi::Opcode::SubmitRequest,
            abi::Status::Ok,
            load_nonce(),
            entry.request_id,
            entry.generation,
            size_of::<abi::MappingRequest>(),
        ),
        synthetic: entry.key.synthetic,
    };
    let buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer as *mut u8 };
    unsafe {
        write_value(buffer, &request);
        complete_irp(irp, STATUS_SUCCESS, size_of::<abi::MappingRequest>());
    }
    true
}

fn reset_flow_slot(slot: &mut FlowSocketSlot) {
    slot.socket = null_mut();
    slot.outbound = null_mut();
    slot.udp_listener = null_mut();
    slot.client_address = [0; 28];
    slot.client_len = 0;
    slot.close_pending = 0;
    slot.inbound_forward = StreamForwardContext::new();
    slot.outbound_forward = StreamForwardContext::new();
    slot.udp_inbound_forward = DatagramForwardContext::new();
    slot.udp_outbound_forward = DatagramForwardContext::new();
}

fn close_slot_sync(index: usize) {
    let (socket, outbound) = {
        let _lock = lock_flow_table();
        let Some(entry) = (unsafe { FLOW_TABLE.get(index) }) else {
            return;
        };
        if entry.state == FlowState::Closing {
            return;
        }
        unsafe {
            let _ = FLOW_TABLE.mark_closing(index);
            let slot = &mut FLOW_SLOTS[index];
            (slot.socket, slot.outbound)
        }
    };
    if !socket.is_null() {
        let _ = close_socket_sync(socket);
    }
    if !outbound.is_null() {
        let _ = close_socket_sync(outbound);
    }
    let _lock = lock_flow_table();
    unsafe {
        FLOW_TABLE.release(index);
        reset_flow_slot(&mut FLOW_SLOTS[index]);
    }
}

fn begin_flow_close_async(index: usize) {
    let (socket, outbound) = {
        let _lock = lock_flow_table();
        let Some(entry) = (unsafe { FLOW_TABLE.get(index) }) else {
            return;
        };
        if entry.state == FlowState::Closing {
            return;
        }
        let Some(_) = (unsafe { FLOW_TABLE.mark_closing(index) }) else {
            return;
        };
        unsafe {
            let slot = &mut FLOW_SLOTS[index];
            slot.close_pending = 0;
            (slot.socket, slot.outbound)
        }
    };
    if socket.is_null() && outbound.is_null() {
        let _lock = lock_flow_table();
        unsafe {
            FLOW_TABLE.release(index);
            reset_flow_slot(&mut FLOW_SLOTS[index]);
        }
        return;
    }
    if !outbound.is_null() {
        unsafe {
            FLOW_SLOTS[index].close_pending = FLOW_SLOTS[index].close_pending.saturating_add(1);
        }
        if !close_socket_async(outbound, unsafe { &mut FLOW_SLOTS[index].outbound_close }) {
            finish_flow_close(index, true);
        }
    }
    if !socket.is_null() {
        unsafe {
            FLOW_SLOTS[index].close_pending = FLOW_SLOTS[index].close_pending.saturating_add(1);
        }
        if !close_socket_async(socket, unsafe { &mut FLOW_SLOTS[index].inbound_close }) {
            finish_flow_close(index, false);
        }
    }
}

fn finish_flow_close(index: usize, outbound: bool) {
    let _lock = lock_flow_table();
    unsafe {
        let Some(slot) = flow_slot(index) else {
            return;
        };
        if outbound {
            slot.outbound = null_mut();
        } else {
            slot.socket = null_mut();
        }
        slot.close_pending = slot.close_pending.saturating_sub(1);
        if slot.close_pending == 0 {
            FLOW_TABLE.release(index);
            reset_flow_slot(slot);
        }
    }
}

fn fail_active_flow_sync() {
    let mut index = 0;
    while index < FLOW_TABLE_CAPACITY {
        let active = {
            let _lock = lock_flow_table();
            unsafe { FLOW_TABLE.get(index).is_some() }
        };
        if active {
            close_slot_sync(index);
        }
        index += 1;
    }
}

fn handle_mapping_completion(completion: &abi::MappingCompletion) -> abi::Status {
    if !SESSION_ACTIVE.load(Ordering::Acquire) {
        return abi::Status::InvalidSession;
    }
    let nonce = load_nonce();
    if completion.header.session_nonce != nonce {
        return abi::Status::InvalidSession;
    }
    let (index, entry) = {
        let _lock = lock_flow_table();
        let mut found = None;
        for index in 0..FLOW_TABLE_CAPACITY {
            if let Some(entry) = unsafe { FLOW_TABLE.get(index) } {
                if entry.request_id == completion.header.request_id
                    && entry.generation == completion.header.generation
                {
                    found = Some((index, entry));
                    break;
                }
            }
        }
        let Some(found) = found else {
            return abi::Status::InvalidIdentity;
        };
        found
    };
    if entry.state != FlowState::AwaitingMapping {
        return abi::Status::Cancelled;
    }
    if let Err(error) = completion.validate(
        nonce,
        entry.request_id,
        entry.generation,
        entry.key.synthetic,
    ) {
        close_slot_sync(index);
        return error.status();
    }
    {
        let _lock = lock_flow_table();
        if unsafe { !FLOW_TABLE.mark_completing(index, entry.request_id, entry.generation) } {
            return abi::Status::Cancelled;
        }
    }
    let outbound = create_outbound_socket(&completion.original, index);
    let Some(outbound) = outbound else {
        close_slot_sync(index);
        return abi::Status::ResourceUnavailable;
    };
    let installed = {
        let _lock = lock_flow_table();
        unsafe {
            match flow_slot(index) {
                Some(slot)
                    if FLOW_TABLE.mark_mapped(
                        index,
                        entry.request_id,
                        entry.generation,
                        now_100ns().saturating_add(FLOW_IDLE_TIMEOUT_100NS),
                    ) =>
                {
                    slot.outbound = outbound;
                    true
                }
                _ => false,
            }
        }
    };
    if !installed {
        let _ = close_socket_sync(outbound);
        return abi::Status::Cancelled;
    }
    abi::Status::Ok
}

fn create_outbound_socket(original: &abi::MappingTuple, index: usize) -> Option<wsk::PWSK_SOCKET> {
    let Some(provider) = provider_npi() else {
        debug_status(b"outbound provider_npi\0", STATUS_NOT_SUPPORTED);
        return None;
    };
    if provider.Dispatch.is_null() {
        debug_status(b"outbound provider dispatch\0", STATUS_NOT_SUPPORTED);
        return None;
    }
    let Some(connect) = (unsafe { (*provider.Dispatch).WskSocketConnect }) else {
        debug_status(b"WskSocketConnect dispatch\0", STATUS_NOT_SUPPORTED);
        return None;
    };
    let socket_type = if original.protocol == IPPROTO_TCP as u8 {
        SOCK_STREAM
    } else {
        SOCK_DGRAM
    };
    debug_connect_attempt(original, index, socket_type);
    match original.address_family {
        4 => {
            let mut local = SockAddrIn {
                family: AF_INET,
                port: 0,
                address: [0; 4],
                zero: [0; 8],
            };
            let mut remote = SockAddrIn {
                family: AF_INET,
                port: original.destination_port.to_be(),
                address: [
                    original.destination_address[0],
                    original.destination_address[1],
                    original.destination_address[2],
                    original.destination_address[3],
                ],
                zero: [0; 8],
            };
            let result = match synchronous_wsk_call(|irp| unsafe {
                connect(
                    provider.Client,
                    socket_type,
                    original.protocol as u32,
                    (&mut local as *mut SockAddrIn).cast(),
                    (&mut remote as *mut SockAddrIn).cast(),
                    0,
                    core::ptr::addr_of_mut!(FLOW_SLOTS[index].outbound_context).cast(),
                    &WSK_CLIENT_CONNECTION_DISPATCH,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    irp.cast(),
                )
            }) {
                Ok(result) => result,
                Err(status) => {
                    debug_connect_result(b"WskSocketConnect IPv4 dispatch\0", status, 0);
                    return None;
                }
            };
            if result.0 == STATUS_SUCCESS && result.1 != 0 {
                let socket = result.1 as usize as wsk::PWSK_SOCKET;
                if enable_socket_event_callbacks(socket, WSK_EVENT_RECEIVE | WSK_EVENT_DISCONNECT) {
                    debug_connect_result(b"WskSocketConnect IPv4 success\0", result.0, result.1);
                    Some(socket)
                } else {
                    debug_status(
                        b"WskSocketConnect IPv4 callback setup\0",
                        STATUS_NOT_SUPPORTED,
                    );
                    let _ = close_socket_sync(socket);
                    None
                }
            } else {
                debug_connect_result(b"WskSocketConnect IPv4 completion\0", result.0, result.1);
                None
            }
        }
        6 => {
            let mut local = SockAddrIn6 {
                family: AF_INET6,
                port: 0,
                flow_info: 0,
                address: [0; 16],
                scope_id: 0,
            };
            let mut remote = SockAddrIn6 {
                family: AF_INET6,
                port: original.destination_port.to_be(),
                flow_info: 0,
                address: original.destination_address,
                scope_id: 0,
            };
            let result = match synchronous_wsk_call(|irp| unsafe {
                connect(
                    provider.Client,
                    socket_type,
                    original.protocol as u32,
                    (&mut local as *mut SockAddrIn6).cast(),
                    (&mut remote as *mut SockAddrIn6).cast(),
                    0,
                    core::ptr::addr_of_mut!(FLOW_SLOTS[index].outbound_context).cast(),
                    &WSK_CLIENT_CONNECTION_DISPATCH,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    irp.cast(),
                )
            }) {
                Ok(result) => result,
                Err(status) => {
                    debug_connect_result(b"WskSocketConnect IPv6 dispatch\0", status, 0);
                    return None;
                }
            };
            if result.0 == STATUS_SUCCESS && result.1 != 0 {
                let socket = result.1 as usize as wsk::PWSK_SOCKET;
                if enable_socket_event_callbacks(socket, WSK_EVENT_RECEIVE | WSK_EVENT_DISCONNECT) {
                    debug_connect_result(b"WskSocketConnect IPv6 success\0", result.0, result.1);
                    Some(socket)
                } else {
                    debug_status(
                        b"WskSocketConnect IPv6 callback setup\0",
                        STATUS_NOT_SUPPORTED,
                    );
                    let _ = close_socket_sync(socket);
                    None
                }
            } else {
                debug_connect_result(b"WskSocketConnect IPv6 completion\0", result.0, result.1);
                None
            }
        }
        _ => {
            debug_status(b"WskSocketConnect family\0", STATUS_INVALID_PARAMETER);
            None
        }
    }
}

fn tuple_from_addresses(
    protocol: u8,
    local: *const wsk::sockaddr,
    remote: *const wsk::sockaddr,
) -> Option<abi::MappingTuple> {
    if local.is_null() || remote.is_null() {
        return None;
    }

    let family = unsafe { (*local).sa_family };
    if family != unsafe { (*remote).sa_family } {
        return None;
    }
    match family {
        AF_INET => {
            let local = unsafe { &*(local.cast::<SockAddrIn>()) };
            let remote = unsafe { &*(remote.cast::<SockAddrIn>()) };
            Some(abi::MappingTuple {
                protocol,
                address_family: 4,
                reserved: 0,
                source_port: u16::from_be(remote.port),
                destination_port: u16::from_be(local.port),
                source_address: [
                    remote.address[0],
                    remote.address[1],
                    remote.address[2],
                    remote.address[3],
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                destination_address: [
                    local.address[0],
                    local.address[1],
                    local.address[2],
                    local.address[3],
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            })
        }
        AF_INET6 => {
            let local = unsafe { &*(local.cast::<SockAddrIn6>()) };
            let remote = unsafe { &*(remote.cast::<SockAddrIn6>()) };
            Some(abi::MappingTuple {
                protocol,
                address_family: 6,
                reserved: 0,
                source_port: u16::from_be(remote.port),
                destination_port: u16::from_be(local.port),
                source_address: remote.address,
                destination_address: local.address,
            })
        }
        _ => None,
    }
}

fn listener_for_context(context: &ListenerContext) -> wsk::PWSK_SOCKET {
    unsafe {
        if context.protocol as u32 == IPPROTO_TCP {
            if context.family == 4 {
                TCP_LISTENER_V4
            } else {
                TCP_LISTENER_V6
            }
        } else if context.family == 4 {
            UDP_LISTENER_V4
        } else {
            UDP_LISTENER_V6
        }
    }
}

fn udp_client_bytes(remote: wsk::PSOCKADDR, family: u8) -> Option<([u8; 28], u8)> {
    if remote.is_null() {
        return None;
    }
    let length = if family == 4 {
        size_of::<SockAddrIn>()
    } else {
        size_of::<SockAddrIn6>()
    };
    let mut bytes = [0u8; 28];
    unsafe {
        copy_nonoverlapping(remote.cast::<u8>(), bytes.as_mut_ptr(), length);
    }
    Some((bytes, length as u8))
}

fn touch_flow(index: usize) {
    let _lock = lock_flow_table();
    unsafe {
        let _ = FLOW_TABLE.touch(index, now_100ns().saturating_add(FLOW_IDLE_TIMEOUT_100NS));
    }
}

unsafe extern "C" fn wsk_accept_event(
    socket_context: PVOID,
    _flags: u32,
    local_address: wsk::PSOCKADDR,
    remote_address: wsk::PSOCKADDR,
    accept_socket: wsk::PWSK_SOCKET,
    accept_socket_context: *mut PVOID,
    accept_socket_dispatch: *mut *const wsk::WSK_CLIENT_CONNECTION_DISPATCH,
) -> NTSTATUS {
    if accept_socket.is_null() || remote_address.is_null() {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    let context = socket_context.cast::<ListenerContext>();
    if context.is_null() {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    let local_address = if local_address.is_null() {
        return STATUS_REQUEST_NOT_ACCEPTED;
    } else {
        local_address
    };
    let Some(synthetic) = tuple_from_addresses(IPPROTO_TCP as u8, local_address, remote_address)
    else {
        return STATUS_REQUEST_NOT_ACCEPTED;
    };
    let reservation = reserve_flow(accept_socket, synthetic, [0; 28], 0, null_mut());
    let FlowReservation::New(index) = reservation else {
        return STATUS_REQUEST_NOT_ACCEPTED;
    };
    if !accept_socket_context.is_null() {
        unsafe {
            *accept_socket_context =
                core::ptr::addr_of_mut!(FLOW_SLOTS[index].inbound_context).cast();
        }
    }
    if !accept_socket_dispatch.is_null() {
        unsafe {
            *accept_socket_dispatch = &WSK_CLIENT_CONNECTION_DISPATCH;
        }
    }
    if !enable_socket_event_callbacks(accept_socket, WSK_EVENT_RECEIVE | WSK_EVENT_DISCONNECT) {
        close_slot_sync(index);
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    let _ = context;
    STATUS_SUCCESS
}

unsafe extern "C" fn wsk_receive_from_event(
    socket_context: PVOID,
    _flags: u32,
    data_indication: wsk::PWSK_DATAGRAM_INDICATION,
) -> NTSTATUS {
    if data_indication.is_null() {
        return STATUS_SUCCESS;
    }
    let context = socket_context.cast::<ListenerContext>();
    let remote = unsafe { (*data_indication).RemoteAddress };
    if context.is_null() || remote.is_null() {
        return STATUS_SUCCESS;
    }
    let local = if (*context).family == 4 {
        SockAddrIn {
            family: AF_INET,
            port: 15_000u16.to_be(),
            address: [
                (*context).address[0],
                (*context).address[1],
                (*context).address[2],
                (*context).address[3],
            ],
            zero: [0; 8],
        }
    } else {
        SockAddrIn {
            family: AF_INET,
            port: 0,
            address: [0; 4],
            zero: [0; 8],
        }
    };
    if (*context).family == 4 {
        if let Some(synthetic) = tuple_from_addresses(
            IPPROTO_UDP as u8,
            (&local as *const SockAddrIn).cast(),
            remote,
        ) {
            let listener = listener_for_context(unsafe { &*context });
            if let Some((client, client_len)) = udp_client_bytes(remote, (*context).family) {
                match reserve_flow(listener, synthetic, client, client_len, listener) {
                    FlowReservation::Existing(index) => {
                        let outbound = {
                            let _lock = lock_flow_table();
                            unsafe {
                                FLOW_TABLE
                                    .get(index)
                                    .filter(|entry| entry.state == FlowState::Mapped)
                                    .map(|_| FLOW_SLOTS[index].outbound)
                            }
                        };
                        if let Some(outbound) = outbound {
                            if !forward_datagram_to_outbound(
                                index,
                                listener,
                                outbound,
                                data_indication,
                            ) {
                                begin_flow_close_async(index);
                            } else {
                                touch_flow(index);
                            }
                        }
                    }
                    FlowReservation::New(_) | FlowReservation::Full => {}
                }
            }
        }
    } else {
        let local = SockAddrIn6 {
            family: AF_INET6,
            port: 15_000u16.to_be(),
            flow_info: 0,
            address: (*context).address,
            scope_id: 0,
        };
        if let Some(synthetic) = tuple_from_addresses(
            IPPROTO_UDP as u8,
            (&local as *const SockAddrIn6).cast(),
            remote,
        ) {
            let listener = listener_for_context(unsafe { &*context });
            if let Some((client, client_len)) = udp_client_bytes(remote, (*context).family) {
                match reserve_flow(listener, synthetic, client, client_len, listener) {
                    FlowReservation::Existing(index) => {
                        let outbound = {
                            let _lock = lock_flow_table();
                            unsafe {
                                FLOW_TABLE
                                    .get(index)
                                    .filter(|entry| entry.state == FlowState::Mapped)
                                    .map(|_| FLOW_SLOTS[index].outbound)
                            }
                        };
                        if let Some(outbound) = outbound {
                            if !forward_datagram_to_outbound(
                                index,
                                listener,
                                outbound,
                                data_indication,
                            ) {
                                begin_flow_close_async(index);
                            } else {
                                touch_flow(index);
                            }
                        }
                    }
                    FlowReservation::New(_) | FlowReservation::Full => {}
                }
            }
        }
    }
    STATUS_SUCCESS
}

unsafe extern "C" fn wsk_receive_event(
    socket_context: PVOID,
    _flags: u32,
    data_indication: wsk::PWSK_DATA_INDICATION,
    bytes_indicated: u64,
    bytes_accepted: *mut u64,
) -> NTSTATUS {
    if !bytes_accepted.is_null() {
        unsafe {
            *bytes_accepted = bytes_indicated;
        }
    }
    let callback = if socket_context.is_null() {
        return STATUS_SUCCESS;
    } else {
        unsafe { &*socket_context.cast::<FlowCallbackContext>() }
    };
    let index = flow_slot_index(callback.slot);
    if index >= FLOW_TABLE_CAPACITY {
        return STATUS_SUCCESS;
    }
    if data_indication.is_null() || unsafe { (*data_indication).Next != null_mut() } {
        begin_flow_close_async(index);
        return STATUS_SUCCESS;
    }
    let entry = {
        let _lock = lock_flow_table();
        unsafe { FLOW_TABLE.get(index) }
    };
    let Some(entry) = entry else {
        return STATUS_SUCCESS;
    };
    if entry.key.synthetic.protocol as u32 == IPPROTO_UDP {
        let (outbound, listener) = {
            let _lock = lock_flow_table();
            unsafe { (FLOW_SLOTS[index].outbound, FLOW_SLOTS[index].udp_listener) }
        };
        if !forward_datagram_to_client(index, outbound, listener, data_indication) {
            begin_flow_close_async(index);
        } else {
            touch_flow(index);
        }
        return STATUS_SUCCESS;
    }
    if entry.state != FlowState::Mapped {
        begin_flow_close_async(index);
        return STATUS_SUCCESS;
    }
    let (source, destination) = {
        let _lock = lock_flow_table();
        unsafe {
            if callback.inbound {
                (FLOW_SLOTS[index].socket, FLOW_SLOTS[index].outbound)
            } else {
                (FLOW_SLOTS[index].outbound, FLOW_SLOTS[index].socket)
            }
        }
    };
    if !forward_stream_data(
        index,
        source,
        destination,
        data_indication,
        callback.inbound,
    ) {
        begin_flow_close_async(index);
    } else {
        touch_flow(index);
    }

    STATUS_SUCCESS
}

fn forward_datagram_to_outbound(
    index: usize,
    source: wsk::PWSK_SOCKET,
    destination: wsk::PWSK_SOCKET,
    indication: wsk::PWSK_DATAGRAM_INDICATION,
) -> bool {
    if source.is_null() || destination.is_null() || indication.is_null() {
        return false;
    }
    let dispatch =
        unsafe { (*destination).Dispatch as *const wsk::WSK_PROVIDER_CONNECTION_DISPATCH };
    if dispatch.is_null() {
        return false;
    }
    let Some(send) = (unsafe { (*dispatch).WskSend }) else {
        return false;
    };
    let irp = unsafe { IoAllocateIrp(1, 0) };
    if irp.is_null() {
        return false;
    }
    let context = unsafe { &mut FLOW_SLOTS[index].udp_inbound_forward };
    if context
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    context.source = source;
    context.indication = indication;
    let status = unsafe {
        IoSetCompletionRoutineEx(
            DEVICE_OBJECT,
            irp,
            Some(datagram_forward_completion),
            context as *mut DatagramForwardContext as PVOID,
            1,
            1,
            1,
        )
    };
    if status != STATUS_SUCCESS {
        unsafe {
            context.busy.store(false, Ordering::Release);
            IoFreeIrp(irp);
        }
        return false;
    }
    let mut buffer = unsafe { (*indication).Buffer };
    let status = unsafe { send(destination, &mut buffer, 0, irp.cast()) };
    status == STATUS_SUCCESS || status == STATUS_PENDING
}

fn forward_datagram_to_client(
    index: usize,
    source: wsk::PWSK_SOCKET,
    destination: wsk::PWSK_SOCKET,
    indication: wsk::PWSK_DATA_INDICATION,
) -> bool {
    if source.is_null() || destination.is_null() || indication.is_null() {
        return false;
    }
    let dispatch = unsafe { (*destination).Dispatch as *const wsk::WSK_PROVIDER_DATAGRAM_DISPATCH };
    if dispatch.is_null() {
        return false;
    }
    let Some(send_to) = (unsafe { (*dispatch).WskSendTo }) else {
        return false;
    };
    let irp = unsafe { IoAllocateIrp(1, 0) };
    if irp.is_null() {
        return false;
    }
    let context = unsafe { &mut FLOW_SLOTS[index].udp_outbound_forward };
    if context
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    context.source = source;
    context.indication = indication.cast();
    let status = unsafe {
        IoSetCompletionRoutineEx(
            DEVICE_OBJECT,
            irp,
            Some(datagram_response_completion),
            context as *mut DatagramForwardContext as PVOID,
            1,
            1,
            1,
        )
    };
    if status != STATUS_SUCCESS {
        unsafe {
            context.busy.store(false, Ordering::Release);
            IoFreeIrp(irp);
        }
        return false;
    }
    let remote = unsafe { core::ptr::addr_of_mut!(FLOW_SLOTS[index].client_address).cast() };
    let mut buffer = unsafe { (*indication).Buffer };
    let status = unsafe {
        send_to(
            destination,
            &mut buffer,
            0,
            remote,
            0,
            null_mut(),
            irp.cast(),
        )
    };
    status == STATUS_SUCCESS || status == STATUS_PENDING
}

unsafe extern "C" fn datagram_forward_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: PVOID,
) -> NTSTATUS {
    if !context.is_null() {
        let forward = unsafe { &mut *context.cast::<DatagramForwardContext>() };
        if !forward.source.is_null() && !forward.indication.is_null() {
            let dispatch =
                unsafe { (*forward.source).Dispatch as *const wsk::WSK_PROVIDER_DATAGRAM_DISPATCH };
            if !dispatch.is_null() {
                if let Some(release) = unsafe { (*dispatch).WskRelease } {
                    let _ = unsafe { release(forward.source, forward.indication) };
                }
            }
        }
        forward.source = null_mut();
        forward.indication = null_mut();
        forward.busy.store(false, Ordering::Release);
        forward.busy.store(false, Ordering::Release);
    }
    unsafe {
        IoFreeIrp(irp);
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

unsafe extern "C" fn datagram_response_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: PVOID,
) -> NTSTATUS {
    if !context.is_null() {
        let forward = unsafe { &mut *context.cast::<DatagramForwardContext>() };
        if !forward.source.is_null() && !forward.indication.is_null() {
            let dispatch = unsafe {
                (*forward.source).Dispatch as *const wsk::WSK_PROVIDER_CONNECTION_DISPATCH
            };
            if !dispatch.is_null() {
                if let Some(release) = unsafe { (*dispatch).WskRelease } {
                    let _ = unsafe {
                        release(
                            forward.source,
                            forward.indication.cast::<wsk::WSK_DATA_INDICATION>(),
                        )
                    };
                }
            }
        }
        forward.source = null_mut();
        forward.indication = null_mut();
        forward.busy.store(false, Ordering::Release);
    }
    unsafe {
        IoFreeIrp(irp);
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

unsafe extern "C" fn wsk_disconnect_event(socket_context: PVOID, _flags: u32) -> NTSTATUS {
    if !socket_context.is_null() {
        let callback = unsafe { &*socket_context.cast::<FlowCallbackContext>() };
        let index = flow_slot_index(callback.slot);
        if index < FLOW_TABLE_CAPACITY {
            begin_flow_close_async(index);
        }
    }
    STATUS_SUCCESS
}

unsafe extern "C" fn stream_forward_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: PVOID,
) -> NTSTATUS {
    if !context.is_null() {
        let forward = unsafe { &mut *context.cast::<StreamForwardContext>() };
        if !forward.source.is_null() && !forward.indication.is_null() {
            let dispatch = unsafe {
                (*forward.source).Dispatch as *const wsk::WSK_PROVIDER_CONNECTION_DISPATCH
            };
            if !dispatch.is_null() {
                if let Some(release) = unsafe { (*dispatch).WskRelease } {
                    let _ = unsafe { release(forward.source, forward.indication) };
                }
            }
        }
        forward.source = null_mut();
        forward.indication = null_mut();
    }
    unsafe {
        IoFreeIrp(irp);
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

fn forward_stream_data(
    index: usize,
    source: wsk::PWSK_SOCKET,
    destination: wsk::PWSK_SOCKET,
    indication: wsk::PWSK_DATA_INDICATION,
    inbound: bool,
) -> bool {
    if source.is_null() || destination.is_null() {
        return false;
    }
    let dispatch =
        unsafe { (*destination).Dispatch as *const wsk::WSK_PROVIDER_CONNECTION_DISPATCH };
    if dispatch.is_null() {
        return false;
    }
    let Some(send) = (unsafe { (*dispatch).WskSend }) else {
        return false;
    };
    let irp = unsafe { IoAllocateIrp(1, 0) };
    if irp.is_null() {
        return false;
    }
    let context = if inbound {
        unsafe { &mut FLOW_SLOTS[index].inbound_forward }
    } else {
        unsafe { &mut FLOW_SLOTS[index].outbound_forward }
    };
    if context
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        unsafe {
            IoFreeIrp(irp);
        }
        return false;
    }
    context.source = source;
    context.indication = indication;
    let device = unsafe { DEVICE_OBJECT };
    let status = unsafe {
        IoSetCompletionRoutineEx(
            device,
            irp,
            Some(stream_forward_completion),
            context as *mut StreamForwardContext as PVOID,
            1,
            1,
            1,
        )
    };
    if status != STATUS_SUCCESS {
        unsafe {
            context.busy.store(false, Ordering::Release);
            IoFreeIrp(irp);
        }
        return false;
    }
    let mut buffer = unsafe { (*indication).Buffer };
    let status = unsafe { send(destination, &mut buffer, 0, irp.cast()) };
    if status != STATUS_SUCCESS && status != STATUS_PENDING {
        unsafe {
            let forward = &mut *context;
            forward.source = null_mut();
            forward.indication = null_mut();
            forward.busy.store(false, Ordering::Release);
            IoFreeIrp(irp);
        }
        return false;
    }
    true
}

fn register_wsk() -> NTSTATUS {
    initialize_flow_slots();
    let mut client_npi = wsk::WSK_CLIENT_NPI {
        ClientContext: null_mut(),
        Dispatch: &WSK_CLIENT_DISPATCH,
    };
    unsafe {
        let registration = core::ptr::addr_of_mut!(WSK_REGISTRATION).cast();
        let status = wsk::WskRegister(&mut client_npi, registration);
        if status != STATUS_SUCCESS {
            debug_status(b"WskRegister\0", status);
            return status;
        }
        WSK_REGISTERED = true;

        let provider = core::ptr::addr_of_mut!(WSK_PROVIDER_NPI).cast();
        let status = wsk::WskCaptureProviderNPI(registration, WSK_INFINITE_WAIT, provider);
        if status != STATUS_SUCCESS {
            debug_status(b"WskCaptureProviderNPI\0", status);
            wsk::WskDeregister(registration);
            WSK_REGISTERED = false;
            return status;
        }
        WSK_PROVIDER_CAPTURED = true;
    }

    let status = set_static_event_callbacks();
    if status != STATUS_SUCCESS {
        debug_status(b"set_static_event_callbacks\0", status);
    }

    let tcp_v4 = setup_listener(AF_INET, IPPROTO_TCP, &TCP_CONTEXT_V4);
    let tcp_v6 = setup_listener(AF_INET6, IPPROTO_TCP, &TCP_CONTEXT_V6);
    let udp_v4 = setup_listener(AF_INET, IPPROTO_UDP, &UDP_CONTEXT_V4);
    let udp_v6 = setup_listener(AF_INET6, IPPROTO_UDP, &UDP_CONTEXT_V6);
    if tcp_v4.is_none() || tcp_v6.is_none() || udp_v4.is_none() || udp_v6.is_none() {
        debug_status(b"setup_listener\0", STATUS_NOT_SUPPORTED);
        if let Some(socket) = tcp_v4 {
            let _ = close_socket_sync(socket);
        }
        if let Some(socket) = tcp_v6 {
            let _ = close_socket_sync(socket);
        }
        if let Some(socket) = udp_v4 {
            let _ = close_socket_sync(socket);
        }
        if let Some(socket) = udp_v6 {
            let _ = close_socket_sync(socket);
        }
        unregister_wsk();
        return STATUS_NOT_SUPPORTED;
    }
    unsafe {
        TCP_LISTENER_V4 = tcp_v4.unwrap_or(null_mut());
        TCP_LISTENER_V6 = tcp_v6.unwrap_or(null_mut());
        UDP_LISTENER_V4 = udp_v4.unwrap_or(null_mut());
        UDP_LISTENER_V6 = udp_v6.unwrap_or(null_mut());
    }
    initialize_mapping_timer();
    STATUS_SUCCESS
}

fn unregister_wsk() {
    stop_mapping_timer();
    cancel_pending_mapping(abi::Status::Cancelled);
    fail_active_flow_sync();
    close_all_listeners();
    STATIC_EVENT_CALLBACKS_ENABLED.store(false, Ordering::Release);
    unsafe {
        let registration = core::ptr::addr_of_mut!(WSK_REGISTRATION).cast();
        if WSK_PROVIDER_CAPTURED {
            wsk::WskReleaseProviderNPI(registration);
            WSK_PROVIDER_CAPTURED = false;
        }
        if WSK_REGISTERED {
            wsk::WskDeregister(registration);
            WSK_REGISTERED = false;
        }
    }
}
