// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Minimal WDM and WSK FFI surface needed by the Windows-gated relay
//! boundary.
#![allow(non_snake_case)]

use core::ffi::c_void;

pub type NtStatus = i32;
pub type KIrql = u8;
pub type ExPushLock = usize;
pub type KSpinLock = usize;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010_u32 as i32;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023_u32 as i32;
pub const STATUS_NOT_SUPPORTED: NtStatus = 0xC000_00BB_u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009A_u32 as i32;
pub const STATUS_PENDING: NtStatus = 0x0000_0103;
pub const STATUS_TIMEOUT: NtStatus = 0x0000_0102;
pub const STATUS_MORE_PROCESSING_REQUIRED: NtStatus = 0xC000_0016_u32 as i32;

pub const IRP_MJ_CREATE: usize = 0x00;
pub const IRP_MJ_CLOSE: usize = 0x02;
pub const IRP_MJ_DEVICE_CONTROL: usize = 0x0E;
pub const IRP_MJ_CLEANUP: usize = 0x12;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1B;

pub const FILE_DEVICE_NETWORK: u32 = 0x12;
pub const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;
pub const DO_BUFFERED_IO: u32 = 0x0000_0004;
pub const IO_NO_INCREMENT: i8 = 0;

pub const DPFLTR_IHVNETWORK_ID: u32 = 0x0077;
pub const DPFLTR_ERROR_LEVEL: u32 = 0;
pub const DPFLTR_INFO_LEVEL: u32 = 3;

pub const WSK_INFINITE_WAIT: u32 = u32::MAX;

#[inline]
pub const fn nt_success(status: NtStatus) -> bool {
    status >= 0
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoStatusBlock {
    pub status: NtStatus,
    pub information: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct Irp {
    pub system_buffer: *mut c_void,
    pub io_status: IoStatusBlock,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceIoControlStack {
    pub output_buffer_length: u32,
    pub input_buffer_length: u32,
    pub io_control_code: u32,
    pub type3_input_buffer: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union IoStackParameters {
    pub device_io_control: DeviceIoControlStack,
    pub reserved: [u8; 32],
}

impl Default for IoStackParameters {
    fn default() -> Self {
        Self { reserved: [0; 32] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: IoStackParameters,
    pub device_object: *mut DeviceObject,
    pub file_object: *mut FileObject,
    pub completion_routine: *mut c_void,
    pub context: *mut c_void,
}

#[repr(C)]
pub struct FileObject {
    _private: [u8; 0],
}

#[repr(C)]
pub struct DeviceObject {
    pub device_extension: *mut c_void,
    pub flags: u32,
}

pub type DriverDispatch = unsafe extern "system" fn(*mut DeviceObject, *mut Irp) -> NtStatus;
pub type DriverUnload = unsafe extern "system" fn(*mut DriverObject);
pub type DriverInitialize =
    unsafe extern "system" fn(*mut DriverObject, *mut UnicodeString) -> NtStatus;

#[repr(C)]
pub struct DriverObject {
    pub type_: i16,
    pub size: i16,
    pub device_object: *mut DeviceObject,
    pub flags: u32,
    pub driver_start: *mut c_void,
    pub driver_size: u32,
    pub driver_section: *mut c_void,
    pub driver_extension: *mut c_void,
    pub driver_name: UnicodeString,
    pub hardware_database: *mut UnicodeString,
    pub fast_io_dispatch: *mut c_void,
    pub driver_init: Option<DriverInitialize>,
    pub driver_start_io: *mut c_void,
    pub driver_unload: Option<DriverUnload>,
    pub major_function: [Option<DriverDispatch>; IRP_MJ_MAXIMUM_FUNCTION + 1],
}

#[cfg(ssp_wdk_native)]
pub type WskRegistration = crate::wsk_bindings::WSK_REGISTRATION;
#[cfg(ssp_wdk_native)]
pub type WskClientDispatch = crate::wsk_bindings::WSK_CLIENT_DISPATCH;
#[cfg(ssp_wdk_native)]
pub type WskClientNpi = crate::wsk_bindings::WSK_CLIENT_NPI;
#[cfg(ssp_wdk_native)]
pub type WskProviderDispatch = crate::wsk_bindings::WSK_PROVIDER_DISPATCH;
#[cfg(ssp_wdk_native)]
pub type WskProviderNpi = crate::wsk_bindings::WSK_PROVIDER_NPI;

#[cfg(not(ssp_wdk_native))]
#[repr(C)]
#[derive(Debug, Default)]
pub struct WskRegistration {
    pub reserved: [usize; 4],
}

#[cfg(not(ssp_wdk_native))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WskClientDispatch {
    pub version: u16,
    pub reserved: u16,
    pub wsk_client_event:
        Option<unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32) -> NtStatus>,
}

#[cfg(not(ssp_wdk_native))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WskClientNpi {
    pub client_context: *mut c_void,
    pub dispatch: *const WskClientDispatch,
}

#[cfg(not(ssp_wdk_native))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskProviderDispatch {
    pub version: u16,
    pub reserved: u16,
    pub wsk_socket: Option<unsafe extern "system" fn() -> NtStatus>,
    pub wsk_socket_connect: Option<unsafe extern "system" fn() -> NtStatus>,
    pub wsk_control_client: Option<unsafe extern "system" fn() -> NtStatus>,
    pub wsk_get_address_info: Option<unsafe extern "system" fn() -> NtStatus>,
    pub wsk_free_address_info: Option<unsafe extern "system" fn(*mut c_void)>,
    pub wsk_get_name_info: Option<unsafe extern "system" fn() -> NtStatus>,
    pub wsk_acquire_socket_lock: Option<unsafe extern "system" fn(*mut c_void) -> NtStatus>,
    pub wsk_release_socket_lock: Option<unsafe extern "system" fn(*mut c_void)>,
}

#[cfg(not(ssp_wdk_native))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WskProviderNpi {
    pub client: *mut c_void,
    pub dispatch: *const WskProviderDispatch,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
pub struct Mdl {
    _private: [u8; 0],
}

#[cfg(ssp_wdk_native)]
extern "system" {
    pub fn ExAcquirePushLockExclusiveEx(lock: *mut ExPushLock, flags: usize);
    pub fn ExReleasePushLockExclusiveEx(lock: *mut ExPushLock, flags: usize);
    pub fn KeInitializeSpinLock(lock: *mut KSpinLock);
    pub fn KeAcquireSpinLockRaiseToDpc(lock: *mut KSpinLock) -> KIrql;
    pub fn KeReleaseSpinLock(lock: *mut KSpinLock, old_irql: KIrql);
    pub fn RtlInitUnicodeString(destination: *mut UnicodeString, source: *const u16);
    pub fn IoCreateDeviceSecure(
        driver_object: *mut DriverObject,
        device_extension_size: u32,
        device_name: *const UnicodeString,
        device_type: u32,
        device_characteristics: u32,
        exclusive: u8,
        default_sddl_string: *const UnicodeString,
        device_class_guid: *const Guid,
        device_object: *mut *mut DeviceObject,
    ) -> NtStatus;
    pub fn IoCreateSymbolicLink(
        symbolic_link_name: *const UnicodeString,
        device_name: *const UnicodeString,
    ) -> NtStatus;
    pub fn IoDeleteSymbolicLink(symbolic_link_name: *const UnicodeString) -> NtStatus;
    pub fn IoDeleteDevice(device_object: *mut DeviceObject);
    pub fn IoCompleteRequest(irp: *mut Irp, priority_boost: i8);
    pub fn IoGetCurrentIrpStackLocation(irp: *mut Irp) -> *mut IoStackLocation;
}

#[cfg(ssp_wdk_native)]
pub unsafe fn WskRegister(
    client_npi: *mut WskClientNpi,
    registration: *mut WskRegistration,
) -> NtStatus {
    crate::wsk_bindings::WskRegister(client_npi, registration)
}

#[cfg(ssp_wdk_native)]
pub unsafe fn WskCaptureProviderNPI(
    registration: *mut WskRegistration,
    wait_timeout: u32,
    provider_npi: *mut WskProviderNpi,
) -> NtStatus {
    crate::wsk_bindings::WskCaptureProviderNPI(registration, wait_timeout, provider_npi)
}

#[cfg(ssp_wdk_native)]
pub unsafe fn WskReleaseProviderNPI(registration: *mut WskRegistration) {
    crate::wsk_bindings::WskReleaseProviderNPI(registration)
}

#[cfg(ssp_wdk_native)]
pub unsafe fn WskDeregister(registration: *mut WskRegistration) {
    crate::wsk_bindings::WskDeregister(registration)
}

#[cfg(not(ssp_wdk_native))]
pub unsafe fn ExAcquirePushLockExclusiveEx(_lock: *mut ExPushLock, _flags: usize) {}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn ExReleasePushLockExclusiveEx(_lock: *mut ExPushLock, _flags: usize) {}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn KeInitializeSpinLock(lock: *mut KSpinLock) {
    if !lock.is_null() {
        *lock = 0;
    }
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn KeAcquireSpinLockRaiseToDpc(_lock: *mut KSpinLock) -> KIrql {
    0
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn KeReleaseSpinLock(_lock: *mut KSpinLock, _old_irql: KIrql) {}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn RtlInitUnicodeString(destination: *mut UnicodeString, source: *const u16) {
    if destination.is_null() {
        return;
    }
    (*destination).buffer = source.cast_mut();
    if source.is_null() {
        (*destination).length = 0;
        (*destination).maximum_length = 0;
        return;
    }
    let mut len = 0usize;
    while *source.add(len) != 0 {
        len += 1;
    }
    (*destination).length = (len * 2) as u16;
    (*destination).maximum_length = ((len + 1) * 2) as u16;
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn IoCreateDeviceSecure(
    _driver_object: *mut DriverObject,
    _device_extension_size: u32,
    _device_name: *const UnicodeString,
    _device_type: u32,
    _device_characteristics: u32,
    _exclusive: u8,
    _default_sddl_string: *const UnicodeString,
    _device_class_guid: *const Guid,
    _device_object: *mut *mut DeviceObject,
) -> NtStatus {
    STATUS_NOT_SUPPORTED
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn IoCreateSymbolicLink(
    _symbolic_link_name: *const UnicodeString,
    _device_name: *const UnicodeString,
) -> NtStatus {
    STATUS_NOT_SUPPORTED
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn IoDeleteSymbolicLink(_symbolic_link_name: *const UnicodeString) -> NtStatus {
    STATUS_NOT_SUPPORTED
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn IoDeleteDevice(_device_object: *mut DeviceObject) {}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn IoCompleteRequest(_irp: *mut Irp, _priority_boost: i8) {}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn IoGetCurrentIrpStackLocation(_irp: *mut Irp) -> *mut IoStackLocation {
    core::ptr::null_mut()
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn WskRegister(
    _client_npi: *const WskClientNpi,
    _registration: *mut WskRegistration,
) -> NtStatus {
    STATUS_NOT_SUPPORTED
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn WskCaptureProviderNPI(
    _registration: *mut WskRegistration,
    _wait_timeout: u32,
    _provider_npi: *mut WskProviderNpi,
) -> NtStatus {
    STATUS_NOT_SUPPORTED
}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn WskReleaseProviderNPI(_registration: *mut WskRegistration) {}
#[cfg(not(ssp_wdk_native))]
pub unsafe fn WskDeregister(_registration: *mut WskRegistration) {}

#[cfg(ssp_wdk_native)]
extern "C" {
    pub fn DbgPrintEx(component_id: u32, level: u32, format: *const u8, ...) -> i32;
}
