// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! User-mode broker-side IOCTL transport and session state machine.

#[cfg(windows)]
use std::sync::{Arc, Mutex};
use std::{
    fmt, io,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::abi::{
    self, AbiError, AbiHeader, CloseSessionRequest, Generation, MappingCompletion, MappingRequest,
    MappingTuple, MappingWaitRequest, Opcode, OpenSessionRequest, OpenSessionResponse, RequestId,
    SessionNonce, Status,
};

/// Broker lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerState {
    /// No device session is open.
    Disconnected,
    /// An open request is in progress.
    Opening,
    /// A device session is active.
    Open,
    /// A close request is in progress.
    Closing,
    /// The broker has been closed and cannot issue requests.
    Closed,
}

/// Errors returned by the broker abstraction.
#[derive(Debug)]
pub enum BrokerError {
    /// ABI validation failed.
    Abi(AbiError),
    /// The broker state does not permit the requested operation.
    InvalidState(BrokerState),
    /// The transport could not complete an IOCTL.
    Transport(io::Error),
    /// The device returned an incomplete or oversized response.
    InvalidResponse,
    /// The device completed an operation with a non-success ABI status.
    DeviceStatus(Status),
    /// The platform does not provide a Windows device transport.
    UnsupportedPlatform,
}

impl fmt::Display for BrokerError {
    /// Formats a broker failure without including credentials or nonce bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abi(error) => write!(formatter, "device ABI error: {error}"),
            Self::InvalidState(state) => write!(formatter, "invalid broker state: {state:?}"),
            Self::Transport(error) => write!(formatter, "device IOCTL failed: {error}"),
            Self::InvalidResponse => write!(formatter, "device returned an invalid response"),
            Self::DeviceStatus(status) => {
                write!(formatter, "device rejected the request: {status:?}")
            }
            Self::UnsupportedPlatform => write!(
                formatter,
                "WSK device transport requires a Windows x64 or ARM64 target"
            ),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<AbiError> for BrokerError {
    /// Wraps a fixed-ABI validation failure.
    fn from(error: AbiError) -> Self {
        Self::Abi(error)
    }
}

/// Minimal IOCTL boundary used by the broker. The implementation owns all
/// platform-specific handle and `DeviceIoControl` details.
pub trait IoctlTransport: Send + Sync {
    /// Sends one buffered IOCTL and returns the bytes written by the device.
    fn ioctl(&self, code: u32, input: &[u8], output_size: usize) -> Result<Vec<u8>, BrokerError>;
}

/// Generic user-mode broker with deterministic request/generation tracking.
pub struct IoctlBroker<T> {
    /// Platform-specific IOCTL implementation.
    transport: T,
    /// Current broker state.
    state: BrokerState,
    /// Device-generated session nonce.
    nonce: Option<SessionNonce>,
    /// Source of request IDs.
    next_request_id: AtomicU64,
    /// Source of request generations.
    next_generation: AtomicU64,
}

impl<T: IoctlTransport> IoctlBroker<T> {
    /// Creates a broker disconnected from the device.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: BrokerState::Disconnected,
            nonce: None,
            next_request_id: AtomicU64::new(1),
            next_generation: AtomicU64::new(1),
        }
    }

    /// Returns the current lifecycle state.
    pub fn state(&self) -> BrokerState {
        self.state
    }

    /// Returns the authenticated session nonce after opening.
    pub fn session_nonce(&self) -> Option<SessionNonce> {
        self.nonce
    }

    /// Opens the device session and validates the returned fixed response.
    pub fn open_session(&mut self, client_nonce: SessionNonce) -> Result<(), BrokerError> {
        if self.state != BrokerState::Disconnected {
            return Err(BrokerError::InvalidState(self.state));
        }
        if client_nonce.is_zero() {
            return Err(BrokerError::Abi(AbiError::InvalidSession));
        }
        self.state = BrokerState::Opening;
        let request_id = self.next_request_id();
        let generation = self.next_generation();
        let request = OpenSessionRequest {
            header: AbiHeader::request(
                Opcode::OpenSession,
                SessionNonce::zero(),
                request_id,
                generation,
                std::mem::size_of::<OpenSessionRequest>(),
            ),
            client_nonce,
        };
        let response = match self.transport.ioctl(
            abi::ioctl::OPEN_SESSION,
            as_bytes(&request),
            std::mem::size_of::<OpenSessionResponse>(),
        ) {
            Ok(response) => response,
            Err(error) => {
                self.state = BrokerState::Disconnected;
                return Err(error);
            }
        };
        let response = match from_bytes::<OpenSessionResponse>(&response) {
            Ok(response) => response,
            Err(error) => {
                self.state = BrokerState::Disconnected;
                self.nonce = None;
                return Err(error);
            }
        };
        let validation = response
            .header
            .validate(
                Opcode::OpenSession,
                std::mem::size_of::<OpenSessionResponse>(),
                None,
            )
            .and_then(|()| response.header.validate_identity(request_id, generation));
        if let Err(error) = validation {
            self.state = BrokerState::Disconnected;
            self.nonce = None;
            return Err(error.into());
        }
        if response.session_nonce.is_zero() {
            self.state = BrokerState::Disconnected;
            self.nonce = None;
            return Err(BrokerError::Abi(AbiError::InvalidSession));
        }
        if response.header.session_nonce != response.session_nonce {
            self.state = BrokerState::Disconnected;
            self.nonce = None;
            return Err(BrokerError::Abi(AbiError::InvalidSession));
        }
        self.nonce = Some(response.session_nonce);
        self.state = BrokerState::Open;
        Ok(())
    }

    /// Closes the device session. A failed close still makes the broker closed
    /// so callers cannot accidentally reuse a possibly invalid handle/session.
    pub fn close_session(&mut self) -> Result<(), BrokerError> {
        if self.state != BrokerState::Open {
            return Err(BrokerError::InvalidState(self.state));
        }
        let nonce = self.nonce.ok_or(BrokerError::InvalidState(self.state))?;
        self.state = BrokerState::Closing;
        let request = CloseSessionRequest {
            header: AbiHeader::request(
                Opcode::CloseSession,
                nonce,
                self.next_request_id(),
                self.next_generation(),
                std::mem::size_of::<CloseSessionRequest>(),
            ),
        };
        let result = self
            .transport
            .ioctl(
                abi::ioctl::CLOSE_SESSION,
                as_bytes(&request),
                std::mem::size_of::<AbiHeader>(),
            )
            .and_then(|response| {
                let header = from_bytes::<AbiHeader>(&response)?;
                header.validate(
                    Opcode::CloseSession,
                    std::mem::size_of::<AbiHeader>(),
                    Some(nonce),
                )?;
                header.validate_identity(request.header.request_id, request.header.generation)?;
                Ok(())
            });
        self.nonce = None;
        self.state = BrokerState::Closed;
        result
    }

    /// Waits for one driver-originated synthetic flow mapping request.
    ///
    /// The IOCTL remains pending in the kernel until a flow arrives, a broker
    /// cancellation occurs, or the driver's bounded mapping wait expires.
    pub fn wait_for_mapping(&mut self) -> Result<MappingRequest, BrokerError> {
        if self.state != BrokerState::Open {
            return Err(BrokerError::InvalidState(self.state));
        }
        let nonce = self.nonce.ok_or(BrokerError::InvalidState(self.state))?;
        let request = MappingWaitRequest {
            header: AbiHeader::request(
                Opcode::SubmitRequest,
                nonce,
                self.next_request_id(),
                self.next_generation(),
                std::mem::size_of::<MappingWaitRequest>(),
            ),
        };
        let response = self.transport.ioctl(
            abi::ioctl::SUBMIT_REQUEST,
            as_bytes(&request),
            std::mem::size_of::<MappingRequest>(),
        )?;
        let mapping = from_bytes::<MappingRequest>(&response)?;
        let status = mapping.header.validate_response(
            Opcode::SubmitRequest,
            std::mem::size_of::<MappingRequest>(),
            nonce,
            request.header.request_id,
            request.header.generation,
        )?;
        if status != Status::Ok {
            return Err(BrokerError::DeviceStatus(status));
        }
        mapping.validate(nonce)?;
        Ok(mapping)
    }

    /// Completes one mapping request with the authenticated original tuple.
    pub fn complete_mapping(
        &mut self,
        mapping: &MappingRequest,
        original: MappingTuple,
    ) -> Result<(), BrokerError> {
        if self.state != BrokerState::Open {
            return Err(BrokerError::InvalidState(self.state));
        }
        let nonce = self.nonce.ok_or(BrokerError::InvalidState(self.state))?;
        mapping.validate(nonce)?;
        original.validate_original()?;
        if original.protocol != mapping.synthetic.protocol
            || original.address_family != mapping.synthetic.address_family
        {
            return Err(BrokerError::Abi(AbiError::InvalidMapping));
        }
        let completion = MappingCompletion {
            header: AbiHeader::request(
                Opcode::CompleteRequest,
                nonce,
                mapping.header.request_id,
                mapping.header.generation,
                std::mem::size_of::<MappingCompletion>(),
            ),
            synthetic: mapping.synthetic,
            original,
        };
        let response = self.transport.ioctl(
            abi::ioctl::COMPLETE_REQUEST,
            as_bytes(&completion),
            std::mem::size_of::<AbiHeader>(),
        )?;
        let header = from_bytes::<AbiHeader>(&response)?;
        let status = header.validate_response(
            Opcode::CompleteRequest,
            std::mem::size_of::<AbiHeader>(),
            nonce,
            completion.header.request_id,
            completion.header.generation,
        )?;
        if status != Status::Ok {
            return Err(BrokerError::DeviceStatus(status));
        }
        Ok(())
    }

    /// Allocates the next nonzero request identity.
    pub fn next_request(&self) -> RequestId {
        self.next_request_id()
    }

    /// Allocates the next nonzero generation identity.
    pub fn next_generation_id(&self) -> Generation {
        self.next_generation()
    }

    /// Allocates a request ID for an internal session operation.
    fn next_request_id(&self) -> RequestId {
        RequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Allocates a generation for an internal session operation.
    fn next_generation(&self) -> Generation {
        Generation(self.next_generation.fetch_add(1, Ordering::Relaxed))
    }
}

/// Windows device transport backed by `DeviceIoControl`.
#[cfg(windows)]
#[derive(Clone)]
pub struct WindowsDevice {
    /// Open handle to the installed device.
    handle: Arc<std::fs::File>,
    /// Native handle for the thread currently issuing a synchronous IOCTL.
    issuing_thread: Arc<Mutex<Option<usize>>>,
}

#[cfg(windows)]
impl WindowsDevice {
    /// Opens a broker device path. The kernel component must be installed.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, BrokerError> {
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(BrokerError::Transport)?;
        Ok(Self {
            handle: Arc::new(handle),
            issuing_thread: Arc::new(Mutex::new(None)),
        })
    }

    /// Cancels pending device I/O so a synchronous mapping wait can shut down.
    pub fn cancel_pending_io(&self) {
        let thread = *self.issuing_thread.lock().unwrap();
        if let Some(thread) = thread {
            unsafe {
                let _ = CancelSynchronousIo(thread as *mut std::ffi::c_void);
            }
        }
    }
}

#[cfg(windows)]
impl IoctlTransport for WindowsDevice {
    /// Sends a synchronous buffered `DeviceIoControl` request.
    fn ioctl(&self, code: u32, input: &[u8], output_size: usize) -> Result<Vec<u8>, BrokerError> {
        use std::os::windows::io::AsRawHandle;

        let mut thread = std::ptr::null_mut();
        unsafe {
            if DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentThread(),
                GetCurrentProcess(),
                &mut thread,
                0,
                0,
                2,
            ) == 0
            {
                return Err(BrokerError::Transport(io::Error::last_os_error()));
            }
        }
        *self.issuing_thread.lock().unwrap() = Some(thread as usize);
        let mut output = vec![0u8; output_size];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                self.handle.as_raw_handle(),
                code,
                input.as_ptr() as *const std::ffi::c_void,
                input.len() as u32,
                output.as_mut_ptr() as *mut std::ffi::c_void,
                output.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        let thread = self.issuing_thread.lock().unwrap().take();
        if let Some(thread) = thread {
            unsafe {
                CloseHandle(thread as *mut std::ffi::c_void);
            }
        }
        if ok == 0 {
            return Err(BrokerError::Transport(io::Error::last_os_error()));
        }
        output.truncate(returned as usize);
        Ok(output)
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    /// Windows kernel32 device-control entry point.
    fn DeviceIoControl(
        device: *mut std::ffi::c_void,
        code: u32,
        input: *const std::ffi::c_void,
        input_size: u32,
        output: *mut std::ffi::c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> i32;

    /// Returns a pseudo-handle for the current process.
    fn GetCurrentProcess() -> *mut std::ffi::c_void;

    /// Returns a pseudo-handle for the current thread.
    fn GetCurrentThread() -> *mut std::ffi::c_void;

    /// Duplicates the current thread handle for cross-thread cancellation.
    fn DuplicateHandle(
        source_process: *mut std::ffi::c_void,
        source: *mut std::ffi::c_void,
        target_process: *mut std::ffi::c_void,
        target: *mut *mut std::ffi::c_void,
        desired_access: u32,
        inherit_handle: i32,
        options: u32,
    ) -> i32;

    /// Cancels synchronous I/O issued by a target thread.
    fn CancelSynchronousIo(thread: *mut std::ffi::c_void) -> i32;

    /// Releases a native Windows handle.
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

/// Explicit non-Windows transport used to keep workspace checks portable.
#[cfg(not(windows))]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDevice;

#[cfg(not(windows))]
impl WindowsDevice {
    /// Returns an explicit prerequisite error rather than pretending to open
    /// a WSK device on a non-Windows host.
    pub fn open(_path: impl AsRef<std::path::Path>) -> Result<Self, BrokerError> {
        Err(BrokerError::UnsupportedPlatform)
    }
}

#[cfg(not(windows))]
impl IoctlTransport for WindowsDevice {
    /// Returns the explicit non-Windows prerequisite error.
    fn ioctl(
        &self,
        _code: u32,
        _input: &[u8],
        _output_size: usize,
    ) -> Result<Vec<u8>, BrokerError> {
        Err(BrokerError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
impl IoctlBroker<WindowsDevice> {
    /// Clones the underlying handle for shutdown cancellation.
    pub fn clone_device(&self) -> WindowsDevice {
        self.transport.clone()
    }

    /// Cancels a pending mapping wait on the underlying device handle.
    pub fn cancel_pending_io(&self) {
        self.transport.cancel_pending_io();
    }
}

/// Views a fixed-layout ABI value as its wire bytes.
fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
}

/// Decodes a fixed-layout ABI value after checking its exact size.
fn from_bytes<T: Copy>(bytes: &[u8]) -> Result<T, BrokerError> {
    if bytes.len() != std::mem::size_of::<T>() {
        return Err(BrokerError::InvalidResponse);
    }
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            value.as_mut_ptr() as *mut u8,
            std::mem::size_of::<T>(),
        );
        Ok(value.assume_init())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{AbiHeader, OpenSessionResponse};
    use std::{io::ErrorKind, sync::Mutex};

    struct FakeTransport {
        calls: Mutex<Vec<u32>>,
        response_nonce: SessionNonce,
        mismatch_open_identity: bool,
        mapping_status: Status,
    }

    impl IoctlTransport for FakeTransport {
        fn ioctl(
            &self,
            code: u32,
            input: &[u8],
            _output_size: usize,
        ) -> Result<Vec<u8>, BrokerError> {
            self.calls.lock().unwrap().push(code);
            if code == abi::ioctl::OPEN_SESSION {
                let request = from_bytes::<OpenSessionRequest>(input)?;
                let response = OpenSessionResponse {
                    header: AbiHeader::request(
                        Opcode::OpenSession,
                        self.response_nonce,
                        if self.mismatch_open_identity {
                            RequestId(request.header.request_id.0 + 1)
                        } else {
                            request.header.request_id
                        },
                        request.header.generation,
                        std::mem::size_of::<OpenSessionResponse>(),
                    ),
                    session_nonce: self.response_nonce,
                };
                return Ok(as_bytes(&response).to_vec());
            }
            if code == abi::ioctl::CLOSE_SESSION {
                let request = from_bytes::<CloseSessionRequest>(input)?;
                let response = AbiHeader::request(
                    Opcode::CloseSession,
                    request.header.session_nonce,
                    request.header.request_id,
                    request.header.generation,
                    std::mem::size_of::<AbiHeader>(),
                );
                return Ok(as_bytes(&response).to_vec());
            }
            if code == abi::ioctl::SUBMIT_REQUEST {
                let request = from_bytes::<MappingWaitRequest>(input)?;
                let response = MappingRequest {
                    header: AbiHeader::response(
                        Opcode::SubmitRequest,
                        Status::Ok,
                        self.response_nonce,
                        request.header.request_id,
                        request.header.generation,
                        std::mem::size_of::<MappingRequest>(),
                    ),
                    synthetic: MappingTuple {
                        protocol: 6,
                        address_family: 4,
                        reserved: 0,
                        source_port: 40_000,
                        destination_port: 15_000,
                        source_address: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        destination_address: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    },
                };
                assert!(request.header.request_id.0 != 0);
                return Ok(as_bytes(&response).to_vec());
            }
            if code == abi::ioctl::COMPLETE_REQUEST {
                let request = from_bytes::<MappingCompletion>(input)?;
                let response = AbiHeader::response(
                    Opcode::CompleteRequest,
                    self.mapping_status,
                    request.header.session_nonce,
                    request.header.request_id,
                    request.header.generation,
                    std::mem::size_of::<AbiHeader>(),
                );
                return Ok(as_bytes(&response).to_vec());
            }
            Err(BrokerError::Transport(io::Error::new(
                ErrorKind::Unsupported,
                "unexpected IOCTL",
            )))
        }
    }

    fn nonce(value: u8) -> SessionNonce {
        SessionNonce::new([value; abi::SESSION_NONCE_SIZE])
    }

    #[test]
    fn broker_transitions_and_allocates_monotonic_ids() {
        let transport = FakeTransport {
            calls: Mutex::new(Vec::new()),
            response_nonce: nonce(9),
            mismatch_open_identity: false,
            mapping_status: Status::Ok,
        };
        let mut broker = IoctlBroker::new(transport);
        assert_eq!(broker.state(), BrokerState::Disconnected);
        broker.open_session(nonce(1)).unwrap();
        assert_eq!(broker.state(), BrokerState::Open);
        assert_eq!(broker.session_nonce(), Some(nonce(9)));
        assert!(broker.next_request() < broker.next_request());
        assert!(broker.next_generation_id() < broker.next_generation_id());
        broker.close_session().unwrap();
        assert_eq!(broker.state(), BrokerState::Closed);
    }

    #[test]
    fn broker_rejects_invalid_transitions_and_zero_nonce() {
        let transport = FakeTransport {
            calls: Mutex::new(Vec::new()),
            response_nonce: nonce(9),
            mismatch_open_identity: false,
            mapping_status: Status::Ok,
        };
        let mut broker = IoctlBroker::new(transport);
        assert!(matches!(
            broker.open_session(SessionNonce::zero()),
            Err(BrokerError::Abi(AbiError::InvalidSession))
        ));
        assert!(matches!(
            broker.close_session(),
            Err(BrokerError::InvalidState(BrokerState::Disconnected))
        ));
    }

    #[test]
    fn broker_fails_closed_on_response_identity_mismatch() {
        let transport = FakeTransport {
            calls: Mutex::new(Vec::new()),
            response_nonce: nonce(9),
            mismatch_open_identity: true,
            mapping_status: Status::Ok,
        };
        let mut broker = IoctlBroker::new(transport);
        assert!(matches!(
            broker.open_session(nonce(1)),
            Err(BrokerError::Abi(AbiError::InvalidIdentity))
        ));
        assert_eq!(broker.state(), BrokerState::Disconnected);
        assert_eq!(broker.session_nonce(), None);
    }

    #[test]
    fn broker_uses_one_mapping_exchange_for_kernel_relay() {
        let transport = FakeTransport {
            calls: Mutex::new(Vec::new()),
            response_nonce: nonce(9),
            mismatch_open_identity: false,
            mapping_status: Status::Ok,
        };
        let mut broker = IoctlBroker::new(transport);
        broker.open_session(nonce(1)).unwrap();
        let mapping = broker.wait_for_mapping().unwrap();
        assert_ne!(mapping.header.request_id, RequestId(0));
        let original = MappingTuple {
            protocol: 6,
            address_family: 4,
            reserved: 0,
            source_port: 40_000,
            destination_port: 443,
            source_address: mapping.synthetic.source_address,
            destination_address: [192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        broker.complete_mapping(&mapping, original).unwrap();
    }
}
