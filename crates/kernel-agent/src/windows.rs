// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use shadow_socket_proxy_kernel_relay::{
    device::MAX_TUNNEL_PAYLOAD_LEN, error::KernelRelayError, ioctl::DeviceIoControlChannel,
};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::Path, ptr, sync::Arc};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const MAX_BUFFER: usize = MAX_TUNNEL_PAYLOAD_LEN + 28;

#[derive(Debug, Clone)]
pub struct WindowsDevice {
    handle: Arc<DeviceHandle>,
}

#[derive(Debug)]
struct DeviceHandle(HANDLE);

unsafe impl Send for DeviceHandle {}
unsafe impl Sync for DeviceHandle {}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

impl WindowsDevice {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KernelRelayError> {
        let wide = OsStr::new(path.as_ref())
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Self::last_error("open kernel relay device"));
        }
        Ok(Self {
            handle: Arc::new(DeviceHandle(handle)),
        })
    }

    fn call(&self, code: u32, payload: &[u8]) -> Result<Vec<u8>, KernelRelayError> {
        if payload.len() > MAX_BUFFER {
            return Err(KernelRelayError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_BUFFER,
            });
        }
        let mut output = vec![0_u8; MAX_BUFFER];
        let mut returned = 0_u32;
        let ok = unsafe {
            DeviceIoControl(
                self.handle.0,
                code,
                payload.as_ptr().cast_mut().cast(),
                payload.len() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(Self::last_error("DeviceIoControl"));
        }
        output.truncate(returned as usize);
        Ok(output)
    }

    fn last_error(operation: &'static str) -> KernelRelayError {
        KernelRelayError::Transport(format!("{operation} failed with Win32 error {}", unsafe {
            GetLastError()
        }))
    }
}

#[async_trait::async_trait]
impl DeviceIoControlChannel for WindowsDevice {
    async fn device_io_control(
        &self,
        code: u32,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, KernelRelayError> {
        let device = self.clone();
        tokio::task::spawn_blocking(move || device.call(code, &payload))
            .await
            .map_err(|error| KernelRelayError::Transport(format!("IOCTL worker failed: {error}")))?
    }
}
