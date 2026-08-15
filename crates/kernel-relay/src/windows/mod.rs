// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Windows-gated WDK/WDM/WSK boundary for the kernel relay.

pub mod driver;
pub mod ffi;
pub mod locks;
pub mod telemetry;
pub mod wsk;

pub use driver::{
    dispatch_cleanup, dispatch_close, dispatch_create, dispatch_device_control, driver_entry,
    driver_unload, DriverRuntime, NativeRuntimeConfig, DEVICE_SDDL,
};
pub use locks::{PushLock, PushLockGuard, SpinLock, SpinLockGuard};
#[cfg(ssp_wdk_native)]
pub use wsk::NativeWskDataplane;
pub use wsk::{
    ListenerBinding, ListenerCallbacks, ListenerSet, TcpRelayOperation, UdpRelayOperation,
    WskDataplane, WskListener, WskProvider, WskSocketHandle,
};
