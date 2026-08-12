// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
#![cfg_attr(all(target_os = "windows", feature = "kernel"), no_std)]

//! Versioned WSK device ABI, user-mode broker, and optional WDM driver.

#[cfg(all(test, target_os = "windows", feature = "kernel"))]
extern crate std;

/// Fixed-layout device messages and validation.
pub mod abi;
/// User-mode IOCTL transport and broker lifecycle.
#[cfg(not(feature = "kernel"))]
pub mod broker;
/// Allocation-free bounded flow-table state used by the WSK implementation.
pub mod flow_table;

#[cfg(all(target_os = "windows", feature = "kernel"))]
/// WDM DriverEntry, device dispatch, and WSK provider registration.
pub mod kernel;

#[cfg(all(target_os = "windows", feature = "kernel", not(test)))]
extern crate wdk_panic;

#[cfg(all(target_os = "windows", feature = "kernel", not(test)))]
use wdk_alloc::WdkAllocator;

#[cfg(all(target_os = "windows", feature = "kernel", not(test)))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

#[cfg(all(target_os = "windows", feature = "kernel"))]
#[doc(hidden)]
pub mod wsk_bindings {
    #![allow(
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        dead_code,
        unnecessary_transmutes,
        clippy::all
    )]
    include!(concat!(env!("OUT_DIR"), "/wsk_bindings.rs"));
}
