// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Typed ownership around kernel `PUSH_LOCK` and `KSPIN_LOCK`.

use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
};

use super::ffi;

#[derive(Debug)]
/// Exclusive PASSIVE-level lock for shared driver state.
pub struct PushLock<T> {
    raw: UnsafeCell<ffi::ExPushLock>,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for PushLock<T> {}
unsafe impl<T: Send> Sync for PushLock<T> {}

impl<T> PushLock<T> {
    /// Creates a zero-initialized `PUSH_LOCK` around typed state.
    pub const fn new(value: T) -> Self {
        Self {
            raw: UnsafeCell::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquires the lock exclusively.
    pub fn lock_exclusive(&self) -> PushLockGuard<'_, T> {
        unsafe { ffi::ExAcquirePushLockExclusiveEx(self.raw.get(), 0) };
        PushLockGuard { lock: self }
    }
}

#[derive(Debug)]
/// Guard returned by `PushLock::lock_exclusive`.
pub struct PushLockGuard<'a, T> {
    lock: &'a PushLock<T>,
}

impl<T> Deref for PushLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for PushLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for PushLockGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { ffi::ExReleasePushLockExclusiveEx(self.lock.raw.get(), 0) };
    }
}

#[derive(Debug)]
/// DISPATCH-safe typed state protected by `KSPIN_LOCK`.
pub struct SpinLock<T> {
    raw: UnsafeCell<ffi::KSpinLock>,
    initialized: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Creates a typed spin lock with lazy WDK initialization.
    pub const fn new(value: T) -> Self {
        Self {
            raw: UnsafeCell::new(0),
            initialized: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquires the spin lock and raises to DISPATCH if needed.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        if !self.initialized.swap(true, Ordering::AcqRel) {
            unsafe { ffi::KeInitializeSpinLock(self.raw.get()) };
        }
        let old_irql = unsafe { ffi::KeAcquireSpinLockRaiseToDpc(self.raw.get()) };
        SpinLockGuard {
            lock: self,
            old_irql,
        }
    }
}

#[derive(Debug)]
/// Guard returned by `SpinLock::lock`.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    old_irql: ffi::KIrql,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { ffi::KeReleaseSpinLock(self.lock.raw.get(), self.old_irql) };
    }
}
