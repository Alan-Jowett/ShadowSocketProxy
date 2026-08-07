// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use arc_swap::ArcSwap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub revision: u64,
    pub cleanup_interval: Duration,
    pub idle_ttl: Duration,
    pub map_scan_batch: usize,
    pub log_capacity: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            revision: 1,
            cleanup_interval: Duration::from_secs(10),
            idle_ttl: Duration::from_secs(60),
            map_scan_batch: 256,
            log_capacity: 1024,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("cleanup interval must be non-zero")]
    ZeroCleanupInterval,
    #[error("idle TTL must be non-zero")]
    ZeroIdleTtl,
    #[error("map scan batch must be between 1 and 100000")]
    InvalidBatch,
    #[error("log capacity must be between 1 and 100000")]
    InvalidLogCapacity,
    #[error("cleanup interval must not exceed idle TTL")]
    IntervalExceedsTtl,
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.cleanup_interval.is_zero() {
            return Err(ConfigError::ZeroCleanupInterval);
        }
        if self.idle_ttl.is_zero() {
            return Err(ConfigError::ZeroIdleTtl);
        }
        if self.map_scan_batch == 0 || self.map_scan_batch > 100_000 {
            return Err(ConfigError::InvalidBatch);
        }
        if self.log_capacity == 0 || self.log_capacity > 100_000 {
            return Err(ConfigError::InvalidLogCapacity);
        }
        if self.cleanup_interval > self.idle_ttl {
            return Err(ConfigError::IntervalExceedsTtl);
        }
        Ok(())
    }
}

pub struct ConfigStore {
    current: ArcSwap<RuntimeConfig>,
    next_revision: AtomicU64,
}

impl ConfigStore {
    pub fn new(initial: RuntimeConfig) -> Result<Self, ConfigError> {
        initial.validate()?;
        Ok(Self {
            next_revision: AtomicU64::new(initial.revision + 1),
            current: ArcSwap::from_pointee(initial),
        })
    }

    pub fn snapshot(&self) -> std::sync::Arc<RuntimeConfig> {
        self.current.load_full()
    }

    pub fn update(
        &self,
        mut next: RuntimeConfig,
    ) -> Result<std::sync::Arc<RuntimeConfig>, ConfigError> {
        next.validate()?;
        next.revision = self.next_revision.fetch_add(1, Ordering::SeqCst);
        let next = std::sync::Arc::new(next);
        self.current.store(next.clone());
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_atomically_and_rejects_invalid_values() {
        let store = ConfigStore::new(RuntimeConfig::default()).unwrap();
        let mut next = (*store.snapshot()).clone();
        next.idle_ttl = Duration::from_secs(120);
        let updated = store.update(next).unwrap();
        assert_eq!(updated.revision, 2);

        let mut invalid = (*updated).clone();
        invalid.map_scan_batch = 0;
        assert_eq!(store.update(invalid), Err(ConfigError::InvalidBatch));
        assert_eq!(store.snapshot().revision, 2);
    }
}
