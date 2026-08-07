// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::mapping::MapMaxima;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub revision: u64,
    pub cleanup_interval: Duration,
    pub idle_ttl: Duration,
    pub map_scan_batch: usize,
    pub log_capacity: usize,
    pub destination_policy_capacity: usize,
    pub active_flow_capacity: usize,
    pub tcp_terminal_grace: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            revision: 1,
            cleanup_interval: Duration::from_secs(10),
            idle_ttl: Duration::from_secs(60),
            map_scan_batch: 256,
            log_capacity: 1024,
            destination_policy_capacity: 1024,
            active_flow_capacity: 4096,
            tcp_terminal_grace: Duration::from_secs(30),
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
    #[error("destination policy capacity must be between 1 and the ELF maximum")]
    InvalidPolicyCapacity,
    #[error("active flow capacity must be between 1 and the ELF maximum")]
    InvalidFlowCapacity,
    #[error("active flow capacity requires two directional indexes per flow")]
    FlowIndexCapacityExceeded,
    #[error("TCP terminal grace must be non-zero")]
    ZeroTerminalGrace,
    #[error("runtime duration is too large")]
    DurationOverflow,
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_with_maxima(MapMaxima::default())
    }

    pub fn validate_with_maxima(&self, maxima: MapMaxima) -> Result<(), ConfigError> {
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
        if self.destination_policy_capacity == 0 || self.destination_policy_capacity > maxima.policy
        {
            return Err(ConfigError::InvalidPolicyCapacity);
        }
        if self.active_flow_capacity == 0 || self.active_flow_capacity > maxima.flow_state {
            return Err(ConfigError::InvalidFlowCapacity);
        }
        if self.active_flow_capacity.saturating_mul(2) > maxima.flow_index {
            return Err(ConfigError::FlowIndexCapacityExceeded);
        }
        if self.tcp_terminal_grace.is_zero() {
            return Err(ConfigError::ZeroTerminalGrace);
        }
        if self.cleanup_interval.as_secs() > 365 * 24 * 60 * 60
            || self.idle_ttl.as_secs() > 365 * 24 * 60 * 60
            || self.tcp_terminal_grace.as_secs() > 365 * 24 * 60 * 60
        {
            return Err(ConfigError::DurationOverflow);
        }
        Ok(())
    }
}

pub struct ConfigStore {
    current: ArcSwap<RuntimeConfig>,
    next_revision: AtomicU64,
    maxima: MapMaxima,
}

impl ConfigStore {
    pub fn new(initial: RuntimeConfig) -> Result<Self, ConfigError> {
        Self::new_with_maxima(initial, MapMaxima::default())
    }

    pub fn new_with_maxima(initial: RuntimeConfig, maxima: MapMaxima) -> Result<Self, ConfigError> {
        initial.validate_with_maxima(maxima)?;
        Ok(Self {
            next_revision: AtomicU64::new(initial.revision + 1),
            current: ArcSwap::from_pointee(initial),
            maxima,
        })
    }

    pub fn snapshot(&self) -> std::sync::Arc<RuntimeConfig> {
        self.current.load_full()
    }

    pub fn update(
        &self,
        mut next: RuntimeConfig,
    ) -> Result<std::sync::Arc<RuntimeConfig>, ConfigError> {
        next.validate_with_maxima(self.maxima)?;
        next.revision = self.next_revision.fetch_add(1, Ordering::SeqCst);
        let next = std::sync::Arc::new(next);
        self.current.store(next.clone());
        Ok(next)
    }

    pub fn maxima(&self) -> MapMaxima {
        self.maxima
    }

    pub fn validate_snapshot_with_maxima(&self, maxima: MapMaxima) -> Result<(), ConfigError> {
        self.snapshot().validate_with_maxima(maxima)
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

    #[test]
    fn runtime_caps_cannot_exceed_fixed_elf_maxima() {
        let mut config = RuntimeConfig::default();
        config.destination_policy_capacity = MapMaxima::default().policy + 1;
        assert!(matches!(
            ConfigStore::new(config),
            Err(ConfigError::InvalidPolicyCapacity)
        ));
    }
}
