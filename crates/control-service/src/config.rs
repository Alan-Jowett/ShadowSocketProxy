// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::mapping::{MapMaxima, RUNTIME_CONFIG_ABI_VERSION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerDescriptor {
    pub address: IpAddr,
    pub port: u16,
    pub ipv4_wildcard: bool,
    pub ipv6_wildcard: bool,
}

impl ListenerDescriptor {
    pub fn from_socket_addr(address: SocketAddr) -> Self {
        Self {
            address: address.ip(),
            port: address.port(),
            ipv4_wildcard: address.ip().is_unspecified() && address.is_ipv4(),
            ipv6_wildcard: address.ip().is_unspecified() && address.is_ipv6(),
        }
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub schema_version: u16,
    pub revision: u64,
    pub cleanup_interval: Duration,
    pub idle_ttl: Duration,
    pub map_scan_batch: usize,
    pub log_capacity: usize,
    pub active_flow_capacity: usize,
    pub tcp_terminal_grace: Duration,
    pub ipv4_target: Option<SocketAddr>,
    pub ipv6_target: Option<SocketAddr>,
    pub listener: ListenerDescriptor,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_CONFIG_ABI_VERSION,
            revision: 1,
            cleanup_interval: Duration::from_secs(10),
            idle_ttl: Duration::from_secs(60),
            map_scan_batch: 256,
            log_capacity: 1024,
            active_flow_capacity: 4096,
            tcp_terminal_grace: Duration::from_secs(30),
            ipv4_target: None,
            ipv6_target: None,
            listener: ListenerDescriptor::from_socket_addr(
                "0.0.0.0:50051".parse().expect("valid default listener"),
            ),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("cleanup interval must be non-zero")]
    ZeroCleanupInterval,
    #[error("runtime config schema version is unsupported")]
    UnsupportedSchemaVersion,
    #[error("idle TTL must be non-zero")]
    ZeroIdleTtl,
    #[error("map scan batch must be between 1 and 100000")]
    InvalidBatch,
    #[error("log capacity must be between 1 and 100000")]
    InvalidLogCapacity,
    #[error("cleanup interval must not exceed idle TTL")]
    IntervalExceedsTtl,
    #[error("active flow capacity must be between 1 and the ELF maximum")]
    InvalidFlowCapacity,
    #[error("active flow capacity requires three flow indexes per flow")]
    FlowIndexCapacityExceeded,
    #[error("TCP terminal grace must be non-zero")]
    ZeroTerminalGrace,
    #[error("runtime duration is too large")]
    DurationOverflow,
    #[error("listener port must be non-zero")]
    InvalidListenerPort,
    #[error("listener wildcard flags do not match the listener address")]
    InvalidListenerWildcard,
    #[error("target address and port must be set together")]
    PartialTarget,
    #[error("target address family does not match its field")]
    TargetFamilyMismatch,
    #[error("target address is unspecified")]
    UnspecifiedTarget,
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_with_maxima(MapMaxima::default())
    }

    pub fn validate_with_maxima(&self, maxima: MapMaxima) -> Result<(), ConfigError> {
        if self.schema_version != RUNTIME_CONFIG_ABI_VERSION {
            return Err(ConfigError::UnsupportedSchemaVersion);
        }
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
        if self.active_flow_capacity == 0 || self.active_flow_capacity > maxima.flow_state {
            return Err(ConfigError::InvalidFlowCapacity);
        }
        if self.active_flow_capacity.saturating_mul(3) > maxima.flow_index {
            return Err(ConfigError::FlowIndexCapacityExceeded);
        }
        if self.tcp_terminal_grace.is_zero() {
            return Err(ConfigError::ZeroTerminalGrace);
        }
        if self.listener.port == 0 {
            return Err(ConfigError::InvalidListenerPort);
        }
        if self.listener.ipv4_wildcard
            != (self.listener.address.is_unspecified() && self.listener.address.is_ipv4())
            || self.listener.ipv6_wildcard
                != (self.listener.address.is_unspecified() && self.listener.address.is_ipv6())
        {
            return Err(ConfigError::InvalidListenerWildcard);
        }
        validate_target(self.ipv4_target, true)?;
        validate_target(self.ipv6_target, false)?;
        if self.cleanup_interval.as_secs() > 365 * 24 * 60 * 60
            || self.idle_ttl.as_secs() > 365 * 24 * 60 * 60
            || self.tcp_terminal_grace.as_secs() > 365 * 24 * 60 * 60
        {
            return Err(ConfigError::DurationOverflow);
        }
        Ok(())
    }
}

fn validate_target(target: Option<SocketAddr>, ipv4: bool) -> Result<(), ConfigError> {
    let Some(target) = target else {
        return Ok(());
    };
    if target.port() == 0 {
        return Err(ConfigError::PartialTarget);
    }
    if target.ip().is_ipv4() != ipv4 {
        return Err(ConfigError::TargetFamilyMismatch);
    }
    if target.ip().is_unspecified() {
        return Err(ConfigError::UnspecifiedTarget);
    }
    Ok(())
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
        let config = RuntimeConfig {
            active_flow_capacity: MapMaxima::default().flow_state + 1,
            ..RuntimeConfig::default()
        };
        assert!(matches!(
            ConfigStore::new(config),
            Err(ConfigError::InvalidFlowCapacity)
        ));
    }

    #[test]
    fn target_pairs_are_atomic() {
        let config = RuntimeConfig {
            ipv4_target: Some("192.0.2.10:0".parse().unwrap()),
            ..RuntimeConfig::default()
        };
        assert!(matches!(
            ConfigStore::new(config),
            Err(ConfigError::PartialTarget)
        ));
    }

    #[test]
    fn listener_descriptor_round_trips_to_socket_address() {
        let address = "192.0.2.10:50051".parse().unwrap();
        let descriptor = ListenerDescriptor::from_socket_addr(address);
        assert_eq!(descriptor.socket_addr(), address);
    }
}
