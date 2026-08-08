// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Validates and publishes the runtime settings shared by gRPC, maintenance,
//! and the BPF map writer.

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::mapping::{MapMaxima, RUNTIME_CONFIG_ABI_VERSION};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Listener address plus the wildcard flags required by the BPF ABI.
pub struct ListenerDescriptor {
    /// Address on which the control transport listens.
    pub address: IpAddr,
    /// Non-zero control listener port.
    pub port: u16,
    /// True only when `address` is an IPv4 unspecified address.
    pub ipv4_wildcard: bool,
    /// True only when `address` is an IPv6 unspecified address.
    pub ipv6_wildcard: bool,
}

impl ListenerDescriptor {
    /// Splits a socket address and derives family-specific wildcard flags.
    pub fn from_socket_addr(address: SocketAddr) -> Self {
        Self {
            address: address.ip(),
            port: address.port(),
            ipv4_wildcard: address.ip().is_unspecified() && address.is_ipv4(),
            ipv6_wildcard: address.ip().is_unspecified() && address.is_ipv6(),
        }
    }

    /// Reconstructs the socket address represented by this descriptor.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Validated settings written to the BPF runtime-config map and read by workers.
pub struct RuntimeConfig {
    /// Runtime-config ABI version required by the BPF program.
    pub schema_version: u16,
    /// Monotonic revision assigned when the store publishes a configuration.
    pub revision: u64,
    /// Delay between maintenance scans.
    pub cleanup_interval: Duration,
    /// Age after which an otherwise active flow or mapping is eligible for cleanup.
    pub idle_ttl: Duration,
    /// Maximum number of map records examined by one cleanup pass.
    pub map_scan_batch: usize,
    /// Maximum number of log records retained by the bounded ring.
    pub log_capacity: usize,
    /// Requested active-flow capacity, bounded by the loaded map maxima.
    pub active_flow_capacity: usize,
    /// Grace period retained after both TCP FIN exchanges complete.
    pub tcp_terminal_grace: Duration,
    /// Optional IPv4 redirection target; address and port must be paired.
    pub ipv4_target: Option<SocketAddr>,
    /// Optional IPv6 redirection target; address and port must be paired.
    pub ipv6_target: Option<SocketAddr>,
    /// Immutable control listener descriptor.
    pub listener: ListenerDescriptor,
}

impl Default for RuntimeConfig {
    /// Returns the protocol-compatible baseline configuration for port 50051.
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
/// Validation failures that prevent an unsafe or ABI-incompatible configuration.
pub enum ConfigError {
    #[error("cleanup interval must be non-zero")]
    /// Maintenance cannot run with a zero interval.
    ZeroCleanupInterval,
    #[error("runtime config schema version is unsupported")]
    /// The requested runtime-config ABI is not understood.
    UnsupportedSchemaVersion,
    #[error("idle TTL must be non-zero")]
    /// Flow cleanup requires a non-zero idle lifetime.
    ZeroIdleTtl,
    #[error("map scan batch must be between 1 and 100000")]
    /// The scan batch is outside the supported 1..=100000 range.
    InvalidBatch,
    #[error("log capacity must be between 1 and 100000")]
    /// The log ring capacity is outside the supported 1..=100000 range.
    InvalidLogCapacity,
    #[error("cleanup interval must not exceed idle TTL")]
    /// A cleanup interval longer than the idle TTL could miss expiration.
    IntervalExceedsTtl,
    #[error("active flow capacity must be between 1 and the ELF maximum")]
    /// Active-flow capacity is zero or exceeds the state-map maximum.
    InvalidFlowCapacity,
    #[error("active flow capacity requires three flow indexes per flow")]
    /// Three tuple indexes per active flow would exceed the index-map maximum.
    FlowIndexCapacityExceeded,
    #[error("TCP terminal grace must be non-zero")]
    /// TCP terminal retention requires a non-zero grace period.
    ZeroTerminalGrace,
    #[error("runtime duration is too large")]
    /// A duration cannot be represented safely by the BPF nanosecond fields.
    DurationOverflow,
    #[error("listener port must be non-zero")]
    /// The control listener port is zero.
    InvalidListenerPort,
    #[error("listener wildcard flags do not match the listener address")]
    /// Wildcard flags disagree with the listener address family or value.
    InvalidListenerWildcard,
    #[error("target address and port must be set together")]
    /// A target supplied only an address or only a port.
    PartialTarget,
    #[error("target address family does not match its field")]
    /// An IPv4/IPv6 target was supplied in the opposite target field.
    TargetFamilyMismatch,
    #[error("target address is unspecified")]
    /// A target address is unspecified and cannot identify a destination.
    UnspecifiedTarget,
}

impl RuntimeConfig {
    /// Validates against the compiled-in map capacities.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_with_maxima(MapMaxima::default())
    }

    /// Validates ABI versions, bounds, address families, and map capacity
    /// constraints before publication or BPF writes.
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

/// Checks optional target pairing, family, port, and address specificity.
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

/// Atomically published configuration with revision assignment and map maxima.
pub struct ConfigStore {
    /// Last validated configuration visible to readers.
    current: ArcSwap<RuntimeConfig>,
    /// Counter used to assign the next published revision.
    next_revision: AtomicU64,
    /// Map capacities used to validate every update.
    maxima: MapMaxima,
}

impl ConfigStore {
    /// Creates a store using the shipped BPF map capacities.
    pub fn new(initial: RuntimeConfig) -> Result<Self, ConfigError> {
        Self::new_with_maxima(initial, MapMaxima::default())
    }

    /// Validates and publishes an initial configuration against explicit maxima.
    pub fn new_with_maxima(initial: RuntimeConfig, maxima: MapMaxima) -> Result<Self, ConfigError> {
        initial.validate_with_maxima(maxima)?;
        Ok(Self {
            next_revision: AtomicU64::new(initial.revision + 1),
            current: ArcSwap::from_pointee(initial),
            maxima,
        })
    }

    /// Loads a consistent, reference-counted configuration snapshot.
    pub fn snapshot(&self) -> std::sync::Arc<RuntimeConfig> {
        self.current.load_full()
    }

    /// Validates, assigns a fresh revision, and atomically publishes `next`.
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

    /// Returns the map capacities enforced by this store.
    pub fn maxima(&self) -> MapMaxima {
        self.maxima
    }

    /// Revalidates the current snapshot against capacities reported after attach.
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
