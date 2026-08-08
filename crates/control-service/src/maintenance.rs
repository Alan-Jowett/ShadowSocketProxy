// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Scans flow-state or legacy mapping maps and removes expired entries without
//! blocking configuration or control-service readers.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use tokio::{sync::watch, task::JoinHandle, time};

use crate::{bpf::BpfBackend, config::ConfigStore, logs::LogRing, mapping::decode_value};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Cumulative counters for maintenance scans and cleanup outcomes.
pub struct MaintenanceSnapshot {
    /// Records examined across all cleanup passes.
    pub scanned: u64,
    /// Records intentionally left in the map.
    pub retained: u64,
    /// Records whose state or mapping was deleted successfully.
    pub deleted: u64,
    /// Legacy entries that could not be decoded.
    pub decode_failed: u64,
    /// Backend scan operations that failed.
    pub read_failed: u64,
    /// Backend deletion operations that failed.
    pub delete_failed: u64,
    /// Future-dated records retained as suspicious rather than deleted.
    pub anomalies: u64,
    /// Flow cleanups that removed only part of their state or indexes.
    pub partial_cleanups: u64,
}

#[derive(Default)]
/// Thread-safe counters and last-error state for the maintenance worker.
pub struct MaintenanceStats {
    /// Cumulative scan counters.
    snapshot: Mutex<MaintenanceSnapshot>,
    /// Most recent backend or decode error, if any.
    last_error: Mutex<Option<String>>,
}

impl MaintenanceStats {
    /// Clones the current counters without exposing their mutex.
    pub fn snapshot(&self) -> MaintenanceSnapshot {
        self.snapshot.lock().unwrap().clone()
    }

    /// Returns the most recent recorded error message.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    /// Applies one counter mutation while holding the state lock.
    fn update(&self, update: impl FnOnce(&mut MaintenanceSnapshot)) {
        update(&mut self.snapshot.lock().unwrap());
    }

    /// Replaces the recorded last-error message.
    fn error(&self, message: impl Into<String>) {
        *self.last_error.lock().unwrap() = Some(message.into());
    }
}

/// Returns nanoseconds elapsed from a process-local monotonic origin.
fn monotonic_now_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// Scans at most the configured batch, deleting expired flow-state records or
/// legacy mappings and recording failures in both stats and logs.
pub async fn run_once<B: BpfBackend + ?Sized>(
    backend: &B,
    config: &ConfigStore,
    stats: &MaintenanceStats,
    logs: &LogRing,
    now_ns: u64,
) {
    let snapshot = config.snapshot();
    match backend.list_flow_states().await {
        Ok(states) => {
            for (index, state) in states.into_iter().enumerate() {
                if index >= snapshot.map_scan_batch {
                    break;
                }
                stats.update(|value| value.scanned += 1);
                if !state.should_delete(
                    now_ns,
                    snapshot.idle_ttl.as_nanos().min(u64::MAX as u128) as u64,
                ) {
                    stats.update(|value| value.retained += 1);
                    continue;
                }
                match backend.delete_flow(state.flow_id, state.generation).await {
                    Ok(report) if report.partial => {
                        stats.update(|value| {
                            value.partial_cleanups += 1;
                            value.delete_failed += 1;
                        });
                        stats.error("flow cleanup was partial");
                        logs.append("ERROR", "flow cleanup was partial");
                    }
                    Ok(report) if report.state_deleted || report.indexes_deleted != 0 => {
                        stats.update(|value| value.deleted += 1);
                    }
                    Ok(_) => stats.update(|value| value.retained += 1),
                    Err(error) => {
                        stats.update(|value| value.delete_failed += 1);
                        stats.error(error.to_string());
                        logs.append("ERROR", format!("flow cleanup failed: {error}"));
                    }
                }
            }
            return;
        }
        Err(crate::bpf::BackendError::Unsupported) => {}
        Err(crate::bpf::BackendError::NotAttached) => return,
        Err(error) => {
            stats.update(|value| value.read_failed += 1);
            stats.error(error.to_string());
            logs.append("ERROR", format!("flow state scan failed: {error}"));
            return;
        }
    }
    let entries = match backend.list_entries().await {
        Ok(entries) => entries,
        Err(crate::bpf::BackendError::NotAttached) => return,
        Err(error) => {
            stats.update(|value| value.read_failed += 1);
            stats.error(error.to_string());
            logs.append("ERROR", format!("maintenance map scan failed: {error}"));
            return;
        }
    };
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index >= snapshot.map_scan_batch {
            break;
        }
        stats.update(|value| value.scanned += 1);
        let mapping = match decode_value(&key, &value) {
            Ok(mapping) => mapping,
            Err(error) => {
                stats.update(|value| value.decode_failed += 1);
                stats.error(error.to_string());
                logs.append("WARN", format!("maintenance decode failed: {error}"));
                continue;
            }
        };
        if mapping.last_seen_ns > now_ns {
            stats.update(|value| {
                value.retained += 1;
                value.anomalies += 1;
            });
            logs.append("WARN", "future mapping timestamp retained");
            continue;
        }
        let age = u128::from(now_ns.saturating_sub(mapping.last_seen_ns));
        if age < snapshot.idle_ttl.as_nanos() {
            stats.update(|value| value.retained += 1);
            continue;
        }
        match backend.delete_entry(&key).await {
            Ok(true) => stats.update(|value| value.deleted += 1),
            Ok(false) => {
                stats.update(|value| value.retained += 1);
                logs.append("INFO", "mapping disappeared during cleanup");
            }
            Err(error) => {
                stats.update(|value| value.delete_failed += 1);
                stats.error(error.to_string());
                logs.append("ERROR", format!("maintenance delete failed: {error}"));
            }
        }
    }
}

/// Starts a task that runs cleanup at the current configuration interval until
/// the shutdown watch becomes true.
pub fn spawn_worker<B: BpfBackend + 'static>(
    backend: Arc<B>,
    config: Arc<ConfigStore>,
    stats: Arc<MaintenanceStats>,
    logs: Arc<LogRing>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let interval = config.snapshot().cleanup_interval;
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                _ = time::sleep(interval) => {
                    run_once(&*backend, &config, &stats, &logs, monotonic_now_ns()).await;
                }
            }
        }
    })
}

#[allow(dead_code)]
/// Converts a duration to nanoseconds for compatibility checks and tests.
fn _duration_ns(duration: Duration) -> u64 {
    duration.as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bpf::InMemoryBackend,
        config::RuntimeConfig,
        mapping::{Mapping, Tuple, PROTOCOL_FLAG_TCP, PROTOCOL_TCP},
    };

    #[tokio::test]
    async fn deletes_idle_and_retains_active_and_future() {
        let backend = InMemoryBackend::default();
        for timestamp in [10, 95, 200] {
            backend.insert_mapping(Mapping {
                synthetic: Tuple {
                    source: format!("192.0.2.{timestamp}").parse().unwrap(),
                    destination: "198.51.100.1".parse().unwrap(),
                    protocol: PROTOCOL_TCP,
                    source_port: timestamp as u16,
                    destination_port: 443,
                },
                original: Tuple {
                    source: "192.0.2.1".parse().unwrap(),
                    destination: "198.51.100.1".parse().unwrap(),
                    protocol: PROTOCOL_TCP,
                    source_port: 1,
                    destination_port: 443,
                },
                last_seen_ns: timestamp,
                protocol_flags: PROTOCOL_FLAG_TCP,
                tcp_state_flags: 0,
            });
        }
        let config = RuntimeConfig {
            cleanup_interval: Duration::from_nanos(1),
            idle_ttl: Duration::from_nanos(50),
            ..RuntimeConfig::default()
        };
        let config = ConfigStore::new(config).unwrap();
        let stats = MaintenanceStats::default();
        let logs = LogRing::new(10);
        run_once(&backend, &config, &stats, &logs, 100).await;
        assert_eq!(stats.snapshot().deleted, 1);
        assert_eq!(stats.snapshot().retained, 2);
    }
}
