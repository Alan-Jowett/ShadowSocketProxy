// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use tokio::{sync::watch, task::JoinHandle, time};

use crate::{bpf::BpfBackend, config::ConfigStore, logs::LogRing, mapping::decode_value};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintenanceSnapshot {
    pub scanned: u64,
    pub retained: u64,
    pub deleted: u64,
    pub decode_failed: u64,
    pub read_failed: u64,
    pub delete_failed: u64,
    pub anomalies: u64,
}

#[derive(Default)]
pub struct MaintenanceStats {
    snapshot: Mutex<MaintenanceSnapshot>,
    last_error: Mutex<Option<String>>,
}

impl MaintenanceStats {
    pub fn snapshot(&self) -> MaintenanceSnapshot {
        self.snapshot.lock().unwrap().clone()
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    fn update(&self, update: impl FnOnce(&mut MaintenanceSnapshot)) {
        update(&mut self.snapshot.lock().unwrap());
    }

    fn error(&self, message: impl Into<String>) {
        *self.last_error.lock().unwrap() = Some(message.into());
    }
}

fn monotonic_now_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

pub async fn run_once<B: BpfBackend + ?Sized>(
    backend: &B,
    config: &ConfigStore,
    stats: &MaintenanceStats,
    logs: &LogRing,
    now_ns: u64,
) {
    let snapshot = config.snapshot();
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
        let mut config = RuntimeConfig::default();
        config.cleanup_interval = Duration::from_nanos(1);
        config.idle_ttl = Duration::from_nanos(50);
        let config = ConfigStore::new(config).unwrap();
        let stats = MaintenanceStats::default();
        let logs = LogRing::new(10);
        run_once(&backend, &config, &stats, &logs, 100).await;
        assert_eq!(stats.snapshot().deleted, 1);
        assert_eq!(stats.snapshot().retained, 2);
    }
}
