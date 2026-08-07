// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use tonic::{Request, Response, Status};

use crate::{
    bpf::{Attachment, BackendError, BpfBackend},
    config::{ConfigStore, RuntimeConfig},
    logs::{LogError, LogRing},
    maintenance::MaintenanceStats,
    mapping::{Mapping, Tuple},
    proto::{self, control_server::Control},
};

#[derive(Clone)]
pub struct ControlService {
    backend: Arc<dyn BpfBackend>,
    config: Arc<ConfigStore>,
    logs: Arc<LogRing>,
    stats: Arc<MaintenanceStats>,
    ready: Arc<AtomicBool>,
}

impl ControlService {
    pub fn new(
        backend: Arc<dyn BpfBackend>,
        config: Arc<ConfigStore>,
        logs: Arc<LogRing>,
        stats: Arc<MaintenanceStats>,
    ) -> Self {
        Self {
            backend,
            config,
            logs,
            stats,
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn map_backend_error(error: BackendError) -> Status {
        let message = error.to_string();
        match error {
            BackendError::MissingElf(_) | BackendError::InvalidInterface(_) => {
                Status::invalid_argument(message)
            }
            BackendError::AbiMismatch(_)
            | BackendError::Unsupported
            | BackendError::NotAttached => Status::failed_precondition(message),
            BackendError::Operation { .. } => Status::internal(message),
        }
    }
}

fn tuple_to_proto(tuple: &Tuple) -> proto::Tuple {
    let (family, source_address, destination_address) = match (tuple.source, tuple.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            (4, source.octets().to_vec(), destination.octets().to_vec())
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            (6, source.octets().to_vec(), destination.octets().to_vec())
        }
        _ => (0, Vec::new(), Vec::new()),
    };
    proto::Tuple {
        family: family as u32,
        source_address,
        destination_address,
        protocol: tuple.protocol as u32,
        source_port: tuple.source_port as u32,
        destination_port: tuple.destination_port as u32,
    }
}

fn tuple_from_proto(tuple: Option<proto::Tuple>) -> Result<Tuple, Status> {
    let tuple = tuple.ok_or_else(|| Status::invalid_argument("synthetic tuple is required"))?;
    let source = match tuple.family {
        4 if tuple.source_address.len() == 4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(tuple.source_address).unwrap(),
        )),
        6 if tuple.source_address.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(tuple.source_address).unwrap(),
        )),
        _ => return Err(Status::invalid_argument("invalid source address/family")),
    };
    let destination = match tuple.family {
        4 if tuple.destination_address.len() == 4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(tuple.destination_address).unwrap(),
        )),
        6 if tuple.destination_address.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(tuple.destination_address).unwrap(),
        )),
        _ => {
            return Err(Status::invalid_argument(
                "invalid destination address/family",
            ))
        }
    };
    if tuple.protocol > u8::MAX as u32
        || tuple.source_port > u16::MAX as u32
        || tuple.destination_port > u16::MAX as u32
    {
        return Err(Status::invalid_argument("tuple field is out of range"));
    }
    Ok(Tuple {
        source,
        destination,
        protocol: tuple.protocol as u8,
        source_port: tuple.source_port as u16,
        destination_port: tuple.destination_port as u16,
    })
}

fn mapping_to_proto(mapping: Mapping) -> proto::Mapping {
    proto::Mapping {
        synthetic: Some(tuple_to_proto(&mapping.synthetic)),
        original: Some(tuple_to_proto(&mapping.original)),
        last_seen_ns: mapping.last_seen_ns,
        protocol_flags: mapping.protocol_flags,
        tcp_state_flags: mapping.tcp_state_flags,
    }
}

fn config_to_proto(config: Arc<RuntimeConfig>) -> proto::ConfigReply {
    proto::ConfigReply {
        revision: config.revision,
        config: Some(proto::Config {
            cleanup_interval_ms: config.cleanup_interval.as_millis() as u64,
            idle_ttl_ms: config.idle_ttl.as_millis() as u64,
            map_scan_batch: config.map_scan_batch as u32,
            log_capacity: config.log_capacity as u32,
        }),
    }
}

fn runtime_config_from_proto(config: Option<proto::Config>) -> Result<RuntimeConfig, Status> {
    let config = config.ok_or_else(|| Status::invalid_argument("config is required"))?;
    Ok(RuntimeConfig {
        revision: 0,
        cleanup_interval: std::time::Duration::from_millis(config.cleanup_interval_ms),
        idle_ttl: std::time::Duration::from_millis(config.idle_ttl_ms),
        map_scan_batch: config.map_scan_batch as usize,
        log_capacity: config.log_capacity as usize,
    })
}

#[tonic::async_trait]
impl Control for ControlService {
    async fn attach(
        &self,
        request: Request<proto::InterfaceRequest>,
    ) -> Result<Response<proto::OperationReply>, Status> {
        let request = request.into_inner();
        if request.elf_path.is_empty() || request.interfaces.is_empty() {
            return Err(Status::invalid_argument(
                "elf_path and interfaces are required",
            ));
        }
        match self
            .backend
            .attach(&PathBuf::from(request.elf_path), &request.interfaces)
            .await
        {
            Ok(_) => Ok(Response::new(proto::OperationReply {
                success: true,
                message: "attached ingress and egress".into(),
                failures: Vec::new(),
            })),
            Err(error) => {
                self.logs.append("ERROR", format!("attach failed: {error}"));
                Err(Self::map_backend_error(error))
            }
        }
    }

    async fn detach(
        &self,
        request: Request<proto::DetachRequest>,
    ) -> Result<Response<proto::OperationReply>, Status> {
        let request = request.into_inner();
        let interfaces = if request.all {
            None
        } else if request.interfaces.is_empty() {
            return Err(Status::invalid_argument("interfaces or all is required"));
        } else {
            Some(request.interfaces.as_slice())
        };
        self.backend
            .detach(interfaces)
            .await
            .map_err(Self::map_backend_error)?;
        Ok(Response::new(proto::OperationReply {
            success: true,
            message: "detached".into(),
            failures: Vec::new(),
        }))
    }

    async fn list_mappings(
        &self,
        request: Request<proto::ListMappingsRequest>,
    ) -> Result<Response<proto::ListMappingsReply>, Status> {
        let request = request.into_inner();
        let limit = if request.limit == 0 {
            256
        } else {
            request.limit as usize
        };
        if limit > 10_000 {
            return Err(Status::resource_exhausted(
                "mapping page limit is too large",
            ));
        }
        let offset = if request.page_token.is_empty() {
            0
        } else if request.page_token.len() == 8 {
            u64::from_be_bytes(request.page_token.as_slice().try_into().unwrap()) as usize
        } else {
            return Err(Status::invalid_argument("invalid page token"));
        };
        let entries = self
            .backend
            .list_entries()
            .await
            .map_err(Self::map_backend_error)?;
        let mut entries = entries;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut mappings = Vec::new();
        let mut skipped = 0;
        for (index, (key, value)) in entries.into_iter().enumerate().skip(offset) {
            if mappings.len() >= limit {
                return Ok(Response::new(proto::ListMappingsReply {
                    mappings,
                    next_page_token: (index as u64).to_be_bytes().to_vec(),
                    skipped_entries: skipped,
                }));
            }
            match crate::mapping::decode_value(&key, &value) {
                Ok(mapping) => mappings.push(mapping_to_proto(mapping)),
                Err(error) => {
                    skipped += 1;
                    self.logs
                        .append("WARN", format!("mapping skipped: {error}"));
                }
            }
        }
        Ok(Response::new(proto::ListMappingsReply {
            mappings,
            next_page_token: Vec::new(),
            skipped_entries: skipped,
        }))
    }

    async fn get_mapping(
        &self,
        request: Request<proto::GetMappingRequest>,
    ) -> Result<Response<proto::Mapping>, Status> {
        let tuple = tuple_from_proto(request.into_inner().synthetic)?;
        let key = crate::mapping::encode_key(&tuple);
        let value = self
            .backend
            .get_entry(&key)
            .await
            .map_err(Self::map_backend_error)?
            .ok_or_else(|| Status::not_found("mapping not found"))?;
        let mapping = crate::mapping::decode_value(&key, &value)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(mapping_to_proto(mapping)))
    }

    async fn get_status(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<proto::StatusReply>, Status> {
        let stats = self.stats.snapshot();
        Ok(Response::new(proto::StatusReply {
            ready: self.is_ready(),
            abi_version: crate::mapping::ABI_VERSION as u32,
            attachments: self
                .backend
                .attachments()
                .into_iter()
                .map(
                    |Attachment {
                         interface,
                         direction,
                     }| format!("{interface}:{direction:?}"),
                )
                .collect(),
            scanned: stats.scanned,
            retained: stats.retained,
            deleted: stats.deleted,
            errors: stats.decode_failed + stats.read_failed + stats.delete_failed + stats.anomalies,
            last_error: self.stats.last_error().unwrap_or_default(),
        }))
    }

    async fn get_config(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<proto::ConfigReply>, Status> {
        Ok(Response::new(config_to_proto(self.config.snapshot())))
    }

    async fn set_config(
        &self,
        request: Request<proto::SetConfigRequest>,
    ) -> Result<Response<proto::ConfigReply>, Status> {
        let next = runtime_config_from_proto(request.into_inner().config)?;
        let updated = self
            .config
            .update(next)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        self.logs.set_capacity(updated.log_capacity);
        Ok(Response::new(config_to_proto(updated)))
    }

    async fn pull_logs(
        &self,
        request: Request<proto::PullLogsRequest>,
    ) -> Result<Response<proto::PullLogsReply>, Status> {
        let request = request.into_inner();
        let limit = if request.limit == 0 {
            256
        } else {
            request.limit as usize
        };
        let (records, next_cursor) =
            self.logs
                .pull(request.cursor, limit)
                .map_err(|error| match error {
                    LogError::CursorExpired { .. } => {
                        Status::failed_precondition(error.to_string())
                    }
                })?;
        Ok(Response::new(proto::PullLogsReply {
            records: records
                .into_iter()
                .map(|record| proto::LogRecord {
                    sequence: record.sequence,
                    level: record.level,
                    message: record.message,
                })
                .collect(),
            next_cursor,
        }))
    }

    async fn health(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<proto::HealthReply>, Status> {
        Ok(Response::new(proto::HealthReply {
            live: true,
            ready: self.is_ready(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bpf::InMemoryBackend,
        config::RuntimeConfig,
        mapping::{Mapping, PROTOCOL_FLAG_UDP, PROTOCOL_UDP},
    };
    use std::time::Duration;

    fn service() -> (Arc<InMemoryBackend>, ControlService) {
        let backend = Arc::new(InMemoryBackend::default());
        let config = Arc::new(ConfigStore::new(RuntimeConfig::default()).unwrap());
        let logs = Arc::new(LogRing::new(4));
        let stats = Arc::new(MaintenanceStats::default());
        (
            backend.clone(),
            ControlService::new(backend, config, logs, stats),
        )
    }

    #[tokio::test]
    async fn mapping_rpc_preserves_tuple_and_not_found_is_distinct() {
        let (backend, service) = service();
        backend.insert_mapping(Mapping {
            synthetic: Tuple {
                source: "192.0.2.10".parse().unwrap(),
                destination: "198.51.100.10".parse().unwrap(),
                protocol: PROTOCOL_UDP,
                source_port: 5000,
                destination_port: 443,
            },
            original: Tuple {
                source: "2001:db8::10".parse().unwrap(),
                destination: "2001:db8::20".parse().unwrap(),
                protocol: PROTOCOL_UDP,
                source_port: 5000,
                destination_port: 443,
            },
            last_seen_ns: 9,
            protocol_flags: PROTOCOL_FLAG_UDP,
            tcp_state_flags: 0,
        });
        let response = service
            .get_mapping(Request::new(proto::GetMappingRequest {
                synthetic: Some(proto::Tuple {
                    family: 4,
                    source_address: vec![192, 0, 2, 10],
                    destination_address: vec![198, 51, 100, 10],
                    protocol: PROTOCOL_UDP as u32,
                    source_port: 5000,
                    destination_port: 443,
                }),
            }))
            .await
            .unwrap();
        assert_eq!(response.into_inner().last_seen_ns, 9);
        let missing = service
            .get_mapping(Request::new(proto::GetMappingRequest {
                synthetic: Some(proto::Tuple {
                    family: 4,
                    source_address: vec![192, 0, 2, 11],
                    destination_address: vec![198, 51, 100, 10],
                    protocol: PROTOCOL_UDP as u32,
                    source_port: 5000,
                    destination_port: 443,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn config_rpc_rejects_partial_invalid_update_and_pull_logs() {
        let (_, service) = service();
        let invalid = service
            .set_config(Request::new(proto::SetConfigRequest {
                config: Some(proto::Config {
                    cleanup_interval_ms: 0,
                    idle_ttl_ms: 1,
                    map_scan_batch: 1,
                    log_capacity: 1,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
        service.logs.append("INFO", "ready");
        let logs = service
            .pull_logs(Request::new(proto::PullLogsRequest {
                cursor: 0,
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(logs.records.len(), 1);
        assert_eq!(
            service.config.snapshot().cleanup_interval,
            Duration::from_secs(10)
        );
    }
}
