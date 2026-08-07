// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use thiserror::Error;

use crate::mapping::{encode_key, encode_value, Mapping, ABI_VERSION};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendError {
    #[error("ELF path does not exist: {0}")]
    MissingElf(PathBuf),
    #[error("invalid interface name: {0}")]
    InvalidInterface(String),
    #[error("backend failure at {location}: {message}")]
    Operation { location: String, message: String },
    #[error("backend does not support Linux TC operations")]
    Unsupported,
    #[error("ABI version {0} is not supported")]
    AbiMismatch(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub interface: String,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Default)]
pub struct AttachReport {
    pub attachments: Vec<Attachment>,
}

#[async_trait]
pub trait BpfBackend: Send + Sync {
    async fn attach(&self, elf: &Path, interfaces: &[String])
        -> Result<AttachReport, BackendError>;
    async fn detach(&self, interfaces: Option<&[String]>) -> Result<(), BackendError>;
    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError>;
    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError>;
    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError>;
    fn attachments(&self) -> Vec<Attachment>;
}

#[derive(Default)]
struct MemoryState {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
    attachments: Vec<Attachment>,
    fail_attach: Option<String>,
    fail_delete: Option<Vec<u8>>,
    fail_list: bool,
}

#[derive(Clone, Default)]
pub struct InMemoryBackend {
    state: Arc<Mutex<MemoryState>>,
}

impl InMemoryBackend {
    pub fn insert_mapping(&self, mapping: Mapping) {
        let mut state = self.state.lock().unwrap();
        state.entries.insert(
            encode_key(&mapping.synthetic).to_vec(),
            encode_value(&mapping).to_vec(),
        );
    }

    pub fn set_attach_failure(&self, location: Option<String>) {
        self.state.lock().unwrap().fail_attach = location;
    }

    pub fn set_delete_failure(&self, key: Option<Vec<u8>>) {
        self.state.lock().unwrap().fail_delete = key;
    }

    pub fn set_list_failure(&self, failure: bool) {
        self.state.lock().unwrap().fail_list = failure;
    }
}

#[async_trait]
impl BpfBackend for InMemoryBackend {
    async fn attach(
        &self,
        _elf: &Path,
        interfaces: &[String],
    ) -> Result<AttachReport, BackendError> {
        let mut state = self.state.lock().unwrap();
        for interface in interfaces {
            if interface.is_empty() || interface.len() > 15 {
                return Err(BackendError::InvalidInterface(interface.clone()));
            }
        }
        let required = interfaces
            .iter()
            .flat_map(|interface| {
                [
                    Attachment {
                        interface: interface.clone(),
                        direction: Direction::Ingress,
                    },
                    Attachment {
                        interface: interface.clone(),
                        direction: Direction::Egress,
                    },
                ]
            })
            .collect::<Vec<_>>();
        let existing = state.attachments.clone();
        for attachment in &required {
            if state.fail_attach.as_deref().is_some_and(|location| {
                location == format!("{}:{:?}", attachment.interface, attachment.direction)
            }) {
                state.attachments = existing;
                return Err(BackendError::Operation {
                    location: format!("{}:{:?}", attachment.interface, attachment.direction),
                    message: "in-memory injected failure (transaction rolled back)".into(),
                });
            }
        }
        for attachment in &required {
            if !state.attachments.contains(attachment) {
                state.attachments.push(attachment.clone());
            }
        }
        Ok(AttachReport {
            attachments: required,
        })
    }

    async fn detach(&self, interfaces: Option<&[String]>) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        state.attachments.retain(|attachment| {
            interfaces
                .map(|selected| !selected.contains(&attachment.interface))
                .unwrap_or(false)
        });
        Ok(())
    }

    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError> {
        let state = self.state.lock().unwrap();
        if state.fail_list {
            return Err(BackendError::Operation {
                location: "map:list".into(),
                message: "in-memory injected list failure".into(),
            });
        }
        Ok(state
            .entries
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self.state.lock().unwrap().entries.get(key).cloned())
    }

    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError> {
        let mut state = self.state.lock().unwrap();
        if state.fail_delete.as_deref() == Some(key) {
            return Err(BackendError::Operation {
                location: "map:delete".into(),
                message: "in-memory injected delete failure".into(),
            });
        }
        Ok(state.entries.remove(key).is_some())
    }

    fn attachments(&self) -> Vec<Attachment> {
        self.state.lock().unwrap().attachments.clone()
    }
}

#[async_trait]
pub trait LinuxTcAdapter: Send + Sync {
    async fn load_elf(&self, elf: &Path, abi_version: u16) -> Result<(), BackendError>;
    async fn attach(&self, interface: &str, direction: Direction) -> Result<(), BackendError>;
    async fn detach(&self, interface: &str, direction: Direction) -> Result<(), BackendError>;
    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError>;
    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError>;
    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError>;
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub struct UnsupportedLinuxTcAdapter;

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl LinuxTcAdapter for UnsupportedLinuxTcAdapter {
    async fn load_elf(&self, _elf: &Path, _abi_version: u16) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn attach(&self, _interface: &str, _direction: Direction) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn detach(&self, _interface: &str, _direction: Direction) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn get_entry(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn delete_entry(&self, _key: &[u8]) -> Result<bool, BackendError> {
        Err(BackendError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
pub const MAP_NAME_V1: &str = "ssp_flow_map_v1";
#[cfg(target_os = "linux")]
pub const INGRESS_PROGRAM_NAME_V1: &str = "ssp_tc_ingress_v1";
#[cfg(target_os = "linux")]
pub const EGRESS_PROGRAM_NAME_V1: &str = "ssp_tc_egress_v1";

#[cfg(target_os = "linux")]
struct AyaLink {
    attachment: Attachment,
    id: aya::programs::tc::SchedClassifierLinkId,
}

#[cfg(target_os = "linux")]
struct AyaState {
    elf: PathBuf,
    bpf: aya::Ebpf,
    links: Vec<AyaLink>,
}

#[cfg(target_os = "linux")]
pub struct AyaLinuxTcAdapter {
    state: Mutex<Option<AyaState>>,
}

#[cfg(target_os = "linux")]
impl Default for AyaLinuxTcAdapter {
    fn default() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }
}

#[cfg(target_os = "linux")]
impl AyaLinuxTcAdapter {
    fn operation(location: impl Into<String>, error: impl std::fmt::Display) -> BackendError {
        BackendError::Operation {
            location: location.into(),
            message: error.to_string(),
        }
    }

    fn map_error(error: impl std::fmt::Display) -> BackendError {
        Self::operation("map", error)
    }

    fn with_map<T>(
        bpf: &mut aya::Ebpf,
        operation: impl FnOnce(
            &mut aya::maps::HashMap<
                &mut aya::maps::MapData,
                [u8; crate::mapping::KEY_LEN],
                [u8; crate::mapping::VALUE_LEN],
            >,
        ) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let map = bpf
            .map_mut(MAP_NAME_V1)
            .ok_or_else(|| Self::operation("map", "versioned mapping map is missing"))?;
        let mut map = aya::maps::HashMap::try_from(map).map_err(Self::map_error)?;
        operation(&mut map)
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl LinuxTcAdapter for AyaLinuxTcAdapter {
    async fn load_elf(&self, elf: &Path, abi_version: u16) -> Result<(), BackendError> {
        if abi_version != ABI_VERSION {
            return Err(BackendError::AbiMismatch(abi_version));
        }

        let mut state = self.state.lock().unwrap();
        if let Some(current) = state.as_ref() {
            if current.elf == elf {
                return Ok(());
            }
            if !current.links.is_empty() {
                return Err(Self::operation(
                    "load",
                    "cannot replace an ELF while owned TC links are attached",
                ));
            }
        }

        let mut bpf = aya::Ebpf::load_file(elf)
            .map_err(|error| Self::operation("load", format!("ELF load failed: {error}")))?;
        if bpf.map(MAP_NAME_V1).is_none() {
            return Err(Self::operation(
                "map",
                format!("required map {MAP_NAME_V1} is missing"),
            ));
        }
        Self::with_map(&mut bpf, |_| Ok(()))?;

        for program_name in [INGRESS_PROGRAM_NAME_V1, EGRESS_PROGRAM_NAME_V1] {
            let program = bpf.program_mut(program_name).ok_or_else(|| {
                Self::operation(
                    format!("program:{program_name}"),
                    "required TC program is missing",
                )
            })?;
            let classifier: &mut aya::programs::SchedClassifier = program
                .try_into()
                .map_err(|error| Self::operation(format!("program:{program_name}"), error))?;
            classifier
                .load()
                .map_err(|error| Self::operation(format!("program:{program_name}"), error))?;
        }

        *state = Some(AyaState {
            elf: elf.to_path_buf(),
            bpf,
            links: Vec::new(),
        });
        Ok(())
    }

    async fn attach(&self, interface: &str, direction: Direction) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        let state = state
            .as_mut()
            .ok_or_else(|| Self::operation("attach", "no ELF has been loaded"))?;
        let attachment = Attachment {
            interface: interface.to_owned(),
            direction,
        };
        if state.links.iter().any(|link| link.attachment == attachment) {
            return Ok(());
        }

        match aya::programs::tc::qdisc_add_clsact(interface) {
            Ok(()) | Err(aya::programs::tc::TcError::AlreadyAttached) => {}
            Err(error) => {
                return Err(Self::operation(
                    format!("{interface}:{direction:?}"),
                    format!("clsact setup failed: {error}"),
                ));
            }
        }

        let (program_name, attach_type) = match direction {
            Direction::Ingress => (
                INGRESS_PROGRAM_NAME_V1,
                aya::programs::TcAttachType::Ingress,
            ),
            Direction::Egress => (EGRESS_PROGRAM_NAME_V1, aya::programs::TcAttachType::Egress),
        };
        let link_id = {
            let program = state.bpf.program_mut(program_name).ok_or_else(|| {
                Self::operation(
                    format!("program:{program_name}"),
                    "required TC program is missing",
                )
            })?;
            let classifier: &mut aya::programs::SchedClassifier = program
                .try_into()
                .map_err(|error| Self::operation(format!("program:{program_name}"), error))?;
            classifier
                .attach(interface, attach_type)
                .map_err(|error| Self::operation(format!("{interface}:{direction:?}"), error))?
        };
        state.links.push(AyaLink {
            attachment,
            id: link_id,
        });
        Ok(())
    }

    async fn detach(&self, interface: &str, direction: Direction) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        let state = state
            .as_mut()
            .ok_or_else(|| Self::operation("detach", "no ELF has been loaded"))?;
        let index = state
            .links
            .iter()
            .position(|link| {
                link.attachment.interface == interface && link.attachment.direction == direction
            })
            .ok_or_else(|| {
                Self::operation(
                    format!("{interface}:{direction:?}"),
                    "owned link is missing",
                )
            })?;
        let link_id = state.links[index].id;
        let program_name = match direction {
            Direction::Ingress => INGRESS_PROGRAM_NAME_V1,
            Direction::Egress => EGRESS_PROGRAM_NAME_V1,
        };
        let result = {
            let program = state.bpf.program_mut(program_name).ok_or_else(|| {
                Self::operation(
                    format!("program:{program_name}"),
                    "required TC program is missing",
                )
            })?;
            let classifier: &mut aya::programs::SchedClassifier = program
                .try_into()
                .map_err(|error| Self::operation(format!("program:{program_name}"), error))?;
            classifier.detach(link_id)
        };
        result.map_err(|error| Self::operation(format!("{interface}:{direction:?}"), error))?;
        state.links.remove(index);
        Ok(())
    }

    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError> {
        let mut state = self.state.lock().unwrap();
        let state = state
            .as_mut()
            .ok_or_else(|| Self::operation("map:list", "no ELF has been loaded"))?;
        Self::with_map(&mut state.bpf, |map| {
            map.iter()
                .map(|entry| {
                    entry
                        .map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .map_err(Self::map_error)
                })
                .collect()
        })
    }

    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        let key: [u8; crate::mapping::KEY_LEN] = key.try_into().map_err(|_| {
            Self::operation(
                "map:get",
                format!("invalid mapping key length: {}", key.len()),
            )
        })?;
        let mut state = self.state.lock().unwrap();
        let state = state
            .as_mut()
            .ok_or_else(|| Self::operation("map:get", "no ELF has been loaded"))?;
        Self::with_map(&mut state.bpf, |map| {
            map.get(&key, 0)
                .map(|value| Some(value.to_vec()))
                .or_else(|error| match error {
                    aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound => {
                        Ok(None)
                    }
                    error => Err(Self::map_error(error)),
                })
        })
    }

    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError> {
        let key: [u8; crate::mapping::KEY_LEN] = key.try_into().map_err(|_| {
            Self::operation(
                "map:delete",
                format!("invalid mapping key length: {}", key.len()),
            )
        })?;
        let mut state = self.state.lock().unwrap();
        let state = state
            .as_mut()
            .ok_or_else(|| Self::operation("map:delete", "no ELF has been loaded"))?;
        Self::with_map(&mut state.bpf, |map| {
            let existed = map
                .get(&key, 0)
                .map(|_| true)
                .or_else(|error| match error {
                    aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound => {
                        Ok(false)
                    }
                    error => Err(Self::map_error(error)),
                })?;
            if existed {
                map.remove(&key).map_err(Self::map_error)?;
            }
            Ok(existed)
        })
    }
}

pub struct LinuxBpfBackend {
    adapter: Arc<dyn LinuxTcAdapter>,
    attachments: Arc<Mutex<Vec<Attachment>>>,
}

impl Default for LinuxBpfBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxBpfBackend {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::with_adapter(Arc::new(AyaLinuxTcAdapter::default()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::with_adapter(Arc::new(UnsupportedLinuxTcAdapter))
        }
    }

    pub fn with_adapter(adapter: Arc<dyn LinuxTcAdapter>) -> Self {
        Self {
            adapter,
            attachments: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl BpfBackend for LinuxBpfBackend {
    async fn attach(
        &self,
        elf: &Path,
        interfaces: &[String],
    ) -> Result<AttachReport, BackendError> {
        if !elf.exists() {
            return Err(BackendError::MissingElf(elf.to_path_buf()));
        }
        if interfaces.is_empty() {
            return Err(BackendError::InvalidInterface(
                "no interfaces supplied".into(),
            ));
        }
        for interface in interfaces {
            if interface.is_empty() || interface.len() > 15 {
                return Err(BackendError::InvalidInterface(interface.clone()));
            }
        }
        self.adapter.load_elf(elf, ABI_VERSION).await?;
        let mut created: Vec<Attachment> = Vec::new();
        for interface in interfaces {
            for direction in [Direction::Ingress, Direction::Egress] {
                let attachment = Attachment {
                    interface: interface.clone(),
                    direction,
                };
                if self.attachments.lock().unwrap().contains(&attachment) {
                    continue;
                }
                if let Err(error) = self.adapter.attach(interface, direction).await {
                    let mut rollback_failures = Vec::new();
                    for prior in &created {
                        if let Err(rollback_error) =
                            self.adapter.detach(&prior.interface, prior.direction).await
                        {
                            rollback_failures.push(format!(
                                "{}:{:?}: {rollback_error}",
                                prior.interface, prior.direction
                            ));
                        }
                    }
                    let rollback = if rollback_failures.is_empty() {
                        "transaction rolled back".to_owned()
                    } else {
                        format!(
                            "transaction rollback incomplete: {}",
                            rollback_failures.join("; ")
                        )
                    };
                    return Err(BackendError::Operation {
                        location: format!("{interface}:{direction:?}"),
                        message: format!("{error} ({rollback})"),
                    });
                }
                created.push(attachment);
            }
        }
        self.attachments.lock().unwrap().extend(created.clone());
        Ok(AttachReport {
            attachments: self.attachments(),
        })
    }

    async fn detach(&self, interfaces: Option<&[String]>) -> Result<(), BackendError> {
        let owned = self.attachments();
        let selected = owned
            .into_iter()
            .filter(|attachment| {
                interfaces
                    .map(|items| items.contains(&attachment.interface))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        let mut failures = Vec::new();
        let mut detached = Vec::new();
        for attachment in &selected {
            if let Err(error) = self
                .adapter
                .detach(&attachment.interface, attachment.direction)
                .await
            {
                failures.push(format!(
                    "{}:{:?}: {error}",
                    attachment.interface, attachment.direction
                ));
            } else {
                detached.push(attachment.clone());
            }
        }
        self.attachments
            .lock()
            .unwrap()
            .retain(|attachment| !detached.contains(attachment));
        if !failures.is_empty() {
            return Err(BackendError::Operation {
                location: "detach".into(),
                message: failures.join("; "),
            });
        }
        Ok(())
    }

    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError> {
        self.adapter.list_entries().await
    }

    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.adapter.get_entry(key).await
    }

    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError> {
        self.adapter.delete_entry(key).await
    }

    fn attachments(&self) -> Vec<Attachment> {
        self.attachments.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{Mapping, Tuple, PROTOCOL_FLAG_TCP, PROTOCOL_TCP};
    #[cfg(target_os = "linux")]
    use std::env;

    #[tokio::test]
    async fn in_memory_attach_rolls_back() {
        let backend = InMemoryBackend::default();
        backend.set_attach_failure(Some("eth1:Egress".into()));
        let error = backend
            .attach(Path::new("placeholder.o"), &["eth0".into(), "eth1".into()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("rolled back"));
        assert!(backend.attachments().is_empty());
    }

    #[tokio::test]
    async fn stores_and_reads_mapping() {
        let backend = InMemoryBackend::default();
        let mapping = Mapping {
            synthetic: Tuple {
                source: "192.0.2.1".parse().unwrap(),
                destination: "198.51.100.1".parse().unwrap(),
                protocol: PROTOCOL_TCP,
                source_port: 1,
                destination_port: 2,
            },
            original: Tuple {
                source: "192.0.2.2".parse().unwrap(),
                destination: "198.51.100.2".parse().unwrap(),
                protocol: PROTOCOL_TCP,
                source_port: 3,
                destination_port: 4,
            },
            last_seen_ns: 1,
            protocol_flags: PROTOCOL_FLAG_TCP,
            tcp_state_flags: 0,
        };
        backend.insert_mapping(mapping);
        assert_eq!(backend.list_entries().await.unwrap().len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn aya_loader_contract_is_environment_gated() {
        let Some(path) = env::var_os("SSP_TEST_BPF_ELF") else {
            eprintln!("skipped Aya ELF contract test: SSP_TEST_BPF_ELF is not set");
            return;
        };
        let adapter = AyaLinuxTcAdapter::default();
        adapter
            .load_elf(Path::new(&path), ABI_VERSION)
            .await
            .expect("SSP_TEST_BPF_ELF must be a loadable ABI-v1 ELF");
        assert!(adapter.list_entries().await.is_ok());
    }
}
