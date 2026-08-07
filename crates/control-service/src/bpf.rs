// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use thiserror::Error;

use crate::config::RuntimeConfig;
#[cfg(target_os = "linux")]
use crate::mapping::{
    decode_flow_state, encode_flow_state_key, FLOW_INDEX_VALUE_LEN, FLOW_STATE_KEY_LEN,
    FLOW_STATE_VALUE_LEN, RUNTIME_CONFIG_VALUE_LEN,
};
use crate::mapping::{
    encode_key, encode_value, FlowIndexValue, FlowState, MapMaxima, Mapping, ABI_VERSION,
};

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
    #[error("no ELF has been loaded")]
    NotAttached,
    #[error("ABI version {0} is not supported")]
    AbiMismatch(u16),
    #[error("active-flow capacity is exhausted")]
    FlowCapacity,
    #[error("partial flow cleanup: {0}")]
    PartialCleanup(String),
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
    pub created: Vec<Attachment>,
    pub maxima: MapMaxima,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowCleanupReport {
    pub state_deleted: bool,
    pub indexes_deleted: usize,
    pub partial: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BpfCounters {
    pub target_misses: u64,
    pub flow_insert_failures: u64,
    pub control_bypasses: u64,
}

#[async_trait]
pub trait BpfBackend: Send + Sync {
    async fn attach(&self, elf: &Path, interfaces: &[String])
        -> Result<AttachReport, BackendError>;
    async fn detach(&self, interfaces: Option<&[String]>) -> Result<(), BackendError>;
    async fn rollback_attach(&self, attachments: &[Attachment]) -> Result<(), BackendError> {
        let interfaces = attachments
            .iter()
            .map(|attachment| attachment.interface.clone())
            .collect::<Vec<_>>();
        self.detach(if interfaces.is_empty() {
            None
        } else {
            Some(&interfaces)
        })
        .await
    }
    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError>;
    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError>;
    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError>;
    async fn list_flow_states(&self) -> Result<Vec<FlowState>, BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn delete_flow(
        &self,
        _flow_id: u64,
        _generation: u32,
    ) -> Result<FlowCleanupReport, BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn set_runtime_config(&self, _config: &RuntimeConfig) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn read_counters(&self) -> Result<BpfCounters, BackendError> {
        Err(BackendError::Unsupported)
    }
    fn map_maxima(&self) -> MapMaxima {
        MapMaxima::default()
    }
    fn attachments(&self) -> Vec<Attachment>;
}

#[derive(Default)]
struct MemoryState {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
    flow_states: BTreeMap<(u64, u32), FlowState>,
    flow_indexes: BTreeMap<Vec<u8>, FlowIndexValue>,
    flow_mode: bool,
    maxima: MapMaxima,
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

    pub fn set_map_maxima(&self, maxima: MapMaxima) {
        self.state.lock().unwrap().maxima = maxima;
    }

    pub fn insert_flow_state(&self, state: FlowState) {
        let mut memory = self.state.lock().unwrap();
        memory.flow_mode = true;
        memory
            .flow_states
            .insert((state.flow_id, state.generation), state.clone());
        memory.flow_indexes.insert(
            encode_key(&state.original).to_vec(),
            FlowIndexValue {
                flow_id: state.flow_id,
                generation: state.generation,
            },
        );
        memory.flow_indexes.insert(
            encode_key(&state.target).to_vec(),
            FlowIndexValue {
                flow_id: state.flow_id,
                generation: state.generation,
            },
        );
        memory.flow_indexes.insert(
            encode_key(&state.reverse).to_vec(),
            FlowIndexValue {
                flow_id: state.flow_id,
                generation: state.generation,
            },
        );
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
        let created = required
            .iter()
            .filter(|attachment| !existing.contains(attachment))
            .cloned()
            .collect::<Vec<_>>();
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
            created,
            maxima: state.maxima,
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

    async fn rollback_attach(&self, attachments: &[Attachment]) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        for attachment in attachments {
            state.attachments.retain(|current| current != attachment);
        }
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
        let mut entries = state
            .entries
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        for flow in state.flow_states.values() {
            let mapping = flow.mapping();
            entries.push((
                encode_key(&mapping.synthetic).to_vec(),
                encode_value(&mapping).to_vec(),
            ));
        }
        Ok(entries)
    }

    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        let state = self.state.lock().unwrap();
        if let Some(value) = state.entries.get(key) {
            return Ok(Some(value.clone()));
        }
        let Some(index) = state.flow_indexes.get(key) else {
            return Ok(None);
        };
        Ok(state
            .flow_states
            .get(&(index.flow_id, index.generation))
            .map(|flow| encode_value(&flow.mapping()).to_vec()))
    }

    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError> {
        let mut state = self.state.lock().unwrap();
        if state.fail_delete.as_deref() == Some(key) {
            return Err(BackendError::Operation {
                location: "map:delete".into(),
                message: "in-memory injected delete failure".into(),
            });
        }
        if state.entries.remove(key).is_some() {
            return Ok(true);
        }
        let Some(index) = state.flow_indexes.get(key).cloned() else {
            return Ok(false);
        };
        let expected = index;
        state.flow_indexes.retain(|_, value| *value != expected);
        Ok(state
            .flow_states
            .remove(&(expected.flow_id, expected.generation))
            .is_some())
    }

    async fn list_flow_states(&self) -> Result<Vec<FlowState>, BackendError> {
        let state = self.state.lock().unwrap();
        if !state.flow_mode {
            return Err(BackendError::Unsupported);
        }
        Ok(state.flow_states.values().cloned().collect())
    }

    async fn delete_flow(
        &self,
        flow_id: u64,
        generation: u32,
    ) -> Result<FlowCleanupReport, BackendError> {
        let mut state = self.state.lock().unwrap();
        let Some(_) = state.flow_states.remove(&(flow_id, generation)) else {
            return Ok(FlowCleanupReport::default());
        };
        let expected = FlowIndexValue {
            flow_id,
            generation,
        };
        let before = state.flow_indexes.len();
        state.flow_indexes.retain(|_, value| *value != expected);
        Ok(FlowCleanupReport {
            state_deleted: true,
            indexes_deleted: before - state.flow_indexes.len(),
            partial: false,
        })
    }

    async fn set_runtime_config(&self, _config: &RuntimeConfig) -> Result<(), BackendError> {
        Ok(())
    }

    fn map_maxima(&self) -> MapMaxima {
        self.state.lock().unwrap().maxima
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
    async fn list_flow_states(&self) -> Result<Vec<FlowState>, BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn delete_flow(
        &self,
        _flow_id: u64,
        _generation: u32,
    ) -> Result<FlowCleanupReport, BackendError> {
        Err(BackendError::Unsupported)
    }
    async fn set_runtime_config(&self, _config: &RuntimeConfig) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
    fn map_maxima(&self) -> MapMaxima {
        MapMaxima::default()
    }
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

pub const FLOW_INDEX_MAP_NAME_V1: &str = "ssp_flow_index_v1";
pub const FLOW_STATE_MAP_NAME_V1: &str = "ssp_flow_state_v1";
pub const RUNTIME_CONFIG_MAP_NAME_V3: &str = "ssp_runtime_config_v3";
pub const COUNTERS_MAP_NAME_V1: &str = "ssp_tc_counters_v1";
pub const INGRESS_PROGRAM_NAME_V3: &str = "ssp_tc_ingress_v3";
pub const EGRESS_PROGRAM_NAME_V3: &str = "ssp_tc_egress_v3";
pub const MAP_NAME_V1: &str = FLOW_INDEX_MAP_NAME_V1;
pub const INGRESS_PROGRAM_NAME_V1: &str = INGRESS_PROGRAM_NAME_V3;
pub const EGRESS_PROGRAM_NAME_V1: &str = EGRESS_PROGRAM_NAME_V3;

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
    maxima: MapMaxima,
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

    fn map_max_entries(map: &mut aya::maps::Map) -> Result<usize, BackendError> {
        let info = match map {
            aya::maps::Map::HashMap(data)
            | aya::maps::Map::LruHashMap(data)
            | aya::maps::Map::Array(data)
            | aya::maps::Map::PerCpuArray(data) => data.info(),
            _ => {
                return Err(Self::operation(
                    "map",
                    "required map has an unsupported map type",
                ))
            }
        };
        info.map_err(Self::map_error)
            .map(|info| info.max_entries() as usize)
    }

    fn with_flow_index_map<T>(
        bpf: &mut aya::Ebpf,
        operation: impl FnOnce(
            &mut aya::maps::HashMap<
                &mut aya::maps::MapData,
                [u8; crate::mapping::KEY_LEN],
                [u8; FLOW_INDEX_VALUE_LEN],
            >,
        ) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let map = bpf
            .map_mut(FLOW_INDEX_MAP_NAME_V1)
            .ok_or_else(|| Self::operation("map", "versioned flow index map is missing"))?;
        let mut map = aya::maps::HashMap::try_from(map).map_err(Self::map_error)?;
        operation(&mut map)
    }

    fn with_state_map<T>(
        bpf: &mut aya::Ebpf,
        operation: impl FnOnce(
            &mut aya::maps::HashMap<
                &mut aya::maps::MapData,
                [u8; FLOW_STATE_KEY_LEN],
                [u8; FLOW_STATE_VALUE_LEN],
            >,
        ) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let map = bpf
            .map_mut(FLOW_STATE_MAP_NAME_V1)
            .ok_or_else(|| Self::operation("map", "versioned flow state map is missing"))?;
        let mut map = aya::maps::HashMap::try_from(map).map_err(Self::map_error)?;
        operation(&mut map)
    }

    fn with_runtime_map<T>(
        bpf: &mut aya::Ebpf,
        operation: impl FnOnce(
            &mut aya::maps::Array<&mut aya::maps::MapData, [u8; RUNTIME_CONFIG_VALUE_LEN]>,
        ) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let map = bpf
            .map_mut(RUNTIME_CONFIG_MAP_NAME_V3)
            .ok_or_else(|| Self::operation("map", "versioned runtime config map is missing"))?;
        let mut map = aya::maps::Array::try_from(map).map_err(Self::map_error)?;
        operation(&mut map)
    }

    fn with_counters_map<T>(
        bpf: &mut aya::Ebpf,
        operation: impl FnOnce(
            &mut aya::maps::Array<&mut aya::maps::MapData, [u8; 8]>,
        ) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let map = bpf
            .map_mut(COUNTERS_MAP_NAME_V1)
            .ok_or_else(|| Self::operation("map", "BPF counters map is missing"))?;
        let mut map = aya::maps::Array::try_from(map).map_err(Self::map_error)?;
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
        if bpf.program_mut("ssp_tc_ingress_v2").is_some()
            || bpf.program_mut("ssp_tc_egress_v2").is_some()
            || bpf.map_mut("ssp_destination_policy_map_v1").is_some()
            || bpf.map_mut("ssp_runtime_config_v1").is_some()
        {
            return Err(Self::operation(
                "load",
                "stale v2 or destination-policy ABI artifact is present",
            ));
        }
        let mut maxima = MapMaxima::default();
        for (name, slot) in [
            (FLOW_INDEX_MAP_NAME_V1, &mut maxima.flow_index),
            (FLOW_STATE_MAP_NAME_V1, &mut maxima.flow_state),
        ] {
            let map = bpf
                .map_mut(name)
                .ok_or_else(|| Self::operation("map", format!("required map {name} is missing")))?;
            *slot = Self::map_max_entries(map)?;
        }
        if bpf.map_mut(RUNTIME_CONFIG_MAP_NAME_V3).is_none() {
            return Err(Self::operation(
                "map",
                format!("required map {RUNTIME_CONFIG_MAP_NAME_V3} is missing"),
            ));
        }
        let counters = bpf
            .map_mut(COUNTERS_MAP_NAME_V1)
            .ok_or_else(|| Self::operation("map", "BPF counters map is missing"))?;
        if Self::map_max_entries(counters)? < 3 {
            return Err(Self::operation(
                "map",
                "BPF counters map does not expose all v3 counter slots",
            ));
        }
        Self::with_flow_index_map(&mut bpf, |_| Ok(()))?;
        Self::with_state_map(&mut bpf, |_| Ok(()))?;
        Self::with_runtime_map(&mut bpf, |_| Ok(()))?;
        Self::with_counters_map(&mut bpf, |_| Ok(()))?;

        for program_name in [INGRESS_PROGRAM_NAME_V3, EGRESS_PROGRAM_NAME_V3] {
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
            maxima,
        });
        Ok(())
    }

    async fn attach(&self, interface: &str, direction: Direction) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().ok_or(BackendError::NotAttached)?;
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
                INGRESS_PROGRAM_NAME_V3,
                aya::programs::TcAttachType::Ingress,
            ),
            Direction::Egress => (EGRESS_PROGRAM_NAME_V3, aya::programs::TcAttachType::Egress),
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
        let state = state.as_mut().ok_or(BackendError::NotAttached)?;
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
        let tracked = state.links.remove(index);
        let link_id = tracked.id;
        let attachment = tracked.attachment;
        let program_name = match direction {
            Direction::Ingress => INGRESS_PROGRAM_NAME_V3,
            Direction::Egress => EGRESS_PROGRAM_NAME_V3,
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
            let link = classifier
                .take_link(link_id)
                .map_err(|error| Self::operation(format!("{interface}:{direction:?}"), error))?;
            let restored_id = aya::programs::Link::id(&link);
            match aya::programs::Link::detach(link) {
                Ok(()) => Ok(()),
                Err(error) => {
                    state.links.insert(
                        index,
                        AyaLink {
                            attachment: attachment.clone(),
                            id: restored_id,
                        },
                    );
                    Err(Self::operation(format!("{interface}:{direction:?}"), error))
                }
            }
        };
        result
    }

    async fn list_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError> {
        Ok(self
            .list_flow_states()
            .await?
            .into_iter()
            .filter(|state| state.lifecycle == crate::mapping::FlowLifecycle::Active)
            .map(|state| {
                let mapping = state.mapping();
                (
                    encode_key(&mapping.synthetic).to_vec(),
                    encode_value(&mapping).to_vec(),
                )
            })
            .collect())
    }

    async fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        let key: [u8; crate::mapping::KEY_LEN] = key.try_into().map_err(|_| {
            Self::operation(
                "map:get",
                format!("invalid mapping key length: {}", key.len()),
            )
        })?;
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().ok_or(BackendError::NotAttached)?;
        let index = Self::with_flow_index_map(&mut state.bpf, |map| {
            map.get(&key, 0)
                .map(|value| Some(value))
                .or_else(|error| match error {
                    aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound => {
                        Ok(None)
                    }
                    error => Err(Self::map_error(error)),
                })
        })?;
        let Some(index) = index else {
            return Ok(None);
        };
        let index = crate::mapping::decode_flow_index(&index)
            .map_err(|error| Self::operation("flow-index:decode", error))?;
        let state_key = encode_flow_state_key(index.flow_id, index.generation);
        let flow = Self::with_state_map(&mut state.bpf, |map| {
            map.get(&state_key, 0)
                .map(|value| Some(value))
                .or_else(|error| match error {
                    aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound => {
                        Ok(None)
                    }
                    error => Err(Self::map_error(error)),
                })
        })?;
        let Some(flow) = flow else {
            return Ok(None);
        };
        let flow = decode_flow_state(&flow)
            .map_err(|error| Self::operation("flow-state:decode", error))?;
        if flow.lifecycle != crate::mapping::FlowLifecycle::Active {
            return Ok(None);
        }
        Ok(Some(encode_value(&flow.mapping()).to_vec()))
    }

    async fn delete_entry(&self, key: &[u8]) -> Result<bool, BackendError> {
        let key: [u8; crate::mapping::KEY_LEN] = key.try_into().map_err(|_| {
            Self::operation(
                "map:delete",
                format!("invalid mapping key length: {}", key.len()),
            )
        })?;
        let index = {
            let mut guard = self.state.lock().unwrap();
            let state = guard.as_mut().ok_or(BackendError::NotAttached)?;
            Self::with_flow_index_map(&mut state.bpf, |map| {
                map.get(&key, 0)
                    .map(|value| Some(value))
                    .or_else(|error| match error {
                        aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound => {
                            Ok(None)
                        }
                        error => Err(Self::map_error(error)),
                    })
            })?
        };
        let Some(index) = index else {
            return Ok(false);
        };
        let index = crate::mapping::decode_flow_index(&index)
            .map_err(|error| Self::operation("flow-index:decode", error))?;
        let report = self.delete_flow(index.flow_id, index.generation).await?;
        Ok(report.state_deleted || report.indexes_deleted != 0)
    }

    async fn list_flow_states(&self) -> Result<Vec<FlowState>, BackendError> {
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().ok_or(BackendError::NotAttached)?;
        Self::with_state_map(&mut state.bpf, |map| {
            map.iter()
                .map(|entry| {
                    let (_, value) = entry.map_err(Self::map_error)?;
                    decode_flow_state(&value)
                        .map_err(|error| Self::operation("flow-state:decode", error))
                })
                .collect()
        })
    }

    async fn delete_flow(
        &self,
        flow_id: u64,
        generation: u32,
    ) -> Result<FlowCleanupReport, BackendError> {
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().ok_or(BackendError::NotAttached)?;
        let expected = FlowIndexValue {
            flow_id,
            generation,
        };
        let state_key = encode_flow_state_key(flow_id, generation);
        let flow = Self::with_state_map(&mut state.bpf, |map| {
            map.get(&state_key, 0)
                .map(|value| Some(value))
                .or_else(|error| match error {
                    aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound => {
                        Ok(None)
                    }
                    error => Err(Self::map_error(error)),
                })
        })?;
        let mut index_keys = if let Some(flow) = flow {
            let flow = decode_flow_state(&flow)
                .map_err(|error| Self::operation("flow-state:decode", error))?;
            vec![
                encode_key(&flow.original),
                encode_key(&flow.target),
                encode_key(&flow.reverse),
            ]
        } else {
            Self::with_flow_index_map(&mut state.bpf, |map| {
                map.iter()
                    .map(|entry| {
                        let (key, value) = entry.map_err(Self::map_error)?;
                        let value = crate::mapping::decode_flow_index(&value)
                            .map_err(|error| Self::operation("flow-index:decode", error))?;
                        Ok((key, value))
                    })
                    .collect::<Result<Vec<_>, BackendError>>()
                    .map(|entries| {
                        entries
                            .into_iter()
                            .filter_map(|(key, value)| (value == expected).then_some(key))
                            .collect::<Vec<_>>()
                    })
            })?
        };
        index_keys.sort_unstable();
        index_keys.dedup();
        let mut indexes_deleted = 0;
        let mut partial = false;
        for key in index_keys {
            match Self::with_flow_index_map(&mut state.bpf, |map| {
                map.remove(&key).map_err(Self::map_error)
            }) {
                Ok(()) => indexes_deleted += 1,
                Err(_) => partial = true,
            }
        }
        let state_key = encode_flow_state_key(flow_id, generation);
        let state_deleted = match Self::with_state_map(&mut state.bpf, |map| {
            let existed = map
                .get(&state_key, 0)
                .map(|_| true)
                .or_else(|error| match error {
                    aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound => {
                        Ok(false)
                    }
                    error => Err(Self::map_error(error)),
                })?;
            if existed {
                map.remove(&state_key).map_err(Self::map_error)?;
            }
            Ok(existed)
        }) {
            Ok(value) => value,
            Err(_) => {
                partial = true;
                false
            }
        };
        Ok(FlowCleanupReport {
            state_deleted,
            indexes_deleted,
            partial,
        })
    }

    async fn set_runtime_config(&self, config: &RuntimeConfig) -> Result<(), BackendError> {
        let mut value = [0_u8; RUNTIME_CONFIG_VALUE_LEN];
        value[0..2].copy_from_slice(&config.schema_version.to_be_bytes());
        if let Some(target) = config.ipv4_target {
            if let std::net::IpAddr::V4(address) = target.ip() {
                value[2] = 1;
                value[4..8].copy_from_slice(&address.octets());
                value[8..10].copy_from_slice(&target.port().to_be_bytes());
            }
        }
        if let Some(target) = config.ipv6_target {
            if let std::net::IpAddr::V6(address) = target.ip() {
                value[3] = 1;
                value[10..26].copy_from_slice(&address.octets());
                value[26..28].copy_from_slice(&target.port().to_be_bytes());
            }
        }
        value[28] = if config.listener.address.is_ipv4() {
            4
        } else {
            6
        };
        value[29] =
            (config.listener.ipv4_wildcard as u8) | ((config.listener.ipv6_wildcard as u8) << 1);
        match config.listener.address {
            std::net::IpAddr::V4(address) => {
                value[42..46].copy_from_slice(&address.octets());
            }
            std::net::IpAddr::V6(address) => {
                value[30..46].copy_from_slice(&address.octets());
            }
        }
        value[46..48].copy_from_slice(&config.listener.port.to_be_bytes());
        value[48..56].copy_from_slice(
            &(config.idle_ttl.as_nanos().min(u64::MAX as u128) as u64).to_le_bytes(),
        );
        value[56..64].copy_from_slice(
            &(config.tcp_terminal_grace.as_nanos().min(u64::MAX as u128) as u64).to_le_bytes(),
        );
        value[64..68].copy_from_slice(&(config.active_flow_capacity as u32).to_le_bytes());
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().ok_or(BackendError::NotAttached)?;
        Self::with_runtime_map(&mut state.bpf, |map| {
            map.set(0, &value, 0).map_err(Self::map_error)
        })
    }

    async fn read_counters(&self) -> Result<BpfCounters, BackendError> {
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().ok_or(BackendError::NotAttached)?;
        Self::with_counters_map(&mut state.bpf, |map| {
            let target_misses = map.get(&0, 0).map_err(Self::map_error)?;
            let flow_insert_failures = map.get(&1, 0).map_err(Self::map_error)?;
            let control_bypasses = map.get(&2, 0).map_err(Self::map_error)?;
            Ok(BpfCounters {
                target_misses: u64::from_le_bytes(target_misses),
                flow_insert_failures: u64::from_le_bytes(flow_insert_failures),
                control_bypasses: u64::from_le_bytes(control_bypasses),
            })
        })
    }

    fn map_maxima(&self) -> MapMaxima {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|state| state.maxima)
            .unwrap_or_default()
    }
}

pub struct LinuxBpfBackend {
    adapter: Arc<dyn LinuxTcAdapter>,
    attachments: Arc<Mutex<Vec<Attachment>>>,
    operation_lock: Arc<tokio::sync::Mutex<()>>,
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
            operation_lock: Arc::new(tokio::sync::Mutex::new(())),
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
        let _operation_guard = self.operation_lock.lock().await;
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
            created: created.clone(),
            maxima: self.adapter.map_maxima(),
        })
    }

    async fn detach(&self, interfaces: Option<&[String]>) -> Result<(), BackendError> {
        let _operation_guard = self.operation_lock.lock().await;
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

    async fn rollback_attach(&self, attachments: &[Attachment]) -> Result<(), BackendError> {
        let _operation_guard = self.operation_lock.lock().await;
        let mut failures = Vec::new();
        let mut detached = Vec::new();
        for attachment in attachments {
            match self
                .adapter
                .detach(&attachment.interface, attachment.direction)
                .await
            {
                Ok(()) => detached.push(attachment.clone()),
                Err(error) => failures.push(format!(
                    "{}:{:?}: {error}",
                    attachment.interface, attachment.direction
                )),
            }
        }
        self.attachments
            .lock()
            .unwrap()
            .retain(|attachment| !detached.contains(attachment));
        if failures.is_empty() {
            Ok(())
        } else {
            Err(BackendError::Operation {
                location: "attach-rollback".into(),
                message: failures.join("; "),
            })
        }
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

    async fn list_flow_states(&self) -> Result<Vec<FlowState>, BackendError> {
        self.adapter.list_flow_states().await
    }

    async fn delete_flow(
        &self,
        flow_id: u64,
        generation: u32,
    ) -> Result<FlowCleanupReport, BackendError> {
        self.adapter.delete_flow(flow_id, generation).await
    }

    async fn set_runtime_config(&self, config: &RuntimeConfig) -> Result<(), BackendError> {
        let _operation_guard = self.operation_lock.lock().await;
        self.adapter.set_runtime_config(config).await
    }

    fn map_maxima(&self) -> MapMaxima {
        self.adapter.map_maxima()
    }

    fn attachments(&self) -> Vec<Attachment> {
        self.attachments.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{
        FlowLifecycle, FlowState, Mapping, Tuple, PROTOCOL_FLAG_TCP, PROTOCOL_FLAG_UDP,
        PROTOCOL_TCP, PROTOCOL_UDP,
    };
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

    #[tokio::test]
    async fn flow_cleanup_removes_all_indexes() {
        let backend = InMemoryBackend::default();
        let original = Tuple {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.10".parse().unwrap(),
            protocol: PROTOCOL_UDP,
            source_port: 40000,
            destination_port: 443,
        };
        let target = Tuple {
            source: original.source,
            destination: "192.0.2.10".parse().unwrap(),
            protocol: PROTOCOL_UDP,
            source_port: 40000,
            destination_port: 8443,
        };
        let reverse = Tuple {
            source: target.destination,
            destination: original.source,
            protocol: PROTOCOL_UDP,
            source_port: 8443,
            destination_port: 40000,
        };
        backend.insert_flow_state(FlowState {
            flow_id: 9,
            generation: 1,
            original,
            target: target.clone(),
            reverse,
            last_used_ns: 1,
            protocol_flags: PROTOCOL_FLAG_UDP,
            tcp_state_flags: 0,
            fin_seen_mask: 0,
            fin_ack_seen_mask: 0,
            lifecycle: FlowLifecycle::Active,
            terminal_deadline_ns: 0,
        });
        assert!(backend
            .get_entry(&encode_key(&target))
            .await
            .unwrap()
            .is_some());
        let report = backend.delete_flow(9, 1).await.unwrap();
        assert_eq!(report.indexes_deleted, 3);
        assert!(backend.list_flow_states().await.unwrap().is_empty());
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
            .expect("SSP_TEST_BPF_ELF must be a loadable ABI-v3 ELF");
        assert!(adapter.list_entries().await.is_ok());
    }
}
