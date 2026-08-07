// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

pub const MAP_ABI_VERSION: u16 = 1;
pub const PROGRAM_ABI_VERSION: u16 = 3;
pub const ABI_VERSION: u16 = PROGRAM_ABI_VERSION;
pub const RUNTIME_CONFIG_ABI_VERSION: u16 = 3;

pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
pub const PROTOCOL_FLAG_TCP: u32 = 1 << 0;
pub const PROTOCOL_FLAG_UDP: u32 = 1 << 1;
pub const PROTOCOL_FLAG_QUIC: u32 = 1 << 2;

pub const TCP_SYN: u32 = 1 << 0;
pub const TCP_SYN_ACK: u32 = 1 << 1;
pub const TCP_ACK: u32 = 1 << 2;
pub const TCP_FIN: u32 = 1 << 3;
pub const TCP_RST: u32 = 1 << 4;

pub const KEY_LEN: usize = 40;
pub const VALUE_LEN: usize = KEY_LEN + 16;
pub const FLOW_INDEX_VALUE_LEN: usize = 16;
pub const FLOW_STATE_KEY_LEN: usize = 16;
pub const FLOW_STATE_VALUE_LEN: usize = 256;
pub const RUNTIME_CONFIG_VALUE_LEN: usize = 80;

pub const ELF_FLOW_INDEX_MAX_ENTRIES: usize = 16384;
pub const ELF_FLOW_STATE_MAX_ENTRIES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapMaxima {
    pub flow_index: usize,
    pub flow_state: usize,
}

impl Default for MapMaxima {
    fn default() -> Self {
        Self {
            flow_index: ELF_FLOW_INDEX_MAX_ENTRIES,
            flow_state: ELF_FLOW_STATE_MAX_ENTRIES,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AbiError {
    #[error("unsupported ABI version {0}")]
    UnsupportedVersion(u16),
    #[error("malformed ABI length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid address family {0}")]
    InvalidFamily(u8),
    #[error("unsupported protocol {0}")]
    UnsupportedProtocol(u8),
    #[error("address families do not match")]
    FamilyMismatch,
    #[error("port must be non-zero")]
    ZeroPort,
    #[error("unspecified address is not supported")]
    UnspecifiedAddress,
    #[error("invalid lifecycle value {0}")]
    InvalidLifecycle(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tuple {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
}

impl Tuple {
    pub fn family(&self) -> u8 {
        match self.source {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }
    }

    pub fn validate(&self) -> Result<(), AbiError> {
        if self.source.is_ipv4() != self.destination.is_ipv4() {
            return Err(AbiError::FamilyMismatch);
        }
        validate_protocol(self.protocol)?;
        if self.source_port == 0 || self.destination_port == 0 {
            return Err(AbiError::ZeroPort);
        }
        if self.source.is_unspecified() || self.destination.is_unspecified() {
            return Err(AbiError::UnspecifiedAddress);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub synthetic: Tuple,
    pub original: Tuple,
    pub last_seen_ns: u64,
    pub protocol_flags: u32,
    pub tcp_state_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowLifecycle {
    Creating = 1,
    Active = 2,
}

impl TryFrom<u8> for FlowLifecycle {
    type Error = AbiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Creating),
            2 => Ok(Self::Active),
            other => Err(AbiError::InvalidLifecycle(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowIndexValue {
    pub flow_id: u64,
    pub generation: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowState {
    pub flow_id: u64,
    pub generation: u32,
    pub original: Tuple,
    pub target: Tuple,
    pub reverse: Tuple,
    pub last_used_ns: u64,
    pub protocol_flags: u32,
    pub tcp_state_flags: u32,
    pub fin_seen_mask: u8,
    pub fin_ack_seen_mask: u8,
    pub lifecycle: FlowLifecycle,
    pub terminal_deadline_ns: u64,
}

impl FlowState {
    pub fn validate(&self) -> Result<(), AbiError> {
        self.original.validate()?;
        self.target.validate()?;
        self.reverse.validate()?;
        if self.original.protocol != self.target.protocol
            || self.target.protocol != self.reverse.protocol
        {
            return Err(AbiError::UnsupportedProtocol(self.original.protocol));
        }
        if self.original.destination.is_ipv4() != self.target.destination.is_ipv4()
            || self.target.destination.is_ipv4() != self.reverse.destination.is_ipv4()
        {
            return Err(AbiError::FamilyMismatch);
        }
        if self.lifecycle == FlowLifecycle::Creating && self.terminal_deadline_ns != 0 {
            return Err(AbiError::InvalidLifecycle(self.lifecycle as u8));
        }
        Ok(())
    }

    pub fn mapping(&self) -> Mapping {
        Mapping {
            synthetic: self.target.clone(),
            original: self.original.clone(),
            last_seen_ns: self.last_used_ns,
            protocol_flags: self.protocol_flags,
            tcp_state_flags: self.tcp_state_flags,
        }
    }

    pub fn observe_tcp(&mut self, direction: u8, flags: u32, now_ns: u64, grace_ns: u64) {
        if self.original.protocol != PROTOCOL_TCP || direction > 1 {
            return;
        }
        self.last_used_ns = now_ns;
        if flags & TCP_SYN != 0 {
            self.tcp_state_flags |= if direction == 0 { TCP_SYN } else { TCP_SYN_ACK };
        }
        if flags & TCP_ACK != 0 && self.fin_seen_mask & (1 << (direction ^ 1)) != 0 {
            self.tcp_state_flags |= TCP_ACK;
            self.fin_ack_seen_mask |= 1 << direction;
        }
        if flags & TCP_FIN != 0 {
            self.tcp_state_flags |= TCP_FIN;
            self.fin_seen_mask |= 1 << direction;
        }
        if flags & TCP_RST != 0 {
            self.tcp_state_flags |= TCP_RST;
        }
        if self.fin_seen_mask == 0b11
            && self.fin_ack_seen_mask == 0b11
            && self.terminal_deadline_ns == 0
        {
            self.terminal_deadline_ns = now_ns.saturating_add(grace_ns);
        }
    }

    pub fn should_delete(&self, now_ns: u64, idle_ttl_ns: u64) -> bool {
        if self.lifecycle == FlowLifecycle::Creating {
            return true;
        }
        if self.tcp_state_flags & TCP_RST != 0 {
            return true;
        }
        if self.original.protocol == PROTOCOL_TCP {
            if self.terminal_deadline_ns != 0 {
                now_ns >= self.terminal_deadline_ns
            } else {
                now_ns.saturating_sub(self.last_used_ns) >= idle_ttl_ns
            }
        } else {
            now_ns.saturating_sub(self.last_used_ns) >= idle_ttl_ns
        }
    }
}

fn validate_protocol(protocol: u8) -> Result<(), AbiError> {
    match protocol {
        PROTOCOL_TCP | PROTOCOL_UDP => Ok(()),
        other => Err(AbiError::UnsupportedProtocol(other)),
    }
}

fn address_bytes(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(address) => {
            let mut bytes = [0; 16];
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..].copy_from_slice(&address.octets());
            bytes
        }
        IpAddr::V6(address) => address.octets(),
    }
}

fn parse_address(family: u8, bytes: &[u8]) -> Result<IpAddr, AbiError> {
    let value: [u8; 16] = bytes.try_into().map_err(|_| AbiError::InvalidLength {
        expected: 16,
        actual: bytes.len(),
    })?;
    match family {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            value[12], value[13], value[14], value[15],
        ))),
        6 => Ok(IpAddr::V6(Ipv6Addr::from(value))),
        other => Err(AbiError::InvalidFamily(other)),
    }
}

pub fn encode_key(tuple: &Tuple) -> [u8; KEY_LEN] {
    let mut output = [0; KEY_LEN];
    output[0..2].copy_from_slice(&MAP_ABI_VERSION.to_be_bytes());
    output[2] = tuple.family();
    output[3] = tuple.protocol;
    output[4..20].copy_from_slice(&address_bytes(tuple.source));
    output[20..36].copy_from_slice(&address_bytes(tuple.destination));
    output[36..38].copy_from_slice(&tuple.source_port.to_be_bytes());
    output[38..40].copy_from_slice(&tuple.destination_port.to_be_bytes());
    output
}

pub fn decode_key(bytes: &[u8]) -> Result<Tuple, AbiError> {
    if bytes.len() != KEY_LEN {
        return Err(AbiError::InvalidLength {
            expected: KEY_LEN,
            actual: bytes.len(),
        });
    }
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version != MAP_ABI_VERSION {
        return Err(AbiError::UnsupportedVersion(version));
    }
    let tuple = Tuple {
        source: parse_address(bytes[2], &bytes[4..20])?,
        destination: parse_address(bytes[2], &bytes[20..36])?,
        protocol: bytes[3],
        source_port: u16::from_be_bytes([bytes[36], bytes[37]]),
        destination_port: u16::from_be_bytes([bytes[38], bytes[39]]),
    };
    if tuple.source.is_ipv4() != tuple.destination.is_ipv4() {
        return Err(AbiError::FamilyMismatch);
    }
    Ok(tuple)
}

pub fn encode_value(mapping: &Mapping) -> [u8; VALUE_LEN] {
    let mut output = [0; VALUE_LEN];
    output[..KEY_LEN].copy_from_slice(&encode_key(&mapping.original));
    output[KEY_LEN..KEY_LEN + 8].copy_from_slice(&mapping.last_seen_ns.to_be_bytes());
    output[KEY_LEN + 8..KEY_LEN + 12].copy_from_slice(&mapping.protocol_flags.to_be_bytes());
    output[KEY_LEN + 12..KEY_LEN + 16].copy_from_slice(&mapping.tcp_state_flags.to_be_bytes());
    output
}

pub fn decode_value(key: &[u8], value: &[u8]) -> Result<Mapping, AbiError> {
    if value.len() != VALUE_LEN {
        return Err(AbiError::InvalidLength {
            expected: VALUE_LEN,
            actual: value.len(),
        });
    }
    Ok(Mapping {
        synthetic: decode_key(key)?,
        original: decode_key(&value[..KEY_LEN])?,
        last_seen_ns: u64::from_be_bytes(value[KEY_LEN..KEY_LEN + 8].try_into().unwrap()),
        protocol_flags: u32::from_be_bytes(value[KEY_LEN + 8..KEY_LEN + 12].try_into().unwrap()),
        tcp_state_flags: u32::from_be_bytes(value[KEY_LEN + 12..KEY_LEN + 16].try_into().unwrap()),
    })
}

pub fn encode_flow_index(value: &FlowIndexValue) -> [u8; FLOW_INDEX_VALUE_LEN] {
    let mut output = [0; FLOW_INDEX_VALUE_LEN];
    output[0..2].copy_from_slice(&MAP_ABI_VERSION.to_be_bytes());
    output[4..12].copy_from_slice(&value.flow_id.to_be_bytes());
    output[12..16].copy_from_slice(&value.generation.to_be_bytes());
    output
}

pub fn decode_flow_index(bytes: &[u8]) -> Result<FlowIndexValue, AbiError> {
    if bytes.len() != FLOW_INDEX_VALUE_LEN {
        return Err(AbiError::InvalidLength {
            expected: FLOW_INDEX_VALUE_LEN,
            actual: bytes.len(),
        });
    }
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version != MAP_ABI_VERSION {
        return Err(AbiError::UnsupportedVersion(version));
    }
    Ok(FlowIndexValue {
        flow_id: u64::from_be_bytes(bytes[4..12].try_into().unwrap()),
        generation: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
    })
}

pub fn encode_flow_state_key(flow_id: u64, generation: u32) -> [u8; FLOW_STATE_KEY_LEN] {
    let mut output = [0; FLOW_STATE_KEY_LEN];
    output[0..2].copy_from_slice(&MAP_ABI_VERSION.to_be_bytes());
    output[4..12].copy_from_slice(&flow_id.to_be_bytes());
    output[12..16].copy_from_slice(&generation.to_be_bytes());
    output
}

pub fn decode_flow_state_key(bytes: &[u8]) -> Result<FlowIndexValue, AbiError> {
    let value = decode_flow_index(bytes)?;
    Ok(value)
}

pub fn encode_flow_state(state: &FlowState) -> [u8; FLOW_STATE_VALUE_LEN] {
    let mut output = [0; FLOW_STATE_VALUE_LEN];
    output[..KEY_LEN].copy_from_slice(&encode_key(&state.original));
    output[KEY_LEN..KEY_LEN * 2].copy_from_slice(&encode_key(&state.target));
    output[KEY_LEN * 2..KEY_LEN * 3].copy_from_slice(&encode_key(&state.reverse));
    output[120..128].copy_from_slice(&state.last_used_ns.to_be_bytes());
    output[128..132].copy_from_slice(&state.protocol_flags.to_be_bytes());
    output[132..136].copy_from_slice(&state.tcp_state_flags.to_be_bytes());
    output[136] = state.fin_seen_mask;
    output[137] = state.fin_ack_seen_mask;
    output[138] = state.lifecycle as u8;
    output[140..148].copy_from_slice(&state.terminal_deadline_ns.to_be_bytes());
    output[148..156].copy_from_slice(&state.flow_id.to_be_bytes());
    output[156..160].copy_from_slice(&state.generation.to_be_bytes());
    output
}

pub fn decode_flow_state(bytes: &[u8]) -> Result<FlowState, AbiError> {
    if bytes.len() != FLOW_STATE_VALUE_LEN {
        return Err(AbiError::InvalidLength {
            expected: FLOW_STATE_VALUE_LEN,
            actual: bytes.len(),
        });
    }
    let state = FlowState {
        original: decode_key(&bytes[..KEY_LEN])?,
        target: decode_key(&bytes[KEY_LEN..KEY_LEN * 2])?,
        reverse: decode_key(&bytes[KEY_LEN * 2..KEY_LEN * 3])?,
        last_used_ns: u64::from_be_bytes(bytes[120..128].try_into().unwrap()),
        protocol_flags: u32::from_be_bytes(bytes[128..132].try_into().unwrap()),
        tcp_state_flags: u32::from_be_bytes(bytes[132..136].try_into().unwrap()),
        fin_seen_mask: bytes[136],
        fin_ack_seen_mask: bytes[137],
        lifecycle: FlowLifecycle::try_from(bytes[138])?,
        terminal_deadline_ns: u64::from_be_bytes(bytes[140..148].try_into().unwrap()),
        flow_id: u64::from_be_bytes(bytes[148..156].try_into().unwrap()),
        generation: u32::from_be_bytes(bytes[156..160].try_into().unwrap()),
    };
    state.validate()?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> FlowState {
        let original = Tuple {
            source: "192.0.2.10".parse().unwrap(),
            destination: "198.51.100.20".parse().unwrap(),
            protocol: PROTOCOL_TCP,
            source_port: 40000,
            destination_port: 443,
        };
        let target = Tuple {
            source: original.source,
            destination: "192.0.2.20".parse().unwrap(),
            protocol: PROTOCOL_TCP,
            source_port: 40000,
            destination_port: 8443,
        };
        let reverse = Tuple {
            source: target.destination,
            destination: original.source,
            protocol: PROTOCOL_TCP,
            source_port: target.destination_port,
            destination_port: original.source_port,
        };
        FlowState {
            flow_id: 42,
            generation: 7,
            original,
            target,
            reverse,
            last_used_ns: 123,
            protocol_flags: PROTOCOL_FLAG_TCP,
            tcp_state_flags: 0,
            fin_seen_mask: 0,
            fin_ack_seen_mask: 0,
            lifecycle: FlowLifecycle::Active,
            terminal_deadline_ns: 0,
        }
    }

    #[test]
    fn round_trips_ipv4_and_ipv6_mapping_abi() {
        let mapping = Mapping {
            synthetic: Tuple {
                source: "192.0.2.10".parse().unwrap(),
                destination: "198.51.100.20".parse().unwrap(),
                protocol: PROTOCOL_TCP,
                source_port: 40000,
                destination_port: 443,
            },
            original: Tuple {
                source: "2001:db8::10".parse().unwrap(),
                destination: "2001:db8::20".parse().unwrap(),
                protocol: PROTOCOL_TCP,
                source_port: 40000,
                destination_port: 443,
            },
            last_seen_ns: 123,
            protocol_flags: PROTOCOL_FLAG_TCP,
            tcp_state_flags: TCP_SYN | TCP_SYN_ACK | TCP_ACK | TCP_FIN | TCP_RST,
        };
        let decoded =
            decode_value(&encode_key(&mapping.synthetic), &encode_value(&mapping)).unwrap();
        assert_eq!(decoded, mapping);
    }

    #[test]
    fn flow_abi_round_trips() {
        let state = flow();
        let key = encode_flow_state_key(state.flow_id, state.generation);
        assert_eq!(decode_flow_state_key(&key).unwrap().flow_id, state.flow_id);
        assert_eq!(
            decode_flow_state(&encode_flow_state(&state)).unwrap(),
            state
        );
    }

    #[test]
    fn tcp_terminal_deadline_beats_idle_ttl() {
        let mut state = flow();
        state.observe_tcp(0, TCP_FIN, 100, 50);
        state.observe_tcp(1, TCP_FIN | TCP_ACK, 110, 50);
        state.observe_tcp(0, TCP_ACK, 120, 50);
        assert!(!state.should_delete(120, 1));
        assert!(state.should_delete(180, 1));
    }

    #[test]
    fn incomplete_tcp_flow_expires_by_idle_ttl() {
        let mut state = flow();
        state.observe_tcp(0, TCP_SYN, 100, 50);
        assert!(!state.should_delete(150, 60));
        assert!(state.should_delete(161, 60));
    }

    #[test]
    fn rejects_unknown_version_and_length() {
        let mut key = encode_key(&Tuple {
            source: "127.0.0.1".parse().unwrap(),
            destination: "127.0.0.2".parse().unwrap(),
            protocol: PROTOCOL_UDP,
            source_port: 1,
            destination_port: 2,
        });
        key[0] = 0;
        key[1] = 2;
        assert!(matches!(
            decode_key(&key),
            Err(AbiError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            decode_key(&key[..3]),
            Err(AbiError::InvalidLength { .. })
        ));
    }
}
