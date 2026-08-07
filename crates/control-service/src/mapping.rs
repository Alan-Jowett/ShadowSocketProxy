// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

pub const ABI_VERSION: u16 = 1;
pub const KEY_LEN: usize = 40;
pub const VALUE_LEN: usize = KEY_LEN + 16;

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

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AbiError {
    #[error("unsupported ABI version {0}")]
    UnsupportedVersion(u16),
    #[error("malformed ABI length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid address family {0}")]
    InvalidFamily(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub synthetic: Tuple,
    pub original: Tuple,
    pub last_seen_ns: u64,
    pub protocol_flags: u32,
    pub tcp_state_flags: u32,
}

fn address_bytes(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(address) => {
            let mut bytes = [0; 16];
            bytes[..10].fill(0);
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
    output[0..2].copy_from_slice(&ABI_VERSION.to_be_bytes());
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
    if version != ABI_VERSION {
        return Err(AbiError::UnsupportedVersion(version));
    }
    Ok(Tuple {
        source: parse_address(bytes[2], &bytes[4..20])?,
        destination: parse_address(bytes[2], &bytes[20..36])?,
        protocol: bytes[3],
        source_port: u16::from_be_bytes([bytes[36], bytes[37]]),
        destination_port: u16::from_be_bytes([bytes[38], bytes[39]]),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_ipv4_and_ipv6() {
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
