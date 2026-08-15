// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Driver-owned `GetMapping` protobuf construction and validation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use prost::Message;

use crate::{
    error::KernelRelayError,
    proto,
    tuple::{FlowProtocol, SocketTuple, ValidatedMapping},
};

/// Maximum protobuf request or reply accepted by the kernel relay.
pub const MAX_PROTO_MESSAGE_LEN: usize = 4096;

/// Returns the authenticated gRPC method path used by the opaque tunnel.
pub const fn mapping_method_path() -> &'static str {
    "/shadow_socket_proxy.control.v1.Control/GetMapping"
}

/// Builds the complete `GetMapping` request payload for one synthetic tuple.
pub fn encode_get_mapping_request(tuple: &SocketTuple) -> Result<Vec<u8>, KernelRelayError> {
    tuple.validate()?;
    let payload = proto::GetMappingRequest {
        synthetic: Some(proto::Tuple {
            family: tuple.family(),
            source_address: ip_bytes(tuple.source.ip()),
            destination_address: ip_bytes(tuple.destination.ip()),
            protocol: tuple.protocol.wire_number() as u32,
            source_port: tuple.source.port() as u32,
            destination_port: tuple.destination.port() as u32,
        }),
    }
    .encode_to_vec();
    enforce_proto_bound(payload.len())?;
    Ok(payload)
}

/// Decodes and validates a `GetMapping` reply for the exact requesting tuple.
pub fn decode_get_mapping_response(
    requested: &SocketTuple,
    bytes: &[u8],
) -> Result<ValidatedMapping, KernelRelayError> {
    requested.validate()?;
    enforce_proto_bound(bytes.len())?;
    let mapping = proto::Mapping::decode(bytes)
        .map_err(|error| KernelRelayError::InvalidMapping(error.to_string()))?;
    let synthetic = tuple_from_proto(
        mapping
            .synthetic
            .ok_or_else(|| KernelRelayError::InvalidMapping("missing synthetic tuple".into()))?,
        Some(requested.protocol),
    )?;
    if synthetic != *requested {
        return Err(KernelRelayError::InvalidMapping(
            "synthetic tuple does not match the requesting flow".into(),
        ));
    }

    let original = tuple_from_proto(
        mapping
            .original
            .ok_or_else(|| KernelRelayError::InvalidMapping("missing original tuple".into()))?,
        Some(requested.protocol),
    )?;
    if original.destination.ip().is_unspecified() || original.destination.port() == 0 {
        return Err(KernelRelayError::InvalidMapping(
            "original destination is invalid".into(),
        ));
    }

    Ok(ValidatedMapping {
        synthetic,
        original,
        last_seen_ns: mapping.last_seen_ns,
        protocol_flags: mapping.protocol_flags,
        tcp_state_flags: mapping.tcp_state_flags,
    })
}

fn enforce_proto_bound(actual: usize) -> Result<(), KernelRelayError> {
    if actual > MAX_PROTO_MESSAGE_LEN {
        return Err(KernelRelayError::PayloadTooLarge {
            actual,
            max: MAX_PROTO_MESSAGE_LEN,
        });
    }
    Ok(())
}

fn tuple_from_proto(
    tuple: proto::Tuple,
    canonical_protocol: Option<FlowProtocol>,
) -> Result<SocketTuple, KernelRelayError> {
    let protocol = u8::try_from(tuple.protocol)
        .map_err(|_| KernelRelayError::InvalidMapping("protocol is out of range".into()))?;
    let protocol = match canonical_protocol {
        Some(expected) if expected.wire_number() == protocol => expected,
        Some(_) => {
            return Err(KernelRelayError::InvalidMapping(
                "protocol does not match the requesting flow".into(),
            ))
        }
        None => FlowProtocol::from_wire(protocol)?,
    };
    if tuple.source_port > u16::MAX as u32 || tuple.destination_port > u16::MAX as u32 {
        return Err(KernelRelayError::InvalidMapping(
            "port is out of range".into(),
        ));
    }
    let source = SocketAddr::new(
        ip_from_bytes(tuple.family, &tuple.source_address)?,
        tuple.source_port as u16,
    );
    let destination = SocketAddr::new(
        ip_from_bytes(tuple.family, &tuple.destination_address)?,
        tuple.destination_port as u16,
    );
    let tuple = SocketTuple {
        source,
        destination,
        protocol,
    };
    tuple.validate()?;
    Ok(tuple)
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn ip_from_bytes(family: u32, bytes: &[u8]) -> Result<IpAddr, KernelRelayError> {
    match family {
        4 if bytes.len() == 4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        6 if bytes.len() == 16 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).expect("validated IPv6 slice length"),
        ))),
        4 | 6 => Err(KernelRelayError::InvalidMapping(
            "address length does not match family".into(),
        )),
        other => Err(KernelRelayError::InvalidMapping(format!(
            "invalid address family {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use prost::Message;

    use super::*;

    fn tcp_tuple() -> SocketTuple {
        SocketTuple {
            source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40000)),
            destination: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 80), 443)),
            protocol: FlowProtocol::Tcp,
        }
    }

    #[test]
    fn encodes_complete_get_mapping_request() {
        let bytes = encode_get_mapping_request(&tcp_tuple()).expect("request should encode");
        let request =
            proto::GetMappingRequest::decode(bytes.as_slice()).expect("request should decode");
        let tuple = request
            .synthetic
            .expect("synthetic tuple should be present");
        assert_eq!(tuple.family, 4);
        assert_eq!(tuple.protocol, 6);
        assert_eq!(tuple.source_port, 40000);
        assert_eq!(tuple.destination_port, 443);
    }

    #[test]
    fn quic_uses_udp_wire_protocol() {
        let tuple = SocketTuple {
            protocol: FlowProtocol::QuicUdp,
            ..tcp_tuple()
        };
        let bytes = encode_get_mapping_request(&tuple).expect("request should encode");
        let request =
            proto::GetMappingRequest::decode(bytes.as_slice()).expect("request should decode");
        assert_eq!(request.synthetic.expect("synthetic").protocol, 17);
    }

    #[test]
    fn decodes_and_validates_mapping_reply() {
        let request = tcp_tuple();
        let reply = proto::Mapping {
            synthetic: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 2],
                destination_address: vec![192, 0, 2, 80],
                protocol: 6,
                source_port: 40000,
                destination_port: 443,
            }),
            original: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 2],
                destination_address: vec![203, 0, 113, 5],
                protocol: 6,
                source_port: 40000,
                destination_port: 8443,
            }),
            last_seen_ns: 42,
            protocol_flags: 7,
            tcp_state_flags: 9,
        }
        .encode_to_vec();

        let mapping =
            decode_get_mapping_response(&request, &reply).expect("mapping should validate");
        assert_eq!(mapping.original.destination.port(), 8443);
        assert_eq!(mapping.protocol_flags, 7);
        assert_eq!(mapping.tcp_state_flags, 9);
    }

    #[test]
    fn accepts_original_source_that_differs_from_the_synthetic_source() {
        let request = tcp_tuple();
        let reply = proto::Mapping {
            synthetic: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 2],
                destination_address: vec![192, 0, 2, 80],
                protocol: 6,
                source_port: 40000,
                destination_port: 443,
            }),
            original: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 9],
                destination_address: vec![203, 0, 113, 5],
                protocol: 6,
                source_port: 41000,
                destination_port: 8443,
            }),
            last_seen_ns: 1,
            protocol_flags: 0,
            tcp_state_flags: 0,
        }
        .encode_to_vec();

        let mapping =
            decode_get_mapping_response(&request, &reply).expect("mapping should validate");
        assert_eq!(mapping.original.source.port(), 41000);
        assert_eq!(mapping.original.destination.port(), 8443);
    }

    #[test]
    fn rejects_wrong_family_or_protocol() {
        let request = tcp_tuple();
        let reply = proto::Mapping {
            synthetic: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 2],
                destination_address: vec![192, 0, 2, 80],
                protocol: 17,
                source_port: 40000,
                destination_port: 443,
            }),
            original: Some(proto::Tuple {
                family: 4,
                source_address: vec![10, 0, 0, 2],
                destination_address: vec![203, 0, 113, 5],
                protocol: 17,
                source_port: 40000,
                destination_port: 8443,
            }),
            last_seen_ns: 0,
            protocol_flags: 0,
            tcp_state_flags: 0,
        }
        .encode_to_vec();

        let error = decode_get_mapping_response(&request, &reply).expect_err("reply should fail");
        assert!(matches!(error, KernelRelayError::InvalidMapping(_)));
    }
}
