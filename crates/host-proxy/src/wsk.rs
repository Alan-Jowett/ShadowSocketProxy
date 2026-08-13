// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Optional user-mode WSK broker/device client.
//!
//! This module adds the device contract without changing the default
//! user-mode TCP/UDP proxy. It is intentionally not selected automatically:
//! a WSK kernel device must be installed before a caller opens it.

pub use shadow_socket_proxy_wsk_driver::abi;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use tokio::runtime::Handle;

use crate::{MappingClient, ProxyError, Tuple};

pub use shadow_socket_proxy_wsk_driver::broker::{
    BrokerError, BrokerState, IoctlBroker, IoctlTransport, WindowsDevice,
};

/// Concrete host-side broker client for the installed WSK device.
pub struct WskDeviceClient {
    /// Authenticated broker session.
    broker: IoctlBroker<WindowsDevice>,
}

impl WskDeviceClient {
    /// Opens the default device and authenticates one broker session.
    pub fn connect(client_nonce: abi::SessionNonce) -> Result<Self, BrokerError> {
        let device = WindowsDevice::open(abi::DEVICE_PATH)?;
        let mut broker = IoctlBroker::new(device);
        broker.open_session(client_nonce)?;
        Ok(Self { broker })
    }

    /// Runs the blocking inverted-call broker while mapping lookups execute on
    /// the authenticated control-service client.
    pub fn run_mapping_broker<C>(
        mut device: WskDeviceClient,
        client: Arc<C>,
        stop: Arc<AtomicBool>,
        listen: SocketAddr,
    ) -> Result<(), BrokerError>
    where
        C: MappingClient + 'static,
    {
        let handle = Handle::current();
        while !stop.load(Ordering::Acquire) {
            let request = match device.wait_for_mapping() {
                Ok(request) => request,
                Err(BrokerError::DeviceStatus(abi::Status::Timeout)) => continue,
                Err(error) => return Err(error),
            };
            if stop.load(Ordering::Acquire) {
                break;
            }
            let tuple = tuple_from_abi(request.synthetic)
                .ok_or(BrokerError::DeviceStatus(abi::Status::InvalidAbi))?;
            let lookup_tuple = match normalize_wildcard_destination(tuple.clone(), listen) {
                Some(tuple) => tuple,
                None => {
                    tracing::warn!(
                        synthetic = ?tuple,
                        configured_listen = %listen,
                        "cannot normalize WSK wildcard destination across address families; leaving flow fail-closed"
                    );
                    continue;
                }
            };
            tracing::info!(synthetic = ?lookup_tuple, "wsk mapping lookup");
            let original = match handle.block_on(client.get_mapping(&lookup_tuple)) {
                Ok(mapping) => {
                    tracing::info!(
                        synthetic = ?lookup_tuple,
                        original = ?mapping,
                        "wsk mapping resolved"
                    );
                    mapping_to_abi(request.synthetic, mapping)
                        .ok_or(BrokerError::DeviceStatus(abi::Status::InvalidAbi))?
                }
                Err(ProxyError::MappingNotFound | ProxyError::InvalidMapping(_)) => {
                    tracing::warn!(
                        synthetic = ?lookup_tuple,
                        "no control-service mapping; leaving flow fail-closed"
                    );
                    continue;
                }
                Err(error) => {
                    tracing::warn!(
                        synthetic = ?lookup_tuple,
                        error = %error,
                        "control-service mapping lookup failed; leaving flow fail-closed"
                    );
                    continue;
                }
            };
            if let Err(error) = device.complete_mapping(&request, original) {
                match error {
                    BrokerError::DeviceStatus(
                        abi::Status::ResourceUnavailable
                        | abi::Status::InvalidMapping
                        | abi::Status::Cancelled,
                    ) => {
                        tracing::warn!(
                            synthetic = ?lookup_tuple,
                            error = %error,
                            "driver rejected mapping for this flow; continuing"
                        );
                        continue;
                    }
                    error => {
                        tracing::error!(
                            synthetic = ?lookup_tuple,
                            error = %error,
                            "driver rejected mapping completion"
                        );
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the broker lifecycle state.
    pub fn state(&self) -> BrokerState {
        self.broker.state()
    }

    /// Returns the device-generated session nonce.
    pub fn session_nonce(&self) -> Option<abi::SessionNonce> {
        self.broker.session_nonce()
    }

    /// Waits for one driver-originated synthetic mapping request.
    pub fn wait_for_mapping(&mut self) -> Result<abi::MappingRequest, BrokerError> {
        self.broker.wait_for_mapping()
    }

    /// Completes a driver mapping request with the validated original tuple.
    pub fn complete_mapping(
        &mut self,
        mapping: &abi::MappingRequest,
        original: abi::MappingTuple,
    ) -> Result<(), BrokerError> {
        self.broker.complete_mapping(mapping, original)
    }

    /// Closes the authenticated device session.
    pub fn close(mut self) -> Result<(), BrokerError> {
        self.broker.close_session()
    }
}

fn normalize_wildcard_destination(tuple: Tuple, listen: SocketAddr) -> Option<Tuple> {
    if !tuple.destination.ip().is_unspecified() {
        return Some(tuple);
    }
    if tuple.destination.is_ipv4() != listen.is_ipv4() {
        return None;
    }
    Some(Tuple {
        destination: SocketAddr::new(listen.ip(), tuple.destination.port()),
        ..tuple
    })
}

fn tuple_from_abi(tuple: abi::MappingTuple) -> Option<Tuple> {
    Some(Tuple {
        source: socket_addr(
            tuple.address_family,
            tuple.source_address,
            tuple.source_port,
        )?,
        destination: socket_addr(
            tuple.address_family,
            tuple.destination_address,
            tuple.destination_port,
        )?,
        protocol: tuple.protocol,
    })
}

fn mapping_to_abi(
    synthetic: abi::MappingTuple,
    mapping: crate::OriginalDestination,
) -> Option<abi::MappingTuple> {
    let (family, destination_address) = match mapping.address.ip() {
        IpAddr::V4(address) => {
            let octets = address.octets();
            (
                4,
                [
                    octets[0], octets[1], octets[2], octets[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            )
        }
        IpAddr::V6(address) => (6, address.octets()),
    };
    if synthetic.address_family != family || synthetic.protocol != mapping.protocol {
        return None;
    }
    Some(abi::MappingTuple {
        protocol: mapping.protocol,
        address_family: family,
        reserved: 0,
        source_port: synthetic.source_port,
        destination_port: mapping.address.port(),
        source_address: synthetic.source_address,
        destination_address,
    })
}

fn socket_addr(family: u8, address: [u8; 16], port: u16) -> Option<SocketAddr> {
    match family {
        4 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            port,
        )),
        6 => Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port)),
        _ => None,
    }
}

/// Opens the default WSK broker device.
pub fn open_default_device() -> Result<WindowsDevice, BrokerError> {
    WindowsDevice::open(abi::DEVICE_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OriginalDestination;

    #[test]
    fn abi_tuple_conversion_preserves_ipv4_and_ports() {
        let tuple = abi::MappingTuple {
            protocol: 6,
            address_family: 4,
            reserved: 0,
            source_port: 40_000,
            destination_port: 15_000,
            source_address: [192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination_address: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let converted = tuple_from_abi(tuple).unwrap();
        assert_eq!(converted.source, "192.0.2.10:40000".parse().unwrap());
        assert_eq!(converted.destination, "127.0.0.1:15000".parse().unwrap());
        assert_eq!(converted.protocol, 6);
    }

    #[test]
    fn abi_mapping_conversion_rejects_family_or_protocol_changes() {
        let synthetic = abi::MappingTuple {
            protocol: 17,
            address_family: 6,
            reserved: 0,
            source_port: 50_000,
            destination_port: 15_000,
            source_address: [0; 16],
            destination_address: [0; 16],
        };
        let mapping = OriginalDestination {
            address: "192.0.2.20:53".parse().unwrap(),
            protocol: 17,
        };
        assert!(mapping_to_abi(synthetic, mapping).is_none());
    }

    #[test]
    fn abi_mapping_conversion_keeps_ipv6_destination() {
        let synthetic = abi::MappingTuple {
            protocol: 6,
            address_family: 6,
            reserved: 0,
            source_port: 50_000,
            destination_port: 15_000,
            source_address: [0; 16],
            destination_address: [0; 16],
        };
        let mapping = OriginalDestination {
            address: "[2001:db8::20]:443".parse().unwrap(),
            protocol: 6,
        };
        let converted = mapping_to_abi(synthetic, mapping).unwrap();
        assert_eq!(converted.destination_address[0], 0x20);
        assert_eq!(converted.destination_port, 443);
    }

    #[test]
    fn wildcard_destination_uses_configured_listen_address() {
        let tuple = Tuple {
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "0.0.0.0:15000".parse().unwrap(),
            protocol: 17,
        };
        let normalized =
            normalize_wildcard_destination(tuple, "172.30.32.1:15000".parse().unwrap()).unwrap();
        assert_eq!(normalized.destination, "172.30.32.1:15000".parse().unwrap());
    }

    #[test]
    fn wildcard_destination_rejects_configured_family_mismatch() {
        let tuple = Tuple {
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: "0.0.0.0:15000".parse().unwrap(),
            protocol: 17,
        };
        assert!(
            normalize_wildcard_destination(tuple, "[2001:db8::1]:15000".parse().unwrap()).is_none()
        );
    }
}
