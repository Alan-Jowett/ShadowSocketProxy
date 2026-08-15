// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Opaque user-mode tunnel over authenticated gRPC.

use async_trait::async_trait;
use http::uri::PathAndQuery;
use prost::bytes::{Buf, BufMut};
use tonic::{
    client::Grpc,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    transport::Channel,
    Status,
};

use crate::{
    codec::mapping_method_path,
    device::{TunnelRequest, TunnelResponse, TunnelResponseStatus},
    error::KernelRelayError,
};

/// Opaque transport used by the first user-mode tunnel implementation.
#[async_trait]
pub trait OpaqueRpcTransport: Send + Sync {
    /// Sends a raw unary gRPC request and returns raw response bytes.
    async fn unary(
        &self,
        path: &'static str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, KernelRelayError>;
}

#[derive(Clone, Debug)]
/// Host agent that forwards driver-produced protobuf bytes without decoding
/// their semantic contents.
pub struct HostTunnelAgent<T> {
    transport: T,
}

impl<T> HostTunnelAgent<T> {
    /// Creates an agent over a caller-supplied authenticated transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: OpaqueRpcTransport> HostTunnelAgent<T> {
    /// Forwards a versioned tunnel request and preserves its correlation tuple.
    pub async fn forward_request(&self, request: TunnelRequest) -> TunnelResponse {
        let status_and_payload = match request.kind {
            crate::device::TunnelRequestKind::GetMapping => self
                .transport
                .unary(mapping_method_path(), request.payload.clone())
                .await
                .map(|payload| (TunnelResponseStatus::Ok, payload)),
        };

        match status_and_payload {
            Ok((status, payload)) => TunnelResponse {
                request_id: request.request_id,
                generation: request.generation,
                epoch: request.epoch,
                status,
                payload,
            },
            Err(KernelRelayError::MappingNotFound) => TunnelResponse {
                request_id: request.request_id,
                generation: request.generation,
                epoch: request.epoch,
                status: TunnelResponseStatus::MappingNotFound,
                payload: Vec::new(),
            },
            Err(KernelRelayError::Cancelled(_)) => TunnelResponse {
                request_id: request.request_id,
                generation: request.generation,
                epoch: request.epoch,
                status: TunnelResponseStatus::Cancelled,
                payload: Vec::new(),
            },
            Err(KernelRelayError::PayloadTooLarge { .. }) => TunnelResponse {
                request_id: request.request_id,
                generation: request.generation,
                epoch: request.epoch,
                status: TunnelResponseStatus::Oversized,
                payload: Vec::new(),
            },
            Err(_) => TunnelResponse {
                request_id: request.request_id,
                generation: request.generation,
                epoch: request.epoch,
                status: TunnelResponseStatus::TransportError,
                payload: Vec::new(),
            },
        }
    }

    /// Decodes, forwards, and re-encodes a raw tunnel frame.
    pub async fn forward_frame(&self, frame: &[u8]) -> Result<Vec<u8>, KernelRelayError> {
        let request = TunnelRequest::decode(frame)?;
        self.forward_request(request).await.encode()
    }
}

#[derive(Clone, Debug)]
/// Authenticated gRPC transport that treats `GetMapping` bytes opaquely.
pub struct GrpcOpaqueTransport {
    channel: Channel,
}

impl GrpcOpaqueTransport {
    /// Wraps an already authenticated tonic channel.
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl OpaqueRpcTransport for GrpcOpaqueTransport {
    async fn unary(
        &self,
        path: &'static str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, KernelRelayError> {
        let mut grpc = Grpc::new(self.channel.clone());
        let response = grpc
            .unary(
                tonic::Request::new(payload),
                PathAndQuery::from_static(path),
                RawBytesCodec,
            )
            .await
            .map_err(map_grpc_error)?;
        Ok(response.into_inner())
    }
}

#[derive(Clone, Copy, Debug)]
struct RawBytesCodec;

#[derive(Clone, Copy, Debug)]
struct RawBytesEncoder;

#[derive(Clone, Copy, Debug)]
struct RawBytesDecoder;

impl Codec for RawBytesCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = RawBytesEncoder;
    type Decoder = RawBytesDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        RawBytesEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        RawBytesDecoder
    }
}

impl Encoder for RawBytesEncoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for RawBytesDecoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        let bytes = src.copy_to_bytes(src.remaining());
        Ok(Some(bytes.to_vec()))
    }
}

fn map_grpc_error(status: Status) -> KernelRelayError {
    if status.code() == tonic::Code::NotFound {
        KernelRelayError::MappingNotFound
    } else {
        KernelRelayError::Transport(status.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::time::sleep;

    use super::*;
    use crate::device::{TunnelRequestKind, TunnelResponseStatus};

    #[derive(Clone, Default)]
    struct MockTransport {
        responses: Arc<Mutex<HashMap<Vec<u8>, Result<Vec<u8>, KernelRelayError>>>>,
        delay: Duration,
    }

    impl MockTransport {
        fn with_response(
            self,
            request: &[u8],
            response: Result<Vec<u8>, KernelRelayError>,
        ) -> Self {
            self.responses
                .lock()
                .expect("mock transport mutex")
                .insert(request.to_vec(), response);
            self
        }
    }

    #[async_trait]
    impl OpaqueRpcTransport for MockTransport {
        async fn unary(
            &self,
            _path: &'static str,
            payload: Vec<u8>,
        ) -> Result<Vec<u8>, KernelRelayError> {
            sleep(self.delay).await;
            self.responses
                .lock()
                .expect("mock transport mutex")
                .remove(&payload)
                .expect("mock response should exist")
        }
    }

    #[tokio::test]
    async fn preserves_correlation_across_concurrent_requests() {
        let transport = MockTransport::default()
            .with_response(b"one", Ok(b"reply-one".to_vec()))
            .with_response(b"two", Ok(b"reply-two".to_vec()));
        let agent = HostTunnelAgent::new(transport);

        let first = agent.forward_request(TunnelRequest {
            request_id: 10,
            generation: 1,
            epoch: 3,
            kind: TunnelRequestKind::GetMapping,
            payload: b"one".to_vec(),
        });
        let second = agent.forward_request(TunnelRequest {
            request_id: 11,
            generation: 2,
            epoch: 3,
            kind: TunnelRequestKind::GetMapping,
            payload: b"two".to_vec(),
        });

        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.request_id, 10);
        assert_eq!(first.generation, 1);
        assert_eq!(first.epoch, 3);
        assert_eq!(first.status, TunnelResponseStatus::Ok);
        assert_eq!(first.payload, b"reply-one");
        assert_eq!(second.request_id, 11);
        assert_eq!(second.generation, 2);
        assert_eq!(second.status, TunnelResponseStatus::Ok);
        assert_eq!(second.payload, b"reply-two");
    }

    #[tokio::test]
    async fn isolates_transport_failures_per_request() {
        let transport = MockTransport::default()
            .with_response(b"good", Ok(b"ok".to_vec()))
            .with_response(
                b"bad",
                Err(KernelRelayError::Transport("channel reset".into())),
            );
        let agent = HostTunnelAgent::new(transport);

        let good = agent.forward_request(TunnelRequest {
            request_id: 20,
            generation: 1,
            epoch: 4,
            kind: TunnelRequestKind::GetMapping,
            payload: b"good".to_vec(),
        });
        let bad = agent.forward_request(TunnelRequest {
            request_id: 21,
            generation: 1,
            epoch: 4,
            kind: TunnelRequestKind::GetMapping,
            payload: b"bad".to_vec(),
        });

        let (good, bad) = tokio::join!(good, bad);
        assert_eq!(good.status, TunnelResponseStatus::Ok);
        assert_eq!(good.payload, b"ok");
        assert_eq!(bad.status, TunnelResponseStatus::TransportError);
        assert!(bad.payload.is_empty());
    }

    #[tokio::test]
    async fn forward_frame_round_trips_request_and_response_framing() {
        let transport = MockTransport::default().with_response(b"wire", Ok(b"reply".to_vec()));
        let agent = HostTunnelAgent::new(transport);
        let request = TunnelRequest {
            request_id: 30,
            generation: 7,
            epoch: 9,
            kind: TunnelRequestKind::GetMapping,
            payload: b"wire".to_vec(),
        };

        let encoded = agent
            .forward_frame(&request.encode().expect("request should encode"))
            .await
            .expect("frame forwarding should succeed");
        let decoded = TunnelResponse::decode(&encoded).expect("response should decode");
        assert_eq!(decoded.request_id, 30);
        assert_eq!(decoded.generation, 7);
        assert_eq!(decoded.epoch, 9);
        assert_eq!(decoded.status, TunnelResponseStatus::Ok);
        assert_eq!(decoded.payload, b"reply");
    }
}
