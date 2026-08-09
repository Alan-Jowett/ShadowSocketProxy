// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Runs the TCP/UDP host-side forwarder and its platform-specific control
//! service client.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use thiserror::Error;
use tokio::{
    io,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{watch, Mutex},
    task::JoinSet,
    time,
};

/// Generated tonic messages and client/server bindings for the control RPC.
pub mod proto {
    tonic::include_proto!("shadow_socket_proxy.control.v1");
}

/// IP protocol number used in TCP mapping lookups.
const TCP_PROTOCOL: u8 = 6;
/// IP protocol number used in UDP mapping lookups.
const UDP_PROTOCOL: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Socket tuple sent to the control service for mapping lookup.
pub struct Tuple {
    /// Originating client address.
    pub source: SocketAddr,
    /// Local proxy address accepted by the client.
    pub destination: SocketAddr,
    /// TCP or UDP protocol number.
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Control-service result identifying where proxy traffic must be forwarded.
pub struct OriginalDestination {
    /// Original destination socket address.
    pub address: SocketAddr,
    /// Protocol associated with the returned mapping.
    pub protocol: u8,
}

#[derive(Debug, Error)]
/// Configuration, mapping, control, and I/O failures surfaced by the proxy.
pub enum ProxyError {
    #[error("invalid configuration: {0}")]
    /// Required endpoint, credential, address, or timeout validation failed.
    InvalidConfiguration(String),
    #[error("mapping not found")]
    /// The control service has no mapping for the accepted tuple.
    MappingNotFound,
    #[error("mapping response is invalid: {0}")]
    /// The response is malformed or uses the wrong transport protocol.
    InvalidMapping(String),
    #[error("control service error: {0}")]
    /// The control RPC or TLS client failed.
    Control(String),
    #[error("I/O error: {0}")]
    /// A socket or stream operation failed.
    Io(#[from] io::Error),
    #[error("proxy is unsupported on this platform")]
    /// The selected build does not provide the TLS-PSK mapping client.
    UnsupportedPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// BPF-agnostic flow record returned by host maintenance enumeration.
pub struct FlowRecord {
    /// Opaque flow identity.
    pub flow_id: u64,
    /// Generation paired with the identity.
    pub generation: u32,
    /// Synthetic tuple used by the proxy.
    pub synthetic: Tuple,
    /// Original tuple restored by the proxy.
    pub original: Tuple,
    /// Last dataplane activity timestamp.
    pub last_used_ns: u64,
    /// Protocol flags observed by the dataplane.
    pub protocol_flags: u32,
    /// TCP lifecycle flags observed by the dataplane.
    pub tcp_state_flags: u32,
    /// Control-service monotonic timestamp corresponding to `last_used_ns`.
    pub observed_now_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Result category for a generation-checked flow deletion.
pub enum FlowDeleteOutcome {
    /// State and indexes were removed.
    Complete,
    /// No matching state or indexes remained.
    AlreadyAbsent,
    /// A newer generation exists and was protected.
    StaleGeneration,
    /// Some state or indexes remain and the operation may be retried.
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// BPF-agnostic result returned by flow deletion.
pub struct FlowDeleteReport {
    /// Requested flow identity.
    pub flow_id: u64,
    /// Requested flow generation.
    pub generation: u32,
    /// Deletion outcome.
    pub outcome: FlowDeleteOutcome,
    /// Number of tuple indexes removed.
    pub indexes_deleted: u32,
    /// Whether canonical state was removed.
    pub state_deleted: bool,
    /// Whether the caller should retry.
    pub retryable: bool,
}

#[async_trait]
/// Lookup interface used by both TCP and UDP forwarding paths.
pub trait MappingClient: Send + Sync {
    /// Resolves a proxy tuple to its original destination or returns a typed
    /// lookup/control error.
    async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError>;
}

#[async_trait]
/// Typed flow lifecycle operations used by host-owned maintenance.
pub trait FlowClient: Send + Sync {
    /// Enumerates one bounded page of active flows.
    async fn enumerate_flows(
        &self,
        page_token: Vec<u8>,
        limit: u32,
    ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError>;
    /// Deletes one flow only when its identity and generation still match.
    async fn delete_flow(
        &self,
        flow_id: u64,
        generation: u32,
    ) -> Result<FlowDeleteReport, ProxyError>;
}

#[derive(Clone)]
/// Listener, control-service, credential, and UDP lifecycle settings.
pub struct ProxyConfig {
    /// Specific local address shared by the TCP and UDP listeners.
    pub listen: SocketAddr,
    /// URI of the TLS-PSK control service.
    pub control_endpoint: String,
    /// Client identity presented during the TLS-PSK handshake.
    pub psk_identity: String,
    /// Secret bytes used by the TLS-PSK handshake.
    pub psk_secret: Vec<u8>,
    /// Inactivity duration after which a UDP association is reaped.
    pub udp_idle_timeout: Duration,
    /// Interval between host-owned flow maintenance passes.
    pub cleanup_interval: Duration,
    /// Idle age used for incomplete TCP and UDP flows.
    pub idle_ttl: Duration,
    /// Grace age for TCP flows after both FIN acknowledgements.
    pub tcp_terminal_grace: Duration,
    /// Maximum flow records requested per enumeration page.
    pub flow_scan_batch: u32,
}

impl ProxyConfig {
    /// Rejects wildcard listeners, missing credentials/endpoints, and zero UDP
    /// idle time before any sockets are opened.
    pub fn validate(&self) -> Result<(), ProxyError> {
        if self.listen.ip().is_unspecified() {
            return Err(ProxyError::InvalidConfiguration(
                "listen address must be specific so UDP tuples identify the local destination"
                    .into(),
            ));
        }
        if self.control_endpoint.is_empty() {
            return Err(ProxyError::InvalidConfiguration(
                "control endpoint is required".into(),
            ));
        }
        if self.psk_identity.is_empty() || self.psk_secret.is_empty() {
            return Err(ProxyError::InvalidConfiguration(
                "PSK identity and secret are required".into(),
            ));
        }
        if self.udp_idle_timeout.is_zero() {
            return Err(ProxyError::InvalidConfiguration(
                "UDP idle timeout must be nonzero".into(),
            ));
        }
        if self.cleanup_interval.is_zero()
            || self.idle_ttl.is_zero()
            || self.tcp_terminal_grace.is_zero()
            || self.flow_scan_batch == 0
        {
            return Err(ProxyError::InvalidConfiguration(
                "maintenance settings must be nonzero".into(),
            ));
        }
        Ok(())
    }
}

/// Runs serialized host-owned flow maintenance until shutdown.
async fn run_maintenance<C: MappingClient + FlowClient + 'static>(
    client: Arc<C>,
    associations: Arc<UdpAssociations<C>>,
    cleanup_interval: Duration,
    idle_ttl: Duration,
    tcp_terminal_grace: Duration,
    flow_scan_batch: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = time::interval(cleanup_interval);
    let mut retry_delay = cleanup_interval.min(Duration::from_millis(100));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                let mut token = Vec::new();
                let mut scan_failed = false;
                loop {
                    let page = client.enumerate_flows(token, flow_scan_batch).await;
                    let (flows, next) = match page {
                        Ok(page) => page,
                        Err(error) => {
                            tracing::warn!(%error, "host maintenance flow enumeration failed");
                            scan_failed = true;
                            break;
                        }
                    };
                    for flow in flows {
                        let age = flow.observed_now_ns.saturating_sub(flow.last_used_ns);
                        let tcp = flow.original.protocol == TCP_PROTOCOL;
                        let terminal = tcp && (flow.tcp_state_flags & (1 << 2)) != 0
                            && (flow.tcp_state_flags & (1 << 3)) != 0;
                        let expired = flow.tcp_state_flags & (1 << 4) != 0
                            || (!terminal && age >= idle_ttl.as_nanos() as u64)
                            || (terminal && age >= tcp_terminal_grace.as_nanos() as u64);
                        if expired {
                            match client.delete_flow(flow.flow_id, flow.generation).await {
                                Ok(report) => {
                                    if matches!(
                                        report.outcome,
                                        FlowDeleteOutcome::Complete
                                            | FlowDeleteOutcome::AlreadyAbsent
                                    ) && flow.original.protocol == UDP_PROTOCOL
                                    {
                                        associations.invalidate(&flow.synthetic).await;
                                    }
                                    tracing::info!(
                                    flow_id = flow.flow_id,
                                    generation = flow.generation,
                                    outcome = ?report.outcome,
                                    "host maintenance flow deletion"
                                    );
                                }
                                Err(error) => tracing::warn!(
                                    flow_id = flow.flow_id,
                                    generation = flow.generation,
                                    %error,
                                    "host maintenance flow deletion failed"
                                ),
                            }
                        }
                    }
                    if next.is_empty() {
                        break;
                    }
                    token = next;
                }
                if scan_failed {
                    let delay = retry_delay;
                    retry_delay = retry_delay
                        .saturating_mul(2)
                        .min(cleanup_interval);
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        _ = time::sleep(delay) => {}
                    }
                } else {
                    retry_delay = cleanup_interval;
                }
            }
        }
    }
}

/// Owns the TCP and UDP forwarding tasks for one validated configuration.
pub struct Proxy<C> {
    /// Immutable listener and forwarding settings.
    config: ProxyConfig,
    /// Shared mapping client used by accepted TCP and UDP traffic.
    client: Arc<C>,
}

impl<C: MappingClient + FlowClient + 'static> Proxy<C> {
    /// Validates configuration and creates a proxy that has not opened sockets.
    pub fn new(config: ProxyConfig, client: Arc<C>) -> Result<Self, ProxyError> {
        config.validate()?;
        Ok(Self { config, client })
    }

    /// Binds TCP and UDP listeners at the configured specific address.
    pub async fn bind(&self) -> Result<(TcpListener, Arc<UdpSocket>), ProxyError> {
        let tcp_listener = TcpListener::bind(self.config.listen).await?;
        let actual_listen = tcp_listener.local_addr()?;
        let udp_socket = Arc::new(UdpSocket::bind(actual_listen).await?);
        Ok((tcp_listener, udp_socket))
    }

    /// Binds both transports, runs them until shutdown or task failure, then
    /// aborts the sibling task and clears UDP associations.
    pub async fn run(self, shutdown: watch::Receiver<bool>) -> Result<(), ProxyError> {
        let (tcp_listener, udp_socket) = self.bind().await?;
        self.run_bound(tcp_listener, udp_socket, shutdown).await
    }

    /// Runs with pre-bound listeners so control-plane activation can safely
    /// target a listening proxy before any redirected traffic is enabled.
    pub async fn run_bound(
        self,
        tcp_listener: TcpListener,
        udp_socket: Arc<UdpSocket>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ProxyError> {
        let udp = Arc::new(UdpAssociations::new(
            udp_socket,
            self.client.clone(),
            self.config.udp_idle_timeout,
            shutdown.clone(),
        ));
        let maintenance = tokio::spawn(run_maintenance(
            self.client.clone(),
            udp.clone(),
            self.config.cleanup_interval,
            self.config.idle_ttl,
            self.config.tcp_terminal_grace,
            self.config.flow_scan_batch,
            shutdown.clone(),
        ));
        let mut tcp_task =
            tokio::spawn(run_tcp(tcp_listener, self.client.clone(), shutdown.clone()));
        let mut udp_task = tokio::spawn(run_udp(udp.clone(), shutdown.clone()));
        let result = tokio::select! {
            _ = shutdown.changed() => {
                let _ = tcp_task.await;
                let _ = udp_task.await;
                let _ = maintenance.await;
                Ok(())
            },
            result = &mut tcp_task => {
                udp_task.abort();
                maintenance.abort();
                let _ = udp_task.await;
                result.map_err(|error| ProxyError::Control(error.to_string()))
            },
            result = &mut udp_task => {
                tcp_task.abort();
                maintenance.abort();
                let _ = tcp_task.await;
                result.map_err(|error| ProxyError::Control(error.to_string()))
            },
        };
        udp.shutdown().await;
        tracing::info!(
            protocol = "proxy",
            reason = "forwarding_stopped",
            "host proxy shutdown"
        );
        result
    }
}

/// Accepts TCP sessions until shutdown and joins or aborts all bridges.
async fn run_tcp<C: MappingClient + 'static>(
    listener: TcpListener,
    client: Arc<C>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(%error, "TCP accept failed");
                        continue;
                    }
                };
                let client = client.clone();
                sessions.spawn(async move {
                    if let Err(error) = bridge_tcp(stream, client).await {
                        tracing::warn!(%error, "TCP forwarding session failed");
                    }
                });
            }
        }
    }
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
}

/// Emits a termination event if a running TCP bridge is cancelled.
struct TcpForwardingGuard {
    /// Synthetic tuple associated with the bridge.
    tuple: Tuple,
    /// Original destination used by the bridge.
    original_destination: SocketAddr,
    /// Indicates that the bridge emitted its normal termination event.
    completed: bool,
}

impl Drop for TcpForwardingGuard {
    /// Reports cancellation when the bridge future is dropped before completion.
    fn drop(&mut self) {
        if !self.completed {
            tracing::info!(
                protocol = "tcp",
                synthetic_source = %self.tuple.source,
                synthetic_destination = %self.tuple.destination,
                original_destination = %self.original_destination,
                reason = "cancelled",
                "TCP forwarding terminated"
            );
        }
    }
}

/// Looks up the accepted tuple, connects to the original destination, and
/// copies bytes bidirectionally until either stream closes.
async fn bridge_tcp<C: MappingClient + 'static>(
    mut accepted: TcpStream,
    client: Arc<C>,
) -> Result<(), ProxyError> {
    let tuple = Tuple {
        source: accepted.peer_addr()?,
        destination: accepted.local_addr()?,
        protocol: TCP_PROTOCOL,
    };
    let original = match client.get_mapping(&tuple).await {
        Ok(original) => original,
        Err(error) => {
            tracing::warn!(
                protocol = "tcp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                error = %error,
                "TCP mapping lookup failed"
            );
            return Err(error);
        }
    };
    if original.protocol != TCP_PROTOCOL {
        tracing::warn!(
            protocol = "tcp",
            synthetic_source = %tuple.source,
            synthetic_destination = %tuple.destination,
            original_destination = %original.address,
            reason = "protocol_mismatch",
            "TCP mapping validation failed"
        );
        return Err(ProxyError::InvalidMapping(
            "TCP lookup returned a non-TCP mapping".into(),
        ));
    }
    let mut outbound = match TcpStream::connect(original.address).await {
        Ok(outbound) => outbound,
        Err(error) => {
            tracing::warn!(
                protocol = "tcp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                original_destination = %original.address,
                error = %error,
                "TCP outbound connection failed"
            );
            return Err(error.into());
        }
    };
    let mut termination = TcpForwardingGuard {
        tuple: tuple.clone(),
        original_destination: original.address,
        completed: false,
    };
    tracing::info!(
        protocol = "tcp",
        synthetic_source = %tuple.source,
        synthetic_destination = %tuple.destination,
        original_destination = %original.address,
        reason = "forwarding_started",
        "TCP forwarding started"
    );
    match io::copy_bidirectional(&mut accepted, &mut outbound).await {
        Ok((client_to_destination, destination_to_client)) => {
            tracing::info!(
                protocol = "tcp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                original_destination = %original.address,
                client_to_destination,
                destination_to_client,
                reason = "stream_closed",
                "TCP forwarding terminated"
            );
            termination.completed = true;
        }
        Err(error) => {
            tracing::warn!(
                protocol = "tcp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                original_destination = %original.address,
                error = %error,
                reason = "stream_error",
                "TCP forwarding terminated with error"
            );
            termination.completed = true;
            return Err(error.into());
        }
    }
    Ok(())
}

/// Receives datagrams, resolves/creates associations, relays replies, and
/// periodically removes idle associations.
async fn run_udp<C: MappingClient + 'static>(
    associations: Arc<UdpAssociations<C>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buffer = vec![0_u8; 65_535];
    let mut reap = time::interval(associations.idle_timeout);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = reap.tick() => {
                associations.reap().await;
            }
            received = associations.socket.recv_from(&mut buffer) => {
                let (length, client_address) = match received {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(%error, "UDP receive failed");
                        continue;
                    }
                };
                if let Err(error) = associations.forward(client_address, &buffer[..length]).await {
                    associations.report_failure(&error).await;
                }
            }
        }
    }
}

/// Shared UDP association table and lifecycle coordination state.
struct UdpAssociations<C> {
    /// Client-facing UDP socket bound to the proxy listener.
    socket: Arc<UdpSocket>,
    /// Mapping service used to resolve each client tuple.
    client: Arc<C>,
    /// Associations keyed by client tuple.
    entries: Mutex<HashMap<Tuple, Arc<UdpAssociation>>>,
    /// Lifetime used by relay timeouts and periodic reaping.
    idle_timeout: Duration,
    /// Watch receiver used to stop relay tasks.
    shutdown: watch::Receiver<bool>,
    /// Timestamp used to rate-limit repeated forwarding warnings.
    last_failure_log: Mutex<Option<std::time::Instant>>,
}

/// One connected outbound UDP socket paired with its originating client.
struct UdpAssociation {
    /// Client endpoint receiving relayed responses.
    client_address: SocketAddr,
    /// Synthetic client tuple used for the control-service mapping.
    synthetic_source: SocketAddr,
    /// Synthetic proxy tuple used for the control-service mapping.
    synthetic_destination: SocketAddr,
    /// Current mapped destination; changes cause association replacement.
    destination: SocketAddr,
    /// Monotonic creation time used to report association lifetime.
    created_at: std::time::Instant,
    /// Connected UDP socket used for outbound datagrams and replies.
    outbound: Arc<UdpSocket>,
    /// Last successful send or receive time for idle reaping.
    last_seen: Mutex<std::time::Instant>,
}

impl<C: MappingClient + 'static> UdpAssociations<C> {
    /// Creates an empty association table around the proxy UDP socket.
    fn new(
        socket: Arc<UdpSocket>,
        client: Arc<C>,
        idle_timeout: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            socket,
            client,
            entries: Mutex::new(HashMap::new()),
            idle_timeout,
            shutdown,
            last_failure_log: Mutex::new(None),
        }
    }

    /// Reuses an active association, resolving only when it is absent or a
    /// destination-specific send failure requires one retry.
    async fn forward(&self, client_address: SocketAddr, payload: &[u8]) -> Result<(), ProxyError> {
        let tuple = Tuple {
            source: client_address,
            destination: self.socket.local_addr()?,
            protocol: UDP_PROTOCOL,
        };
        let association = self.entries.lock().await.get(&tuple).cloned();
        let association = match association {
            Some(association) => association,
            None => self.resolve_association(&tuple, client_address).await?,
        };
        if let Err(error) = association.outbound.send(payload).await {
            tracing::warn!(
                protocol = "udp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                original_destination = %association.destination,
                error = %error,
                "UDP datagram send failed"
            );
            if !matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
            ) {
                return Err(error.into());
            }
            self.entries.lock().await.remove(&tuple);
            let replacement = self.resolve_association(&tuple, client_address).await?;
            replacement.outbound.send(payload).await?;
            *replacement.last_seen.lock().await = std::time::Instant::now();
            return Ok(());
        }
        *association.last_seen.lock().await = std::time::Instant::now();
        Ok(())
    }

    /// Performs the one mapping lookup needed to create an association.
    async fn resolve_association(
        &self,
        tuple: &Tuple,
        client_address: SocketAddr,
    ) -> Result<Arc<UdpAssociation>, ProxyError> {
        let mapping = self.client.get_mapping(tuple).await.map_err(|error| {
            tracing::warn!(
                protocol = "udp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                error = %error,
                "UDP mapping lookup failed"
            );
            error
        })?;
        if mapping.protocol != UDP_PROTOCOL {
            tracing::warn!(
                protocol = "udp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                original_destination = %mapping.address,
                reason = "protocol_mismatch",
                "UDP mapping validation failed"
            );
            return Err(ProxyError::InvalidMapping(
                "UDP lookup returned a non-UDP mapping".into(),
            ));
        }
        self.insert_association(tuple.clone(), client_address, mapping, None)
            .await
    }

    /// Binds and connects a new outbound UDP socket, publishing it atomically
    /// if another task has not already installed the same destination.
    async fn insert_association(
        &self,
        tuple: Tuple,
        client_address: SocketAddr,
        mapping: OriginalDestination,
        previous_destination: Option<SocketAddr>,
    ) -> Result<Arc<UdpAssociation>, ProxyError> {
        let destination = mapping.address;
        let outbound = Arc::new(match UdpSocket::bind(unspecified_for(destination)).await {
            Ok(outbound) => outbound,
            Err(error) => {
                tracing::warn!(
                    protocol = "udp",
                    synthetic_source = %tuple.source,
                    synthetic_destination = %tuple.destination,
                    original_destination = %destination,
                    error = %error,
                    "UDP outbound socket bind failed"
                );
                return Err(error.into());
            }
        });
        if let Err(error) = outbound.connect(destination).await {
            tracing::warn!(
                protocol = "udp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                original_destination = %destination,
                error = %error,
                "UDP outbound connection failed"
            );
            return Err(error.into());
        }
        let candidate = Arc::new(UdpAssociation {
            client_address,
            synthetic_source: tuple.source,
            synthetic_destination: tuple.destination,
            destination,
            created_at: std::time::Instant::now(),
            outbound,
            last_seen: Mutex::new(std::time::Instant::now()),
        });
        let mut entries = self.entries.lock().await;
        if let Some(existing) = entries.get(&tuple) {
            if existing.destination == destination {
                return Ok(existing.clone());
            }
        }
        let source = tuple.source;
        let proxy = tuple.destination;
        entries.insert(tuple, candidate.clone());
        drop(entries);
        match previous_destination {
            Some(previous_destination) => tracing::info!(
                protocol = "udp",
                synthetic_source = %source,
                synthetic_destination = %proxy,
                previous_destination = %previous_destination,
                original_destination = %destination,
                association_age_ms = 0_u64,
                reason = "association_replaced",
                "UDP association replaced"
            ),
            None => tracing::info!(
                protocol = "udp",
                synthetic_source = %source,
                synthetic_destination = %proxy,
                original_destination = %destination,
                association_age_ms = 0_u64,
                reason = "association_created",
                "UDP association created"
            ),
        }
        spawn_udp_relay(
            candidate.clone(),
            self.socket.clone(),
            self.idle_timeout,
            self.shutdown.clone(),
        );
        Ok(candidate)
    }

    /// Logs forwarding failures at most once per second.
    async fn report_failure(&self, error: &ProxyError) {
        let now = std::time::Instant::now();
        let mut last_failure_log = self.last_failure_log.lock().await;
        if last_failure_log
            .map(|last| now.duration_since(last) >= Duration::from_secs(1))
            .unwrap_or(true)
        {
            *last_failure_log = Some(now);
            tracing::warn!(%error, "UDP forwarding failed");
        }
    }

    /// Drops all association entries; relay tasks exit via their watch signal.
    async fn shutdown(&self) {
        let count = {
            let mut entries = self.entries.lock().await;
            let count = entries.len();
            entries.clear();
            count
        };
        tracing::info!(
            protocol = "udp",
            association_count = count,
            reason = "proxy_shutdown",
            "UDP associations cleared"
        );
    }

    /// Removes a locally cached association after confirmed host deletion.
    async fn invalidate(&self, tuple: &Tuple) {
        let removed = self.entries.lock().await.remove(tuple).is_some();
        if removed {
            tracing::info!(
                protocol = "udp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                reason = "flow_deleted",
                "UDP association invalidated"
            );
        }
    }

    /// Removes associations idle longer than the configured timeout.
    async fn reap(&self) {
        let candidates = {
            let entries = self.entries.lock().await;
            entries
                .iter()
                .map(|(tuple, association)| (tuple.clone(), association.clone()))
                .collect::<Vec<_>>()
        };
        let mut expired = Vec::new();
        for (tuple, association) in candidates {
            let age = association.last_seen.lock().await.elapsed();
            if age >= self.idle_timeout {
                expired.push((tuple, association, age));
            }
        }
        if expired.is_empty() {
            return;
        }
        let mut entries = self.entries.lock().await;
        for (tuple, association, _) in expired {
            let Some(current) = entries.get(&tuple).cloned() else {
                continue;
            };
            if !Arc::ptr_eq(&current, &association) {
                continue;
            }
            let idle_age = current.last_seen.lock().await.elapsed();
            if idle_age >= self.idle_timeout {
                let association_age = current.created_at.elapsed();
                entries.remove(&tuple);
                tracing::info!(
                    protocol = "udp",
                    synthetic_source = %tuple.source,
                    synthetic_destination = %tuple.destination,
                    original_destination = %current.destination,
                    association_age_ms = association_age.as_millis() as u64,
                    idle_age_ms = idle_age.as_millis() as u64,
                    idle_timeout_ms = self.idle_timeout.as_millis() as u64,
                    reason = "idle_timeout",
                    "UDP association expired"
                );
            }
        }
    }
}

/// Spawns the reply loop for one outbound association until timeout, I/O error,
/// or shutdown.
fn spawn_udp_relay(
    association: Arc<UdpAssociation>,
    client_socket: Arc<UdpSocket>,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let result = {
                let receive = time::timeout(idle_timeout, association.outbound.recv(&mut buffer));
                tokio::pin!(receive);
                tokio::select! {
                    _ = shutdown.changed() => {
                        tracing::info!(
                            protocol = "udp",
                            synthetic_source = %association.synthetic_source,
                            synthetic_destination = %association.synthetic_destination,
                            client_address = %association.client_address,
                            original_destination = %association.destination,
                            association_age_ms = association.created_at.elapsed().as_millis() as u64,
                            reason = "proxy_shutdown",
                            "UDP relay stopped"
                        );
                        return;
                    },
                    result = &mut receive => result,
                }
            };
            match result {
                Ok(Ok(length)) => {
                    if let Err(error) = client_socket
                        .send_to(&buffer[..length], association.client_address)
                        .await
                    {
                        tracing::warn!(
                            protocol = "udp",
                            synthetic_source = %association.synthetic_source,
                            synthetic_destination = %association.synthetic_destination,
                            client_address = %association.client_address,
                            original_destination = %association.destination,
                            error = %error,
                            association_age_ms = association.created_at.elapsed().as_millis() as u64,
                            reason = "relay_delivery",
                            "UDP relay delivery failed"
                        );
                        tracing::info!(
                            protocol = "udp",
                            synthetic_source = %association.synthetic_source,
                            synthetic_destination = %association.synthetic_destination,
                            client_address = %association.client_address,
                            original_destination = %association.destination,
                            association_age_ms = association.created_at.elapsed().as_millis() as u64,
                            reason = "delivery_error",
                            "UDP relay stopped"
                        );
                        break;
                    }
                    *association.last_seen.lock().await = std::time::Instant::now();
                }
                Ok(Err(error)) => {
                    tracing::warn!(
                        protocol = "udp",
                        synthetic_source = %association.synthetic_source,
                        synthetic_destination = %association.synthetic_destination,
                        client_address = %association.client_address,
                        original_destination = %association.destination,
                        error = %error,
                        association_age_ms = association.created_at.elapsed().as_millis() as u64,
                        reason = "receive_error",
                        "UDP relay receive failed"
                    );
                    tracing::info!(
                        protocol = "udp",
                        synthetic_source = %association.synthetic_source,
                        synthetic_destination = %association.synthetic_destination,
                        client_address = %association.client_address,
                        original_destination = %association.destination,
                        association_age_ms = association.created_at.elapsed().as_millis() as u64,
                        reason = "receive_error",
                        "UDP relay stopped"
                    );
                    break;
                }
                Err(_) => {
                    tracing::info!(
                        protocol = "udp",
                        synthetic_source = %association.synthetic_source,
                        synthetic_destination = %association.synthetic_destination,
                        client_address = %association.client_address,
                        original_destination = %association.destination,
                        idle_timeout_ms = idle_timeout.as_millis() as u64,
                        association_age_ms = association.created_at.elapsed().as_millis() as u64,
                        reason = "idle_timeout",
                        "UDP relay stopped"
                    );
                    break;
                }
            }
        }
    });
}

/// Returns an unspecified bind address matching the destination IP family.
fn unspecified_for(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0; 16], 0)),
    }
}

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
#[derive(Clone)]
/// Placeholder client that reports TLS-PSK support is unavailable on this build.
pub struct TlsPskMappingClient;

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
impl TlsPskMappingClient {
    /// Always returns `UnsupportedPlatform` when the Windows TLS feature is absent.
    pub async fn connect(
        _endpoint: &str,
        _identity: &str,
        _secret: &[u8],
    ) -> Result<Self, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }

    /// Reports that BPF activation is unavailable without the Windows TLS client.
    pub async fn activate(
        &self,
        _elf_path: &str,
        _interface: &str,
        _proxy: SocketAddr,
    ) -> Result<(), ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }

    /// Reports that BPF detachment is unavailable without the Windows TLS client.
    pub async fn detach(&self, _interface: &str) -> Result<(), ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }
}

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
#[async_trait]
impl MappingClient for TlsPskMappingClient {
    /// Always returns `UnsupportedPlatform` when the Windows TLS feature is absent.
    async fn get_mapping(&self, _tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }
}

#[cfg(not(all(target_os = "windows", feature = "tls-psk")))]
#[async_trait]
impl FlowClient for TlsPskMappingClient {
    /// Reports that typed flow operations are unavailable without TLS support.
    async fn enumerate_flows(
        &self,
        _page_token: Vec<u8>,
        _limit: u32,
    ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }

    /// Reports that typed flow operations are unavailable without TLS support.
    async fn delete_flow(
        &self,
        _flow_id: u64,
        _generation: u32,
    ) -> Result<FlowDeleteReport, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }
}

#[cfg(all(target_os = "windows", feature = "tls-psk"))]
/// Windows TLS-PSK control-service client, compiled only with `tls-psk`.
mod windows_client {
    use super::*;
    use hyper_util::rt::TokioIo;
    use openssl::{
        error::ErrorStack,
        ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion},
    };
    use std::pin::Pin;
    use tokio_openssl::SslStream;
    use tonic::transport::Endpoint;
    use tower::service_fn;

    #[derive(Clone)]
    /// Reusable TLS-PSK gRPC channel for mapping lookups.
    pub struct TlsPskMappingClient {
        /// Serialized access to the tonic client because lookups are concurrent.
        client: Arc<Mutex<proto::control_client::ControlClient<tonic::transport::Channel>>>,
    }

    impl TlsPskMappingClient {
        /// Validates credentials, builds TLS 1.2 PSK context, and connects the
        /// tonic channel to `endpoint`.
        pub async fn connect(
            endpoint: &str,
            identity: &str,
            secret: &[u8],
        ) -> Result<Self, ProxyError> {
            if identity.as_bytes().contains(&0) || identity.is_empty() || secret.is_empty() {
                return Err(ProxyError::InvalidConfiguration(
                    "invalid TLS-PSK credentials".into(),
                ));
            }
            let uri: http::Uri = endpoint.parse().map_err(|error| {
                ProxyError::InvalidConfiguration(format!("invalid endpoint: {error}"))
            })?;
            let context = build_context(identity, secret)?;
            let connector = service_fn(move |uri: http::Uri| {
                let context = context.clone();
                async move { connect_tls(uri, context).await }
            });
            let channel = Endpoint::from(uri)
                .connect_with_connector(connector)
                .await
                .map_err(|error| ProxyError::Control(error.to_string()))?;
            Ok(Self {
                client: Arc::new(Mutex::new(proto::control_client::ControlClient::new(
                    channel,
                ))),
            })
        }

        /// Attaches the WSL BPF ELF and sets this proxy listener as its family
        /// target before the proxy begins accepting redirected traffic.
        pub async fn activate(
            &self,
            elf_path: &str,
            interface: &str,
            proxy: SocketAddr,
        ) -> Result<(), ProxyError> {
            if elf_path.is_empty() || interface.is_empty() {
                return Err(ProxyError::InvalidConfiguration(
                    "BPF ELF path and interface are required".into(),
                ));
            }
            let mut client = self.client.lock().await;
            let attached = client
                .attach(proto::InterfaceRequest {
                    elf_path: elf_path.into(),
                    interfaces: vec![interface.into()],
                })
                .await
                .map_err(|error| ProxyError::Control(error.to_string()))?
                .into_inner();
            if !attached.success {
                return Err(ProxyError::Control(attached.message));
            }
            let configured = async {
                let mut config = client
                    .get_config(proto::Empty {})
                    .await
                    .map_err(|error| ProxyError::Control(error.to_string()))?
                    .into_inner()
                    .config
                    .ok_or_else(|| {
                        ProxyError::Control("control service returned no config".into())
                    })?;
                match proxy.ip() {
                    IpAddr::V4(address) => {
                        config.ipv4_target_address = address.octets().to_vec();
                        config.ipv4_target_port = proxy.port() as u32;
                    }
                    IpAddr::V6(address) => {
                        config.ipv6_target_address = address.octets().to_vec();
                        config.ipv6_target_port = proxy.port() as u32;
                    }
                }
                client
                    .set_config(proto::SetConfigRequest {
                        config: Some(config),
                    })
                    .await
                    .map_err(|error| ProxyError::Control(error.to_string()))?;
                Ok(())
            }
            .await;
            if let Err(error) = configured {
                let rollback = client
                    .detach(proto::DetachRequest {
                        interfaces: vec![interface.into()],
                        all: false,
                    })
                    .await;
                return match rollback {
                    Ok(_) => Err(error),
                    Err(rollback_error) => Err(ProxyError::Control(format!(
                        "{error}; attach rollback failed: {rollback_error}"
                    ))),
                };
            }
            Ok(())
        }

        /// Detaches BPF classifiers associated with one interface.
        pub async fn detach(&self, interface: &str) -> Result<(), ProxyError> {
            self.client
                .lock()
                .await
                .detach(proto::DetachRequest {
                    interfaces: vec![interface.into()],
                    all: false,
                })
                .await
                .map_err(|error| ProxyError::Control(error.to_string()))?;
            Ok(())
        }

        /// Enumerates one bounded page of typed flow records.
        pub async fn enumerate_flows(
            &self,
            page_token: Vec<u8>,
            limit: u32,
        ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
            let reply = self
                .client
                .lock()
                .await
                .enumerate_flows(proto::EnumerateFlowsRequest { limit, page_token })
                .await
                .map_err(|error| ProxyError::Control(error.to_string()))?
                .into_inner();
            let mut flows = Vec::with_capacity(reply.flows.len());
            for flow in reply.flows {
                let synthetic = tuple_from_proto(flow.synthetic.ok_or_else(|| {
                    ProxyError::InvalidMapping("flow synthetic tuple missing".into())
                })?)?;
                let original = tuple_from_proto(flow.original.ok_or_else(|| {
                    ProxyError::InvalidMapping("flow original tuple missing".into())
                })?)?;
                if synthetic.protocol != flow.protocol as u8
                    || original.protocol != flow.protocol as u8
                {
                    return Err(ProxyError::InvalidMapping(
                        "flow protocol does not match tuples".into(),
                    ));
                }
                flows.push(FlowRecord {
                    flow_id: flow.flow_id,
                    generation: flow.generation,
                    synthetic,
                    original,
                    last_used_ns: flow.last_used_ns,
                    protocol_flags: flow.protocol_flags,
                    tcp_state_flags: flow.tcp_state_flags,
                    observed_now_ns: flow.observed_now_ns,
                });
            }
            Ok((flows, reply.next_page_token))
        }

        /// Deletes one generation-checked flow and converts its typed outcome.
        pub async fn delete_flow(
            &self,
            flow_id: u64,
            generation: u32,
        ) -> Result<FlowDeleteReport, ProxyError> {
            let reply = self
                .client
                .lock()
                .await
                .delete_flow(proto::DeleteFlowRequest {
                    flow_id,
                    generation,
                })
                .await
                .map_err(|error| ProxyError::Control(error.to_string()))?
                .into_inner();
            let outcome = match proto::delete_flow_reply::Outcome::try_from(reply.outcome)
                .map_err(|_| ProxyError::Control("unknown flow deletion outcome".into()))?
            {
                proto::delete_flow_reply::Outcome::Complete => FlowDeleteOutcome::Complete,
                proto::delete_flow_reply::Outcome::AlreadyAbsent => {
                    FlowDeleteOutcome::AlreadyAbsent
                }
                proto::delete_flow_reply::Outcome::StaleGeneration => {
                    FlowDeleteOutcome::StaleGeneration
                }
                proto::delete_flow_reply::Outcome::Partial => FlowDeleteOutcome::Partial,
            };
            Ok(FlowDeleteReport {
                flow_id: reply.flow_id,
                generation: reply.generation,
                outcome,
                indexes_deleted: reply.indexes_deleted,
                state_deleted: reply.state_deleted,
                retryable: reply.retryable,
            })
        }
    }

    #[async_trait]
    impl MappingClient for TlsPskMappingClient {
        /// Converts the socket tuple to protobuf, performs the RPC, and
        /// validates the returned original tuple and protocol.
        async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            let request = proto::GetMappingRequest {
                synthetic: Some(proto::Tuple {
                    family: if tuple.source.is_ipv4() { 4 } else { 6 },
                    source_address: ip_bytes(&tuple.source.ip()),
                    destination_address: ip_bytes(&tuple.destination.ip()),
                    protocol: tuple.protocol as u32,
                    source_port: tuple.source.port() as u32,
                    destination_port: tuple.destination.port() as u32,
                }),
            };
            let mapping = self
                .client
                .lock()
                .await
                .get_mapping(request)
                .await
                .map_err(|error| {
                    if error.code() == tonic::Code::NotFound {
                        ProxyError::MappingNotFound
                    } else {
                        ProxyError::Control(error.to_string())
                    }
                })?
                .into_inner();
            let synthetic = mapping
                .synthetic
                .ok_or_else(|| ProxyError::InvalidMapping("missing synthetic tuple".into()))?;
            if tuple_from_proto(synthetic)? != *tuple {
                return Err(ProxyError::InvalidMapping(
                    "mapping synthetic tuple does not match lookup".into(),
                ));
            }
            let original = mapping
                .original
                .ok_or_else(|| ProxyError::InvalidMapping("missing original tuple".into()))?;
            let address = tuple_from_proto(original)?;
            if address.protocol != tuple.protocol {
                return Err(ProxyError::InvalidMapping(
                    "mapping protocol does not match lookup".into(),
                ));
            }
            if address.destination.ip().is_unspecified()
                || address.destination.port() == 0
                || address.destination.is_ipv4() != tuple.destination.is_ipv4()
            {
                return Err(ProxyError::InvalidMapping(
                    "mapping destination has an invalid address or port".into(),
                ));
            }
            Ok(OriginalDestination {
                address: address.destination,
                protocol: address.protocol,
            })
        }
    }

    #[async_trait]
    impl FlowClient for TlsPskMappingClient {
        /// Delegates typed flow enumeration to the authenticated channel.
        async fn enumerate_flows(
            &self,
            page_token: Vec<u8>,
            limit: u32,
        ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
            self.enumerate_flows(page_token, limit).await
        }

        /// Delegates generation-checked flow deletion to the authenticated channel.
        async fn delete_flow(
            &self,
            flow_id: u64,
            generation: u32,
        ) -> Result<FlowDeleteReport, ProxyError> {
            self.delete_flow(flow_id, generation).await
        }
    }

    /// Converts a protobuf tuple to a socket tuple, rejecting family/width and
    /// protocol-field violations.
    fn tuple_from_proto(tuple: proto::Tuple) -> Result<Tuple, ProxyError> {
        let source = ip_from_bytes(tuple.family, &tuple.source_address)?;
        let destination = ip_from_bytes(tuple.family, &tuple.destination_address)?;
        if tuple.protocol > u8::MAX as u32
            || tuple.source_port > u16::MAX as u32
            || tuple.destination_port > u16::MAX as u32
        {
            return Err(ProxyError::InvalidMapping(
                "tuple field out of range".into(),
            ));
        }

        Ok(Tuple {
            source: SocketAddr::new(source, tuple.source_port as u16),
            destination: SocketAddr::new(destination, tuple.destination_port as u16),
            protocol: tuple.protocol as u8,
        })
    }

    /// Encodes an IP address as its native 4- or 16-byte representation.
    fn ip_bytes(address: &IpAddr) -> Vec<u8> {
        match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        }
    }

    /// Decodes a family-tagged address and rejects incorrect byte lengths.
    fn ip_from_bytes(family: u32, bytes: &[u8]) -> Result<IpAddr, ProxyError> {
        match family {
            4 if bytes.len() == 4 => Ok(IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ))),
            6 if bytes.len() == 16 => Ok(IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).unwrap(),
            ))),
            _ => Err(ProxyError::InvalidMapping("invalid address family".into())),
        }
    }

    /// Builds the TLS 1.2 AES-256-GCM PSK context used by the Windows client.
    fn build_context(identity: &str, secret: &[u8]) -> Result<Arc<SslContext>, ProxyError> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).map_err(openssl_error)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(openssl_error)?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(openssl_error)?;
        builder
            .set_cipher_list("PSK-AES256-GCM-SHA384")
            .map_err(openssl_error)?;
        builder.set_alpn_protos(b"\x02h2").map_err(openssl_error)?;
        let identity = identity.as_bytes().to_vec();
        let secret = secret.to_vec();
        builder.set_psk_client_callback(move |_, _, identity_out, key_out| {
            if identity_out.len() < identity.len() + 1 || key_out.len() < secret.len() {
                return Err(ErrorStack::get());
            }
            identity_out[..identity.len()].copy_from_slice(&identity);
            identity_out[identity.len()] = 0;
            key_out[..secret.len()].copy_from_slice(&secret);
            Ok(secret.len())
        });
        Ok(Arc::new(builder.build()))
    }

    /// Opens a TCP stream within five seconds for the URI and completes the
    /// client TLS handshake so an unreachable control service cannot block
    /// proxy startup indefinitely.
    async fn connect_tls(
        uri: http::Uri,
        context: Arc<SslContext>,
    ) -> Result<TokioIo<SslStream<TcpStream>>, io::Error> {
        let authority = uri.authority().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "endpoint authority missing")
        })?;
        let stream = time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(authority.as_str()),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control connect timeout"))??;
        let host = authority.host();
        let mut ssl = Ssl::new(&context).map_err(openssl_io_error)?;
        ssl.set_hostname(host).map_err(openssl_io_error)?;
        let mut ssl = SslStream::new(ssl, stream).map_err(openssl_io_error)?;
        time::timeout(Duration::from_secs(5), Pin::new(&mut ssl).connect())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control TLS handshake timeout"))?
            .map_err(openssl_io_error)?;
        Ok(TokioIo::new(ssl))
    }

    /// Converts OpenSSL setup failures into proxy control errors.
    fn openssl_error(error: ErrorStack) -> ProxyError {
        ProxyError::Control(error.to_string())
    }

    /// Converts an OpenSSL/display error into an I/O error for async adapters.
    fn openssl_io_error(error: impl std::fmt::Display) -> io::Error {
        io::Error::other(error.to_string())
    }

    pub use self::TlsPskMappingClient as PublicTlsPskMappingClient;
}

#[cfg(all(target_os = "windows", feature = "tls-psk"))]
pub use windows_client::PublicTlsPskMappingClient as TlsPskMappingClient;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{HashSet, VecDeque},
        sync::Mutex as StdMutex,
    };
    use tracing::{field::Visit, Event, Subscriber};
    use tracing_subscriber::{
        layer::{Context, Layer},
        prelude::*,
        registry::LookupSpan,
    };

    #[derive(Clone, Default)]
    struct EventRecorder {
        reasons: Arc<StdMutex<Vec<String>>>,
        field_sets: Arc<StdMutex<Vec<HashSet<String>>>>,
    }

    struct FieldVisitor {
        fields: HashSet<String>,
        reasons: Vec<String>,
    }

    impl FieldVisitor {
        fn new() -> Self {
            Self {
                fields: HashSet::new(),
                reasons: Vec::new(),
            }
        }
    }

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields.insert(field.name().to_owned());
            if field.name() == "reason" {
                self.reasons.push(format!("{value:?}"));
            }
        }
    }

    impl<S> Layer<S> for EventRecorder
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = FieldVisitor::new();
            event.record(&mut visitor);
            self.reasons.lock().unwrap().extend(visitor.reasons);
            self.field_sets.lock().unwrap().push(visitor.fields);
        }
    }

    impl EventRecorder {
        fn has_reason(&self, reason: &str) -> bool {
            self.reasons
                .lock()
                .unwrap()
                .iter()
                .any(|value| value.contains(reason))
        }

        fn count_reason(&self, reason: &str) -> usize {
            self.reasons
                .lock()
                .unwrap()
                .iter()
                .filter(|value| value.contains(reason))
                .count()
        }

        fn has_fields(&self, required: &[&str]) -> bool {
            self.field_sets.lock().unwrap().iter().any(|fields| {
                required
                    .iter()
                    .all(|required_field| fields.contains(*required_field))
            })
        }
    }

    #[derive(Clone)]
    struct MockClient {
        destination: SocketAddr,
        protocol: u8,
    }

    #[async_trait]
    impl MappingClient for MockClient {
        async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            assert_eq!(tuple.protocol, self.protocol);
            Ok(OriginalDestination {
                address: self.destination,
                protocol: tuple.protocol,
            })
        }
    }

    #[async_trait]
    impl FlowClient for MockClient {
        async fn enumerate_flows(
            &self,
            _page_token: Vec<u8>,
            _limit: u32,
        ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
            Ok((Vec::new(), Vec::new()))
        }

        async fn delete_flow(
            &self,
            _flow_id: u64,
            _generation: u32,
        ) -> Result<FlowDeleteReport, ProxyError> {
            Ok(FlowDeleteReport {
                flow_id: 0,
                generation: 0,
                outcome: FlowDeleteOutcome::AlreadyAbsent,
                indexes_deleted: 0,
                state_deleted: false,
                retryable: false,
            })
        }
    }

    struct SequenceClient {
        destinations: StdMutex<VecDeque<SocketAddr>>,
    }

    #[async_trait]
    impl MappingClient for SequenceClient {
        async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            Ok(OriginalDestination {
                address: self.destinations.lock().unwrap().pop_front().unwrap(),
                protocol: tuple.protocol,
            })
        }
    }

    #[async_trait]
    impl FlowClient for SequenceClient {
        async fn enumerate_flows(
            &self,
            _page_token: Vec<u8>,
            _limit: u32,
        ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
            Ok((Vec::new(), Vec::new()))
        }

        async fn delete_flow(
            &self,
            _flow_id: u64,
            _generation: u32,
        ) -> Result<FlowDeleteReport, ProxyError> {
            Ok(FlowDeleteReport {
                flow_id: 0,
                generation: 0,
                outcome: FlowDeleteOutcome::AlreadyAbsent,
                indexes_deleted: 0,
                state_deleted: false,
                retryable: false,
            })
        }
    }

    #[test]
    fn configuration_rejects_missing_credentials_and_zero_timeout() {
        let config = ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            control_endpoint: "https://127.0.0.1:50051".into(),
            psk_identity: String::new(),
            psk_secret: Vec::new(),
            udp_idle_timeout: Duration::ZERO,
            cleanup_interval: Duration::from_secs(5),
            idle_ttl: Duration::from_secs(60),
            tcp_terminal_grace: Duration::from_secs(30),
            flow_scan_batch: 256,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn configuration_rejects_wildcard_listen_address() {
        let config = ProxyConfig {
            listen: "0.0.0.0:15000".parse().unwrap(),
            control_endpoint: "https://127.0.0.1:50051".into(),
            psk_identity: "identity".into(),
            psk_secret: vec![1],
            udp_idle_timeout: Duration::from_secs(5),
            cleanup_interval: Duration::from_secs(5),
            idle_ttl: Duration::from_secs(60),
            tcp_terminal_grace: Duration::from_secs(30),
            flow_scan_batch: 256,
        };
        assert!(matches!(
            config.validate(),
            Err(ProxyError::InvalidConfiguration(message))
                if message.contains("listen address must be specific")
        ));
    }

    #[tokio::test]
    async fn tcp_bridge_copies_data_to_original_destination() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &buffer)
                .await
                .unwrap();
        });
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = client_listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (stream, _) = client_listener.accept().await.unwrap();
            bridge_tcp(
                stream,
                Arc::new(MockClient {
                    destination,
                    protocol: TCP_PROTOCOL,
                }),
            )
            .await
            .unwrap();
        });
        let mut client = TcpStream::connect(client_address).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, b"test")
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut response)
            .await
            .unwrap();
        assert_eq!(&response, b"test");
        drop(client);
        accepted.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_forwarding_relays_response_to_originating_client() {
        let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 4];
            let (length, client_address) = destination.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"ping");
            destination.send_to(b"pong", client_address).await.unwrap();
        });

        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let associations = Arc::new(UdpAssociations::new(
            proxy_socket.clone(),
            Arc::new(MockClient {
                destination: destination_address,
                protocol: UDP_PROTOCOL,
            }),
            Duration::from_secs(5),
            shutdown,
        ));
        let receiver = tokio::spawn(run_udp(associations, shutdown_sender.subscribe()));

        client_socket
            .send_to(b"ping", proxy_socket.local_addr().unwrap())
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        let (length, sender) = time::timeout(
            Duration::from_secs(2),
            client_socket.recv_from(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[..length], b"pong");
        assert_eq!(sender, proxy_socket.local_addr().unwrap());
        shutdown_sender.send(true).unwrap();
        receiver.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_lifecycle_events_capture_replacement_and_expiry() {
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        let _default = tracing::subscriber::set_default(subscriber);

        let first_destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (shutdown_sender, shutdown) = watch::channel(false);
        let associations = UdpAssociations::new(
            proxy_socket.clone(),
            Arc::new(SequenceClient {
                destinations: StdMutex::new(VecDeque::from([
                    first_destination.local_addr().unwrap(),
                    second_destination.local_addr().unwrap(),
                    second_destination.local_addr().unwrap(),
                ])),
            }),
            Duration::from_secs(5),
            shutdown,
        );
        let client_address: SocketAddr = "127.0.0.1:42000".parse().unwrap();

        associations.forward(client_address, b"one").await.unwrap();
        associations.forward(client_address, b"two").await.unwrap();
        associations
            .forward(client_address, b"three")
            .await
            .unwrap();

        let tuple = Tuple {
            source: client_address,
            destination: proxy_socket.local_addr().unwrap(),
            protocol: UDP_PROTOCOL,
        };
        let association = associations
            .entries
            .lock()
            .await
            .get(&tuple)
            .unwrap()
            .clone();
        *association.last_seen.lock().await = std::time::Instant::now() - Duration::from_secs(10);
        associations.reap().await;
        shutdown_sender.send(true).unwrap();

        assert_eq!(recorder.count_reason("association_created"), 1);
        assert_eq!(recorder.count_reason("association_replaced"), 0);
        assert_eq!(recorder.count_reason("idle_timeout"), 1);
        assert!(recorder.has_fields(&[
            "protocol",
            "synthetic_source",
            "synthetic_destination",
            "original_destination",
            "association_age_ms",
        ]));
    }

    #[test]
    fn tcp_cancellation_emits_termination_event() {
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        let _default = tracing::subscriber::set_default(subscriber);
        let guard = TcpForwardingGuard {
            tuple: Tuple {
                source: "127.0.0.1:42000".parse().unwrap(),
                destination: "127.0.0.1:15000".parse().unwrap(),
                protocol: TCP_PROTOCOL,
            },
            original_destination: "127.0.0.1:443".parse().unwrap(),
            completed: false,
        };
        drop(guard);
        assert!(recorder.has_reason("cancelled"));
    }
}
