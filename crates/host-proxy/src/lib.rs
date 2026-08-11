// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Runs the TCP/UDP host-side forwarder and its platform-specific control
//! service client.

#[cfg(all(feature = "tls-psk", feature = "tls-rustls"))]
compile_error!("tls-psk and tls-rustls are mutually exclusive");

#[cfg(any(target_os = "windows", test))]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use thiserror::Error;
#[cfg(any(not(target_os = "windows"), test))]
use tokio::net::TcpListener;
#[cfg(not(target_os = "windows"))]
use tokio::task::JoinSet;
use tokio::{
    io,
    net::{TcpStream, UdpSocket},
    sync::{watch, Mutex, Notify},
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
/// Upper bound for a host-issued control RPC or maintenance operation.
const CONTROL_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Lifecycle state for a Windows conditional-accept request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[cfg(any(target_os = "windows", test))]
enum ConditionalAttemptState {
    /// Request has been deferred and awaits preconnect.
    Deferred = 0,
    /// Worker owns a preconnected outbound socket.
    Ready = 1,
    /// Callback permitted `WSAAccept` to return the client socket.
    Claimed = 2,
    /// Request must receive conditional rejection.
    Rejected = 3,
    /// Shutdown cancelled the request before completion.
    Cancelled = 4,
}

#[cfg(any(target_os = "windows", test))]
impl ConditionalAttemptState {
    /// Decodes the atomic representation, treating unknown values as cancelled.
    fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Deferred,
            1 => Self::Ready,
            2 => Self::Claimed,
            3 => Self::Rejected,
            _ => Self::Cancelled,
        }
    }
}

/// Exact deferred-request identity. The generation prevents a late worker
/// result from being associated with a new request using the same tuple.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConditionalRequestId {
    /// Exact synthetic tuple presented to the condition callback.
    tuple: Tuple,
    /// Unique incarnation for one deferred use of that tuple.
    generation: u64,
}

/// State shared by the conditional callback, coordinator, and preconnect
/// worker. It contains no socket ownership so it is also testable off Windows.
#[cfg(any(target_os = "windows", test))]
struct ConditionalAttempt {
    /// Immutable identity for this deferred attempt.
    id: ConditionalRequestId,
    /// Timestamp of the initial `CF_DEFER`.
    #[cfg(target_os = "windows")]
    deferred_at: std::time::Instant,
    /// Atomic lifecycle state shared across native contexts.
    state: AtomicU8,
    /// Ensures the admission count is decremented at most once.
    released: AtomicBool,
}

#[cfg(any(target_os = "windows", test))]
impl ConditionalAttempt {
    /// Creates a request in the deferred state.
    fn new(id: ConditionalRequestId) -> Self {
        Self {
            id,
            #[cfg(target_os = "windows")]
            deferred_at: std::time::Instant::now(),
            state: AtomicU8::new(ConditionalAttemptState::Deferred as u8),
            released: AtomicBool::new(false),
        }
    }

    /// Reads the atomically published lifecycle state.
    fn state(&self) -> ConditionalAttemptState {
        ConditionalAttemptState::from_raw(self.state.load(Ordering::Acquire))
    }
}

/// Atomically limits pending Windows conditional-accept attempts and gives
/// every admitted request a monotonically increasing generation.
#[cfg(any(target_os = "windows", test))]
struct ConditionalAdmissions {
    /// Maximum number of unaccepted deferred attempts.
    limit: usize,
    /// Currently reserved deferred attempts.
    pending: AtomicUsize,
    /// Source of unique request-generation values.
    next_generation: AtomicU64,
}

#[cfg(any(target_os = "windows", test))]
impl ConditionalAdmissions {
    /// Creates an admission controller with the configured limit.
    fn new(limit: usize) -> Self {
        Self {
            limit,
            pending: AtomicUsize::new(0),
            next_generation: AtomicU64::new(1),
        }
    }

    /// Reserves one bounded attempt and assigns its request generation.
    fn reserve(&self, tuple: Tuple) -> Option<ConditionalAttempt> {
        let mut current = self.pending.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return None;
            }
            match self.pending.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
                    return Some(ConditionalAttempt::new(ConditionalRequestId {
                        tuple,
                        generation,
                    }));
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Releases a reservation once, including on stale completion and shutdown
    /// paths that race the conditional callback.
    fn release(&self, attempt: &ConditionalAttempt) {
        if !attempt.released.swap(true, Ordering::AcqRel) {
            self.pending.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }
}

/// Computes the remaining conditional-preconnect budget from the first defer,
/// not from when a worker happens to start.
#[cfg(any(target_os = "windows", test))]
fn conditional_preconnect_budget(deferred_at: std::time::Instant) -> Result<Duration, ProxyError> {
    CONTROL_RPC_TIMEOUT
        .checked_sub(deferred_at.elapsed())
        .ok_or_else(|| {
            ProxyError::Control("conditional preconnect timed out before it started".into())
        })
}

/// Changes a deferred request to ready only once its outbound socket is stored.
#[cfg(any(target_os = "windows", test))]
fn mark_attempt_ready(attempt: &ConditionalAttempt) -> bool {
    attempt
        .state
        .compare_exchange(
            ConditionalAttemptState::Deferred as u8,
            ConditionalAttemptState::Ready as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Claims a ready request for the single matching accepted client socket.
#[cfg(any(target_os = "windows", test))]
fn claim_ready_attempt(attempt: &ConditionalAttempt) -> bool {
    attempt
        .state
        .compare_exchange(
            ConditionalAttemptState::Ready as u8,
            ConditionalAttemptState::Claimed as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

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
    /// The selected build does not provide its platform TLS mapping client.
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
    /// Directional FIN observations, bit zero for original-to-target and bit
    /// one for target-to-original.
    pub fin_seen_mask: u32,
    /// Directional FIN acknowledgements using the same direction bits.
    pub fin_ack_seen_mask: u32,
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
    /// The flow changed after enumeration and was not deleted.
    ObservationMismatch,
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
        observed_last_used_ns: u64,
    ) -> Result<FlowDeleteReport, ProxyError>;
}

#[derive(Clone)]
/// Listener, control-service, credential, and UDP lifecycle settings.
pub struct ProxyConfig {
    /// Specific local address shared by the TCP and UDP listeners.
    pub listen: SocketAddr,
    /// Native TCP listen backlog. Windows uses a separate fixed conditional
    /// work capacity because Winsock condition callbacks service one queued
    /// connection at a time.
    pub listen_backlog: u32,
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
        #[cfg(not(feature = "tls-rustls"))]
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
        if self.listen_backlog == 0 || self.listen_backlog > i32::MAX as u32 {
            return Err(ProxyError::InvalidConfiguration(
                "native listen backlog must be between 1 and i32::MAX; it does not size internal conditional-accept queues".into(),
            ));
        }
        for (name, duration) in [
            ("UDP idle timeout", self.udp_idle_timeout),
            ("cleanup interval", self.cleanup_interval),
            ("idle TTL", self.idle_ttl),
            ("TCP terminal grace", self.tcp_terminal_grace),
        ] {
            duration_to_nanos(duration, name)?;
        }
        if self.cleanup_interval.is_zero()
            || self.idle_ttl.is_zero()
            || self.tcp_terminal_grace.is_zero()
            || self.flow_scan_batch == 0
            || self.flow_scan_batch > 10_000
        {
            return Err(ProxyError::InvalidConfiguration(
                "maintenance settings must be nonzero".into(),
            ));
        }
        Ok(())
    }

    /// Validates the legacy OpenSSL TLS-PSK credentials used by the PSK
    /// control client.
    #[cfg(feature = "tls-psk")]
    pub fn validate_tls_psk(&self) -> Result<(), ProxyError> {
        if self.psk_identity.is_empty() || self.psk_secret.is_empty() {
            return Err(ProxyError::InvalidConfiguration(
                "PSK identity and secret are required".into(),
            ));
        }
        Ok(())
    }
}

/// Converts timeout settings to the dataplane's bounded nanosecond domain.
fn duration_to_nanos(duration: Duration, name: &str) -> Result<u64, ProxyError> {
    u64::try_from(duration.as_nanos()).map_err(|_| {
        ProxyError::InvalidConfiguration(format!("{name} is too large to represent in nanoseconds"))
    })
}

/// Runs a control operation with a local deadline and cooperative shutdown.
async fn control_operation<T>(
    shutdown: &mut watch::Receiver<bool>,
    operation: impl Future<Output = Result<T, ProxyError>>,
) -> Result<Option<T>, ProxyError> {
    tokio::select! {
        _ = shutdown.changed() => Ok(None),
        result = time::timeout(CONTROL_RPC_TIMEOUT, operation) => {
            match result {
                Ok(result) => result.map(Some),
                Err(_) => Err(ProxyError::Control("control RPC timed out".into())),
            }
        }
    }
}

/// Runs serialized host-owned flow maintenance until shutdown.
#[allow(clippy::too_many_arguments)]
async fn run_maintenance<C: MappingClient + FlowClient + 'static>(
    client: Arc<C>,
    associations: Arc<UdpAssociations<C>>,
    cleanup_interval: Duration,
    udp_idle_timeout: Duration,
    idle_ttl: Duration,
    tcp_terminal_grace: Duration,
    flow_scan_batch: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    let initial_retry_delay = cleanup_interval.min(Duration::from_millis(100));
    let mut retry_delay = initial_retry_delay;
    let mut pending_deletes = std::collections::HashMap::<(u64, u32), FlowRecord>::new();
    let udp_idle_timeout_ns =
        duration_to_nanos(udp_idle_timeout, "UDP idle timeout").expect("validated configuration");
    let idle_ttl_ns = duration_to_nanos(idle_ttl, "idle TTL").expect("validated configuration");
    let tcp_terminal_grace_ns = duration_to_nanos(tcp_terminal_grace, "TCP terminal grace")
        .expect("validated configuration");
    let mut next_run = time::Instant::now();
    'maintenance: loop {
        let sleep = time::sleep_until(next_run);
        tokio::pin!(sleep);
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = &mut sleep => {
                let mut token = Vec::new();
                let mut pass_failed = false;
                loop {
                    let page = control_operation(
                        &mut shutdown,
                        client.enumerate_flows(token, flow_scan_batch),
                    )
                    .await;
                    let page = match page {
                        Ok(Some(page)) => page,
                        Ok(None) => break 'maintenance,
                        Err(error) => {
                            tracing::warn!(%error, "host maintenance flow enumeration failed");
                            pass_failed = true;
                            break;
                        }
                    };
                    let (flows, next) = page;
                    for flow in flows {
                        let age = flow.observed_now_ns.saturating_sub(flow.last_used_ns);
                        let tcp = flow.original.protocol == TCP_PROTOCOL;
                        if flow.original.protocol == UDP_PROTOCOL {
                            associations
                                .observe_flow(&flow.synthetic, flow.flow_id, flow.generation)
                                .await;
                        }
                        let terminal = tcp
                            && flow.fin_seen_mask == 0b11
                            && flow.fin_ack_seen_mask == 0b11;
                        let idle_threshold = if flow.original.protocol == UDP_PROTOCOL {
                            udp_idle_timeout_ns
                        } else {
                            idle_ttl_ns
                        };
                        let expired = flow.tcp_state_flags & (1 << 4) != 0
                            || (!terminal && age >= idle_threshold)
                            || (terminal && age >= tcp_terminal_grace_ns);
                        if expired {
                            pending_deletes.insert((flow.flow_id, flow.generation), flow);
                        }
                    }
                    if next.is_empty() {
                        break;
                    }
                    token = next;
                }
                let pending = pending_deletes.values().cloned().collect::<Vec<_>>();
                for flow in pending {
                    match control_operation(
                        &mut shutdown,
                        client.delete_flow(
                            flow.flow_id,
                            flow.generation,
                            flow.last_used_ns,
                        ),
                    )
                    .await
                    {
                        Ok(Some(report)) => {
                            if matches!(
                                report.outcome,
                                FlowDeleteOutcome::Complete
                                    | FlowDeleteOutcome::AlreadyAbsent
                                    | FlowDeleteOutcome::StaleGeneration
                                    | FlowDeleteOutcome::ObservationMismatch
                            ) {
                                pending_deletes.remove(&(flow.flow_id, flow.generation));
                                if flow.original.protocol == UDP_PROTOCOL
                                    && matches!(
                                        report.outcome,
                                        FlowDeleteOutcome::Complete
                                            | FlowDeleteOutcome::AlreadyAbsent
                                    )
                                {
                                    associations
                                        .invalidate(
                                            &flow.synthetic,
                                            flow.flow_id,
                                            flow.generation,
                                        )
                                        .await;
                                }
                            }
                            if report.retryable {
                                pass_failed = true;
                            }
                            tracing::info!(
                                flow_id = flow.flow_id,
                                generation = flow.generation,
                                outcome = ?report.outcome,
                                "host maintenance flow deletion"
                            );
                        }
                        Ok(None) => break 'maintenance,
                        Err(error) => {
                            pass_failed = true;
                            tracing::warn!(
                                flow_id = flow.flow_id,
                                generation = flow.generation,
                                %error,
                                "host maintenance flow deletion failed"
                            );
                        }
                    }
                }
                if pass_failed {
                    let delay = retry_delay;
                    retry_delay = retry_delay
                        .saturating_mul(2)
                        .min(cleanup_interval);
                    next_run = time::Instant::now() + delay;
                } else {
                    retry_delay = initial_retry_delay;
                    next_run = time::Instant::now() + cleanup_interval;
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

/// A TCP listener whose Windows implementation owns the conditional-accept
/// callback context for the complete coordinator lifetime.
pub struct BoundTcpListener {
    /// Tokio listener retained by the unchanged non-Windows path.
    #[cfg(not(target_os = "windows"))]
    listener: TcpListener,
    /// Native conditional listener retained by the Windows coordinator path.
    #[cfg(target_os = "windows")]
    listener: windows_conditional::ConditionalListener,
}

impl BoundTcpListener {
    /// Returns the exact address selected by the TCP listener.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        #[cfg(not(target_os = "windows"))]
        {
            self.listener.local_addr()
        }
        #[cfg(target_os = "windows")]
        {
            Ok(self.listener.local_addr())
        }
    }
}

impl<C: MappingClient + FlowClient + 'static> Proxy<C> {
    /// Validates configuration and creates a proxy that has not opened sockets.
    pub fn new(config: ProxyConfig, client: Arc<C>) -> Result<Self, ProxyError> {
        config.validate()?;
        Ok(Self { config, client })
    }

    /// Binds TCP and UDP listeners at the configured specific address.
    pub async fn bind(&self) -> Result<(BoundTcpListener, Arc<UdpSocket>), ProxyError> {
        #[cfg(not(target_os = "windows"))]
        {
            let tcp_listener = TcpListener::bind(self.config.listen).await?;
            let actual_listen = tcp_listener.local_addr()?;
            let udp_socket = Arc::new(UdpSocket::bind(actual_listen).await?);
            Ok((
                BoundTcpListener {
                    listener: tcp_listener,
                },
                udp_socket,
            ))
        }
        #[cfg(target_os = "windows")]
        {
            let tcp_listener = windows_conditional::ConditionalListener::bind(
                self.config.listen,
                self.config.listen_backlog,
            )?;
            let actual_listen = tcp_listener.local_addr();
            let udp_socket = Arc::new(UdpSocket::bind(actual_listen).await?);
            Ok((
                BoundTcpListener {
                    listener: tcp_listener,
                },
                udp_socket,
            ))
        }
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
        tcp_listener: BoundTcpListener,
        udp_socket: Arc<UdpSocket>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ProxyError> {
        // A local fanout makes a sibling task failure a coordinated shutdown
        // rather than an abort that could strand Windows native threads.
        let (stop, task_shutdown) = watch::channel(false);
        let udp = Arc::new(UdpAssociations::new(
            udp_socket,
            self.client.clone(),
            self.config.udp_idle_timeout,
            task_shutdown.clone(),
        ));
        let maintenance = tokio::spawn(run_maintenance(
            self.client.clone(),
            udp.clone(),
            self.config.cleanup_interval,
            self.config.udp_idle_timeout,
            self.config.idle_ttl,
            self.config.tcp_terminal_grace,
            self.config.flow_scan_batch,
            task_shutdown.clone(),
        ));
        let mut tcp_task = tokio::spawn(run_tcp(
            tcp_listener,
            self.client.clone(),
            task_shutdown.clone(),
        ));
        let mut udp_task = tokio::spawn(run_udp(udp.clone(), task_shutdown));
        let result = tokio::select! {
            _ = shutdown.changed() => {
                let _ = stop.send(true);
                let tcp_result = tcp_task
                    .await
                    .map_err(|error| ProxyError::Control(error.to_string()))
                    .and_then(|result| result);
                let _ = udp_task.await;
                let _ = maintenance.await;
                tcp_result
            },
            result = &mut tcp_task => {
                let _ = stop.send(true);
                let _ = udp_task.await;
                let _ = maintenance.await;
                result
                    .map_err(|error| ProxyError::Control(error.to_string()))
                    .and_then(|result| result)
            },
            result = &mut udp_task => {
                let _ = stop.send(true);
                let _ = tcp_task.await;
                let _ = maintenance.await;
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
    listener: BoundTcpListener,
    client: Arc<C>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    #[cfg(not(target_os = "windows"))]
    let BoundTcpListener { listener } = listener;
    #[cfg(not(target_os = "windows"))]
    {
        run_tcp_tokio(listener, client, shutdown).await;
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        windows_conditional::run_tcp_conditional(listener.listener, client, shutdown).await
    }
}

/// Accepts TCP sessions through Tokio on platforms that do not use Windows
/// conditional accept.
#[cfg(not(target_os = "windows"))]
async fn run_tcp_tokio<C: MappingClient + 'static>(
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
#[cfg(any(not(target_os = "windows"), test))]
async fn bridge_tcp<C: MappingClient + 'static>(
    accepted: TcpStream,
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
    validate_tcp_mapping(&tuple, &original)?;
    let outbound = match TcpStream::connect(original.address).await {
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
    bridge_tcp_streams(accepted, outbound, tuple, original.address).await
}

/// Validates a TCP mapping before either forwarding path obtains an outbound
/// socket. This protects the generic mapping-client interface as well as the
/// protocol client's protobuf validation.
fn validate_tcp_mapping(tuple: &Tuple, original: &OriginalDestination) -> Result<(), ProxyError> {
    if original.protocol != TCP_PROTOCOL {
        return Err(ProxyError::InvalidMapping(
            "TCP lookup returned a non-TCP mapping".into(),
        ));
    }
    if original.address.ip().is_unspecified()
        || original.address.port() == 0
        || original.address.is_ipv4() != tuple.destination.is_ipv4()
    {
        return Err(ProxyError::InvalidMapping(
            "TCP mapping destination has an invalid address, port, or family".into(),
        ));
    }
    Ok(())
}

/// Bridges a client socket and an already validated, connected outbound socket.
/// Windows conditional accept uses this entry point so the socket that caused
/// `CF_ACCEPT` is never connected a second time.
async fn bridge_tcp_streams(
    mut accepted: TcpStream,
    mut outbound: TcpStream,
    tuple: Tuple,
    original_destination: SocketAddr,
) -> Result<(), ProxyError> {
    let mut termination = TcpForwardingGuard {
        tuple: tuple.clone(),
        original_destination,
        completed: false,
    };
    tracing::info!(
        protocol = "tcp",
        synthetic_source = %tuple.source,
        synthetic_destination = %tuple.destination,
        original_destination = %original_destination,
        reason = "forwarding_started",
        "TCP forwarding started"
    );
    match io::copy_bidirectional(&mut accepted, &mut outbound).await {
        Ok((client_to_destination, destination_to_client)) => {
            tracing::info!(
                protocol = "tcp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                original_destination = %original_destination,
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
                original_destination = %original_destination,
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

/// Receives datagrams, resolves/creates associations, and relays replies.
async fn run_udp<C: MappingClient + 'static>(
    associations: Arc<UdpAssociations<C>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buffer = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            received = associations.socket.recv_from(&mut buffer) => {
                let (length, client_address) = match received {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(%error, "UDP receive failed");
                        continue;
                    }
                };
                tokio::select! {
                    _ = shutdown.changed() => break,
                    result = associations.forward(client_address, &buffer[..length]) => {
                        if let Err(error) = result {
                            associations.report_failure(&error).await;
                        }
                    }
                }
            }
        }
    }
}

/// Shared UDP association table and lifecycle coordination state.
type AssociationTable = HashMap<Tuple, Arc<UdpAssociation>>;

/// Coordinates cached UDP associations and their relay lifetimes.
struct UdpAssociations<C> {
    /// Client-facing UDP socket bound to the proxy listener.
    socket: Arc<UdpSocket>,
    /// Mapping service used to resolve each client tuple.
    client: Arc<C>,
    /// Associations keyed by client tuple.
    entries: Arc<Mutex<AssociationTable>>,
    /// Lifetime used by relay timeouts and periodic reaping.
    idle_timeout: Duration,
    /// Watch receiver used to stop relay tasks.
    shutdown: watch::Receiver<bool>,
    /// Timestamp used to rate-limit repeated forwarding warnings.
    last_failure_log: Mutex<Option<std::time::Instant>>,
}

/// One connected outbound UDP socket paired with its originating client.
struct UdpAssociation {
    /// Synthetic tuple identifying this cache entry.
    key: Tuple,
    /// Weak cache reference used when the relay expires on its own.
    entries: Weak<Mutex<AssociationTable>>,
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
    /// Wakes the relay when client-to-destination activity extends its lease.
    activity: Notify,
    /// Dataplane flow incarnation associated with this relay, when observed.
    flow_identity: Mutex<Option<(u64, u32)>>,
    /// Signals this relay to stop when the dataplane flow is deleted.
    cancel: watch::Sender<bool>,
    /// Becomes true when the relay has released its socket.
    relay_done: watch::Sender<bool>,
}

/// Extends an association lease after successful traffic in either direction.
async fn touch_association(association: &UdpAssociation) {
    *association.last_seen.lock().await = std::time::Instant::now();
    association.activity.notify_one();
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
            entries: Arc::new(Mutex::new(HashMap::new())),
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
            let old = self.entries.lock().await.remove(&tuple);
            if let Some(old) = old {
                Self::stop_association(old).await;
            }
            let replacement = self.resolve_association(&tuple, client_address).await?;
            replacement.outbound.send(payload).await?;
            touch_association(&replacement).await;
            return Ok(());
        }
        touch_association(&association).await;
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
        let (cancel, relay_shutdown) = watch::channel(false);
        let (relay_done, _) = watch::channel(false);
        let candidate = Arc::new(UdpAssociation {
            key: tuple.clone(),
            entries: Arc::downgrade(&self.entries),
            client_address,
            synthetic_source: tuple.source,
            synthetic_destination: tuple.destination,
            destination,
            created_at: std::time::Instant::now(),
            outbound,
            last_seen: Mutex::new(std::time::Instant::now()),
            activity: Notify::new(),
            flow_identity: Mutex::new(None),
            cancel,
            relay_done,
        });
        let entries = self.entries.lock().await;
        if let Some(existing) = entries.get(&tuple) {
            if existing.destination == destination {
                return Ok(existing.clone());
            }
        }
        drop(entries);
        spawn_udp_relay(
            candidate.clone(),
            self.socket.clone(),
            self.idle_timeout,
            self.shutdown.clone(),
            relay_shutdown,
            candidate.relay_done.clone(),
        );
        let mut entries = self.entries.lock().await;
        if let Some(existing) = entries.get(&tuple) {
            if existing.destination == destination {
                let existing = existing.clone();
                drop(entries);
                Self::stop_association(candidate).await;
                return Ok(existing);
            }
        }
        let source = tuple.source;
        let proxy = tuple.destination;
        let previous = entries.insert(tuple, candidate.clone());
        drop(entries);
        if let Some(previous) = previous {
            Self::stop_association(previous).await;
        }
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

    /// Cancels every association and waits for relay tasks to release sockets.
    async fn shutdown(&self) {
        let associations = {
            let mut entries = self.entries.lock().await;
            entries
                .drain()
                .map(|(_, association)| association)
                .collect::<Vec<_>>()
        };
        let count = associations.len();
        for association in associations {
            Self::stop_association(association).await;
        }
        tracing::info!(
            protocol = "udp",
            association_count = count,
            reason = "proxy_shutdown",
            "UDP associations cleared"
        );
    }

    /// Removes a locally cached association after confirmed host deletion.
    async fn invalidate(&self, tuple: &Tuple, flow_id: u64, generation: u32) {
        let association = self.entries.lock().await.get(tuple).cloned();
        let Some(association) = association else {
            return;
        };
        if *association.flow_identity.lock().await != Some((flow_id, generation)) {
            return;
        }
        let association = {
            let mut entries = self.entries.lock().await;
            entries
                .get(tuple)
                .is_some_and(|current| Arc::ptr_eq(current, &association))
                .then(|| entries.remove(tuple))
                .flatten()
        };
        if let Some(association) = association {
            Self::stop_association(association).await;
            tracing::info!(
                protocol = "udp",
                synthetic_source = %tuple.source,
                synthetic_destination = %tuple.destination,
                reason = "flow_deleted",
                "UDP association invalidated"
            );
        }
    }

    /// Records the flow incarnation currently backing a UDP association.
    async fn observe_flow(&self, tuple: &Tuple, flow_id: u64, generation: u32) {
        if let Some(association) = self.entries.lock().await.get(tuple).cloned() {
            *association.flow_identity.lock().await = Some((flow_id, generation));
        }
    }

    /// Cancels an association relay and waits until it has released its socket.
    async fn stop_association(association: Arc<UdpAssociation>) {
        let mut relay_done = association.relay_done.subscribe();
        if *relay_done.borrow() {
            return;
        }
        let _ = association.cancel.send(true);
        while !*relay_done.borrow() {
            if relay_done.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Removes an association when its relay exits and signals waiters.
async fn finish_udp_relay(association: &Arc<UdpAssociation>, relay_done: &watch::Sender<bool>) {
    if let Some(entries) = association.entries.upgrade() {
        let mut entries = entries.lock().await;
        if entries
            .get(&association.key)
            .is_some_and(|current| Arc::ptr_eq(current, association))
        {
            entries.remove(&association.key);
        }
    }
    let _ = relay_done.send(true);
}

/// Spawns the reply loop for one outbound association until timeout, I/O error,
/// or shutdown.
fn spawn_udp_relay(
    association: Arc<UdpAssociation>,
    client_socket: Arc<UdpSocket>,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
    mut cancel: watch::Receiver<bool>,
    relay_done: watch::Sender<bool>,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let deadline = *association.last_seen.lock().await + idle_timeout;
            let idle = time::sleep_until(deadline.into());
            let activity = association.activity.notified();
            tokio::pin!(idle);
            tokio::pin!(activity);
            let result = tokio::select! {
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
                    finish_udp_relay(&association, &relay_done).await;
                    return;
                },
                _ = cancel.changed() => {
                    finish_udp_relay(&association, &relay_done).await;
                    return;
                },
                _ = &mut activity => continue,
                _ = &mut idle => {
                    if std::time::Instant::now()
                        .saturating_duration_since(*association.last_seen.lock().await)
                        < idle_timeout
                    {
                        continue;
                    }
                    Err(())
                },
                result = association.outbound.recv(&mut buffer) => Ok(result),
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
                    touch_association(&association).await;
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
                Err(()) => {
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
        finish_udp_relay(&association, &relay_done).await;
    });
}

/// Returns an unspecified bind address matching the destination IP family.
fn unspecified_for(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0; 16], 0)),
    }
}

#[cfg(target_os = "windows")]
/// Windows-only conditional-accept listener, coordinator, and worker.
mod windows_conditional {
    use super::*;
    use std::{
        ffi::{c_char, c_int, c_ulong, c_void},
        io, mem,
        net::{SocketAddrV6, TcpStream as StdTcpStream},
        os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket, RawSocket},
        ptr,
        sync::{
            mpsc::{self, Receiver, SyncSender},
            Mutex as StdMutex,
        },
        thread::{self, JoinHandle},
    };
    use tokio::{net::TcpSocket, runtime::Builder, sync::mpsc as tokio_mpsc, task::JoinSet};

    /// Winsock socket handle representation.
    type Socket = usize;
    /// Windows kernel object handle representation.
    type Handle = *mut c_void;

    /// Invalid Winsock socket sentinel.
    const INVALID_SOCKET: Socket = !0;
    /// Winsock socket option level.
    const SOL_SOCKET: c_int = 0xffff;
    /// Winsock option that enables conditional accept.
    const SO_CONDITIONAL_ACCEPT: c_int = 0x3002;
    /// Winsock ioctl selecting nonblocking mode.
    const FIONBIO: c_ulong = 0x8004_667e;
    /// Winsock result indicating no immediately accepted socket.
    const WSAEWOULDBLOCK: c_int = 10035;
    /// Winsock result produced by a deferred conditional request.
    const WSATRY_AGAIN: c_int = 11002;
    /// Winsock error indicating that the pending client disconnected.
    const WSAECONNRESET: c_int = 10054;
    /// Winsock error indicating that the pending client was aborted.
    const WSAECONNABORTED: c_int = 10053;
    /// Winsock error indicating that the pending client timed out.
    const WSAETIMEDOUT: c_int = 10060;
    /// Winsock error returned when a conditional request is rejected.
    const WSAECONNREFUSED: c_int = 10061;
    /// Winsock error for a conditional request withdrawn by the client.
    const WSAEACCES: c_int = 10013;
    /// Maximum number of deferred attempts supported by the Windows
    /// conditional-accept state machine. Winsock re-invokes the callback only
    /// for the queue head while it is deferred, so accepting more than one
    /// application attempt would only advertise unsupported parallelism.
    const CONDITIONAL_ATTEMPT_CAPACITY: usize = 1;
    /// Result value for an event wait timeout.
    const WAIT_TIMEOUT: u32 = 258;
    /// Result value for a failed event wait.
    const WAIT_FAILED: u32 = u32::MAX;

    /// Condition callback result authorizing the connection.
    const CF_ACCEPT: c_int = 0;
    /// Condition callback result rejecting the connection.
    const CF_REJECT: c_int = 1;
    /// Condition callback result deferring the connection.
    const CF_DEFER: c_int = 2;

    /// Returns whether a failed `WSAAccept` can be attributed to the
    /// currently queued client rather than to the listener itself.
    fn is_conditional_client_error(error: c_int) -> bool {
        matches!(
            error,
            WSAEWOULDBLOCK
                | WSATRY_AGAIN
                | WSAECONNRESET
                | WSAECONNABORTED
                | WSAETIMEDOUT
                | WSAECONNREFUSED
                | WSAEACCES
        )
    }

    /// C representation of a Winsock address/data buffer.
    #[repr(C)]
    struct WsaBuf {
        /// Byte length of the pointed-to buffer.
        len: u32,
        /// Address of the bytes.
        buf: *mut c_char,
    }

    /// ABI of a Winsock conditional-accept callback.
    type ConditionProc = unsafe extern "system" fn(
        *mut WsaBuf,
        *mut WsaBuf,
        *mut c_void,
        *mut c_void,
        *mut WsaBuf,
        *mut WsaBuf,
        *mut u32,
        usize,
    ) -> c_int;

    #[link(name = "Ws2_32")]
    extern "system" {
        /// Configures a native Winsock socket option.
        fn setsockopt(
            socket: Socket,
            level: c_int,
            option_name: c_int,
            option_value: *const c_char,
            option_len: c_int,
        ) -> c_int;
        /// Runs conditional accept for one queued connection.
        fn WSAAccept(
            socket: Socket,
            address: *mut c_void,
            address_length: *mut c_int,
            condition: Option<ConditionProc>,
            callback_data: usize,
        ) -> Socket;
        /// Returns the last Winsock error for the calling thread.
        fn WSAGetLastError() -> c_int;
        /// Closes a native Winsock socket.
        fn closesocket(socket: Socket) -> c_int;
        /// Configures nonblocking mode on a native socket.
        fn ioctlsocket(socket: Socket, command: c_ulong, argument: *mut c_ulong) -> c_int;
    }

    #[link(name = "Kernel32")]
    extern "system" {
        /// Creates an unnamed event for cross-thread wakeups.
        fn CreateEventW(
            attributes: *const c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> Handle;
        /// Signals an event.
        fn SetEvent(event: Handle) -> i32;
        /// Clears a manual-reset event.
        fn ResetEvent(event: Handle) -> i32;
        /// Waits boundedly for an event.
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        /// Closes an owned kernel handle.
        fn CloseHandle(handle: Handle) -> i32;
    }

    /// Closes a Winsock socket unless ownership has been transferred to a
    /// standard or Tokio stream.
    struct OwnedSocket(Socket);

    unsafe impl Send for OwnedSocket {}

    impl OwnedSocket {
        /// Wraps a newly owned raw Winsock socket.
        fn new(socket: Socket) -> Self {
            Self(socket)
        }

        /// Borrows the raw socket without transferring ownership.
        fn raw(&self) -> Socket {
            self.0
        }

        /// Transfers sole raw-socket ownership to the caller.
        fn into_raw(mut self) -> Socket {
            let socket = self.0;
            self.0 = INVALID_SOCKET;
            socket
        }
    }

    impl Drop for OwnedSocket {
        /// Closes the still-owned raw socket.
        fn drop(&mut self) {
            if self.0 != INVALID_SOCKET {
                // SAFETY: this type owns the valid Winsock socket exactly once.
                unsafe {
                    let _ = closesocket(self.0);
                }
            }
        }
    }

    /// A preconnected socket that cannot be published independently from its
    /// matching accepted client socket.
    struct PreparedSocket {
        /// Connected outbound socket owned until handoff.
        socket: OwnedSocket,
        /// Validated original destination paired with the socket.
        destination: SocketAddr,
    }

    /// Fixed storage for the one attempt that Winsock can drive while its
    /// queue head is deferred.
    struct AttemptSlot {
        /// Shared identity and state.
        attempt: ConditionalAttempt,
        /// Outbound socket available only after worker success.
        prepared: Option<PreparedSocket>,
    }

    impl AttemptSlot {
        /// Creates an empty fixed-capacity conditional attempt slot.
        fn new(attempt: ConditionalAttempt) -> Self {
            Self {
                attempt,
                prepared: None,
            }
        }
    }

    /// The context owns this fixed slot, so a condition callback never
    /// allocates memory.
    type AttemptTable = Option<AttemptSlot>;

    /// Stable callback data shared with `WSAAccept`. The `Arc` is retained by
    /// both the listener task and coordinator thread until the thread joins.
    struct ConditionalContext {
        /// Bounded pending-attempt accounting.
        admissions: ConditionalAdmissions,
        /// Exact-tuple attempt registry.
        attempt: StdMutex<AttemptTable>,
        /// Bounded nonblocking callback-to-worker queue.
        request_sender: SyncSender<()>,
        /// Whether the callback may defer new work.
        accepting: AtomicBool,
        /// Number of accepted socket handoffs queued for Tokio conversion.
        handoffs: AtomicUsize,
        /// A callback-reserved handoff capacity unit, transferred only to a
        /// matching `SocketHandoff`.
        handoff_reserved: AtomicBool,
        /// Generation claimed by the callback for a successful accept.
        accepted_generation: AtomicU64,
        /// Manual-reset coordinator wake event.
        wake_event: Handle,
    }

    unsafe impl Send for ConditionalContext {}
    unsafe impl Sync for ConditionalContext {}

    impl ConditionalContext {
        /// Creates the context whose address is passed to `WSAAccept`.
        fn new(request_sender: SyncSender<()>, wake_event: Handle) -> Self {
            Self {
                admissions: ConditionalAdmissions::new(CONDITIONAL_ATTEMPT_CAPACITY),
                attempt: StdMutex::new(None),
                request_sender,
                accepting: AtomicBool::new(true),
                handoffs: AtomicUsize::new(0),
                handoff_reserved: AtomicBool::new(false),
                accepted_generation: AtomicU64::new(0),
                wake_event,
            }
        }

        /// Signals the coordinator after work or shutdown state changes.
        fn wake(&self) {
            // SAFETY: `wake_event` is created with CreateEventW and remains
            // open until this context's final Arc is dropped after join.
            unsafe {
                let _ = SetEvent(self.wake_event);
            }
        }

        /// Snapshots the fixed deferred attempt for the worker without
        /// exposing callback-owned storage across an await point.
        fn deferred_attempt(&self) -> Option<(ConditionalRequestId, std::time::Instant)> {
            let attempt = self.attempt.lock().expect("conditional attempt poisoned");
            attempt.as_ref().and_then(|slot| {
                (slot.attempt.state() == ConditionalAttemptState::Deferred)
                    .then(|| (slot.attempt.id.clone(), slot.attempt.deferred_at))
            })
        }

        /// Reads the state only if the worker result still belongs to the
        /// current fixed slot.
        fn attempt_state(&self, id: &ConditionalRequestId) -> Option<ConditionalAttemptState> {
            let attempt = self.attempt.lock().expect("conditional attempt poisoned");
            attempt
                .as_ref()
                .filter(|slot| slot.attempt.id == *id)
                .map(|slot| slot.attempt.state())
        }

        /// Stops new admissions and removes the one live attempt. Taking the
        /// attempt under the same lock used by the callback makes this store
        /// the shutdown linearization point: a later callback cannot claim a
        /// ready socket.
        fn stop_and_reject_pending(&self) {
            let slot = {
                let mut attempt = self.attempt.lock().expect("conditional attempt poisoned");
                self.accepting.store(false, Ordering::Release);
                attempt.take()
            };
            if let Some(slot) = slot {
                slot.attempt
                    .state
                    .store(ConditionalAttemptState::Cancelled as u8, Ordering::Release);
                self.admissions.release(&slot.attempt);
            }
            self.release_handoff_reservation();
            self.wake();
        }

        /// Reserves one bounded handoff slot before conditional acceptance.
        fn reserve_handoff(&self) -> bool {
            let mut current = self.handoffs.load(Ordering::Acquire);
            loop {
                if current >= self.admissions.limit {
                    return false;
                }
                match self.handoffs.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        self.handoff_reserved.store(true, Ordering::Release);
                        return true;
                    }
                    Err(observed) => current = observed,
                }
            }
        }

        /// Releases a queued handoff slot exactly once after conversion or
        /// rejection.
        fn release_handoff(&self) {
            self.handoffs.fetch_sub(1, Ordering::AcqRel);
        }

        /// Releases a callback reservation only when it was not transferred
        /// into a handoff owner.
        fn release_handoff_reservation(&self) {
            if self.handoff_reserved.swap(false, Ordering::AcqRel) {
                self.release_handoff();
            }
        }

        /// Releases the fixed attempt and every related reservation. The
        /// caller must have removed it from `attempt`.
        fn reject_and_release(&self, slot: AttemptSlot, state: ConditionalAttemptState) {
            slot.attempt.state.store(state as u8, Ordering::Release);
            self.release_handoff_reservation();
            self.admissions.release(&slot.attempt);
        }

        /// Removes the sole currently claimed generation after `WSAAccept`
        /// fails after its callback returned `CF_ACCEPT`.
        fn reject_claimed_generation(&self, generation: u64) {
            let removed = {
                let mut attempt = self.attempt.lock().expect("conditional attempt poisoned");
                attempt
                    .as_ref()
                    .is_some_and(|slot| {
                        slot.attempt.id.generation == generation
                            && slot.attempt.state() == ConditionalAttemptState::Claimed
                    })
                    .then(|| attempt.take())
                    .flatten()
            };
            if let Some(slot) = removed {
                self.reject_and_release(slot, ConditionalAttemptState::Rejected);
            }
        }

        /// Removes the queue-head attempt after Winsock reports that its
        /// conditional client was lost before acceptance.
        fn reject_active_attempt(&self) {
            let slot = self
                .attempt
                .lock()
                .expect("conditional attempt poisoned")
                .take();
            if let Some(slot) = slot {
                self.reject_and_release(slot, ConditionalAttemptState::Rejected);
            }
        }

        /// Removes a slot that the callback marked terminal without dropping
        /// its prepared socket from inside the callback.
        fn reject_terminal_attempt(&self) {
            let terminal = {
                let attempt = self.attempt.lock().expect("conditional attempt poisoned");
                attempt.as_ref().is_some_and(|slot| {
                    matches!(
                        slot.attempt.state(),
                        ConditionalAttemptState::Rejected | ConditionalAttemptState::Cancelled
                    )
                })
            };
            if terminal {
                self.reject_active_attempt();
            }
        }
    }

    impl Drop for ConditionalContext {
        /// Releases the coordinator event after every callback is impossible.
        fn drop(&mut self) {
            // SAFETY: no callback can still use this context because the
            // coordinator's Arc is dropped only after its thread has stopped.
            unsafe {
                let _ = CloseHandle(self.wake_event);
            }
        }
    }

    /// Owns the native listening socket and the callback context until
    /// `run_tcp_conditional` joins the coordinator.
    pub(super) struct ConditionalListener {
        /// Native socket owned by the coordinator thread.
        socket: OwnedSocket,
        /// Address selected before Tokio ownership conversion.
        local_addr: SocketAddr,
        /// Stable callback state retained through coordinator join.
        context: Arc<ConditionalContext>,
        /// Deferred callback requests consumed by the worker.
        request_receiver: Receiver<()>,
    }

    impl ConditionalListener {
        /// Binds and configures a TCP socket for conditional accept before
        /// native `listen`, then transfers it to the coordinator.
        pub(super) fn bind(local_addr: SocketAddr, backlog: u32) -> Result<Self, ProxyError> {
            let socket = match local_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };
            socket.bind(local_addr)?;
            // SAFETY: the event is an unnamed, manual-reset event owned by the
            // context and used only to wake its coordinator thread.
            let wake_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
            if wake_event.is_null() {
                return Err(ProxyError::Io(io::Error::last_os_error()));
            }
            // Native backlog is deliberately independent from the fixed
            // callback/worker capacity, so a valid i32::MAX backlog cannot
            // allocate an application-sized channel at startup.
            let (request_sender, request_receiver) =
                mpsc::sync_channel(CONDITIONAL_ATTEMPT_CAPACITY);
            let context = Arc::new(ConditionalContext::new(request_sender, wake_event));
            let enabled: c_int = 1;
            // SAFETY: `TcpSocket` owns a bound but not-yet-listening socket.
            // The option points to `enabled` only for this synchronous call.
            if unsafe {
                setsockopt(
                    socket.as_raw_socket() as Socket,
                    SOL_SOCKET,
                    SO_CONDITIONAL_ACCEPT,
                    (&enabled as *const c_int).cast::<c_char>(),
                    mem::size_of_val(&enabled) as c_int,
                )
            } != 0
            {
                return Err(last_socket_error("enable SO_CONDITIONAL_ACCEPT"));
            }
            let listener = socket.listen(backlog)?;
            let local_addr = listener.local_addr()?;
            let listener = listener.into_std()?;
            listener.set_nonblocking(true)?;
            let socket = OwnedSocket::new(listener.into_raw_socket() as Socket);
            Ok(Self {
                socket,
                local_addr,
                context,
                request_receiver,
            })
        }

        /// Returns the address selected before raw socket ownership transfer.
        pub(super) fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }
    }

    /// Result sent from the preconnect worker to the coordinator. A stale
    /// result owns its socket until the coordinator drops it.
    enum WorkerResult {
        /// Mapping and connect succeeded with a paired outbound socket.
        Ready {
            id: ConditionalRequestId,
            prepared: PreparedSocket,
        },
        /// Lookup, validation, connect, timeout, or cancellation failed.
        Rejected {
            id: ConditionalRequestId,
            error: ProxyError,
        },
    }

    /// A raw client/preconnected pair that has not yet been converted into
    /// Tokio streams. Dropping it closes both raw sockets.
    struct SocketHandoff {
        /// Raw client socket returned by the matching `WSAAccept`.
        client: OwnedSocket,
        /// Matching validated and preconnected outbound socket.
        outbound: PreparedSocket,
        /// Exact tuple bound to both raw sockets.
        tuple: Tuple,
        /// Releases the callback capacity reservation when conversion fails,
        /// the handoff queue is full, or conversion succeeds.
        _reservation: HandoffReservation,
    }

    /// RAII ownership of one callback handoff reservation.
    struct HandoffReservation {
        /// Context whose counter was incremented by the callback.
        context: Arc<ConditionalContext>,
    }

    impl Drop for HandoffReservation {
        /// Releases the reservation if the handoff was not consumed.
        fn drop(&mut self) {
            self.context.release_handoff();
        }
    }

    /// Starts a worker with a private current-thread runtime. It never calls
    /// `Handle::block_on`, so it cannot nest a runtime on Tokio's worker
    /// threads.
    fn spawn_preconnect_worker<C: MappingClient + 'static>(
        client: Arc<C>,
        context: Arc<ConditionalContext>,
        receiver: Receiver<()>,
        sender: mpsc::Sender<WorkerResult>,
    ) -> Result<JoinHandle<Result<(), ProxyError>>, ProxyError> {
        thread::Builder::new()
            .name("ssp-preconnect".into())
            .spawn(move || {
                let panic_context = context.clone();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_preconnect_worker(client, context, receiver, sender)
                })) {
                    Ok(result) => result,
                    Err(_) => {
                        panic_context.stop_and_reject_pending();
                        Err(ProxyError::Control(
                            "conditional preconnect worker thread panicked".into(),
                        ))
                    }
                }
            })
            .map_err(ProxyError::Io)
    }

    /// Runs the preconnect worker and reports runtime construction failures to
    /// the async proxy owner instead of treating them as clean shutdown.
    fn run_preconnect_worker<C: MappingClient + 'static>(
        client: Arc<C>,
        context: Arc<ConditionalContext>,
        receiver: Receiver<()>,
        sender: mpsc::Sender<WorkerResult>,
    ) -> Result<(), ProxyError> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                context.stop_and_reject_pending();
                ProxyError::Control(format!(
                    "conditional preconnect runtime initialization failed: {error}"
                ))
            })?;
        while context.accepting.load(Ordering::Acquire) {
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(()) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            let Some((id, deferred_at)) = context.deferred_attempt() else {
                continue;
            };
            if context.attempt_state(&id) != Some(ConditionalAttemptState::Deferred) {
                continue;
            }
            let result = runtime.block_on(preconnect_attempt(
                client.clone(),
                context.clone(),
                id.clone(),
                deferred_at,
            ));
            let result = match result {
                Ok(prepared) => WorkerResult::Ready { id, prepared },
                Err(error) => WorkerResult::Rejected { id, error },
            };
            if sender.send(result).is_err() {
                break;
            }
            context.wake();
        }
        Ok(())
    }

    /// Performs the asynchronous mapping lookup and TCP connect entirely
    /// outside the condition callback, bounded from the first `CF_DEFER`.
    async fn preconnect_attempt<C: MappingClient + 'static>(
        client: Arc<C>,
        context: Arc<ConditionalContext>,
        id: ConditionalRequestId,
        deferred_at: std::time::Instant,
    ) -> Result<PreparedSocket, ProxyError> {
        let remaining = conditional_preconnect_budget(deferred_at)?;
        let work = async {
            let mapping = client.get_mapping(&id.tuple).await?;
            validate_tcp_mapping(&id.tuple, &mapping)?;
            let outbound = TcpStream::connect(mapping.address).await?;
            let outbound = outbound.into_std()?;
            outbound.set_nonblocking(true)?;
            Ok(PreparedSocket {
                // SAFETY: `into_raw_socket` transfers sole ownership from the
                // standard stream to the RAII socket wrapper.
                socket: OwnedSocket::new(outbound.into_raw_socket() as Socket),
                destination: mapping.address,
            })
        };
        tokio::select! {
            result = time::timeout(remaining, work) => {
                result
                    .map_err(|_| ProxyError::Control("conditional preconnect timed out".into()))?
            }
            _ = wait_for_attempt_cancellation(context, id.clone()) => Err(ProxyError::Control(
                "conditional preconnect cancelled".into(),
            )),
        }
    }

    /// Polls an atomic state rather than blocking the dedicated worker while
    /// shutdown changes the request lifecycle.
    async fn wait_for_attempt_cancellation(
        context: Arc<ConditionalContext>,
        id: ConditionalRequestId,
    ) {
        while context.attempt_state(&id) == Some(ConditionalAttemptState::Deferred) {
            time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Publishes only a current deferred worker completion into its slot.
    fn apply_worker_result(context: &ConditionalContext, result: WorkerResult) {
        let (id, result) = match result {
            WorkerResult::Ready { id, prepared } => (id, Ok(prepared)),
            WorkerResult::Rejected { id, error } => (id, Err(error)),
        };
        let mut attempt = context
            .attempt
            .lock()
            .expect("conditional attempt poisoned");
        let Some(slot) = attempt.as_mut().filter(|slot| slot.attempt.id == id) else {
            return;
        };
        if slot.attempt.state() != ConditionalAttemptState::Deferred {
            return;
        }
        match result {
            Ok(prepared) => {
                slot.prepared = Some(prepared);
                if !mark_attempt_ready(&slot.attempt) {
                    let _ = slot.prepared.take();
                }
            }
            Err(error) => {
                tracing::warn!(
                    protocol = "tcp",
                    synthetic_source = %id.tuple.source,
                    synthetic_destination = %id.tuple.destination,
                    error = %error,
                    "conditional TCP mapping lookup or preconnect failed"
                );
                slot.attempt
                    .state
                    .store(ConditionalAttemptState::Rejected as u8, Ordering::Release);
            }
        }
    }

    /// Removes a claimed slot and extracts its paired raw socket owners.
    fn take_handoff(
        context: &Arc<ConditionalContext>,
        generation: u64,
        client: OwnedSocket,
    ) -> Option<SocketHandoff> {
        let slot = {
            let mut attempt = context
                .attempt
                .lock()
                .expect("conditional attempts poisoned");
            attempt
                .as_ref()
                .is_some_and(|slot| {
                    slot.attempt.id.generation == generation
                        && slot.attempt.state() == ConditionalAttemptState::Claimed
                })
                .then(|| attempt.take())
                .flatten()
        }?;
        let tuple = slot.attempt.id.tuple.clone();
        let attempt = slot.attempt;
        let outbound = match slot.prepared {
            Some(outbound) => outbound,
            None => {
                context.release_handoff_reservation();
                context.admissions.release(&attempt);
                return None;
            }
        };
        context.admissions.release(&attempt);
        if !context.handoff_reserved.swap(false, Ordering::AcqRel) {
            return None;
        }
        Some(SocketHandoff {
            client,
            outbound,
            tuple,
            _reservation: HandoffReservation {
                context: context.clone(),
            },
        })
    }

    /// Drives nonblocking `WSAAccept` on its own native thread. The event
    /// wakes it promptly for worker completions and shutdown; the bounded
    /// polling interval also services incoming connection attempts.
    fn run_coordinator(
        socket: OwnedSocket,
        context: Arc<ConditionalContext>,
        result_receiver: Receiver<WorkerResult>,
        handoff_sender: tokio_mpsc::Sender<SocketHandoff>,
    ) -> Result<(), ProxyError> {
        while context.accepting.load(Ordering::Acquire) {
            while let Ok(result) = result_receiver.try_recv() {
                apply_worker_result(&context, result);
            }
            context.accepted_generation.store(0, Ordering::Release);
            // SAFETY: `socket` remains owned by this thread; the callback
            // pointer targets the context Arc retained for the entire loop.
            let accepted = unsafe {
                WSAAccept(
                    socket.raw(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    Some(condition_callback),
                    Arc::as_ptr(&context) as usize,
                )
            };
            if accepted != INVALID_SOCKET {
                let client = OwnedSocket::new(accepted);
                let generation = context.accepted_generation.load(Ordering::Acquire);
                if generation == 0 {
                    tracing::error!("WSAAccept returned a socket without a conditional request");
                } else if let Some(handoff) = take_handoff(&context, generation, client) {
                    if let Err(error) = set_nonblocking(handoff.client.raw()) {
                        tracing::warn!(%error, "conditional accepted socket setup failed");
                    } else {
                        match handoff_sender.try_send(handoff) {
                            Ok(()) => {}
                            Err(tokio_mpsc::error::TrySendError::Full(handoff)) => {
                                drop(handoff);
                                tracing::warn!("conditional TCP handoff capacity exhausted");
                            }
                            Err(tokio_mpsc::error::TrySendError::Closed(handoff)) => {
                                drop(handoff);
                                break;
                            }
                        }
                    }
                } else {
                    context.reject_claimed_generation(generation);
                    tracing::error!(
                        generation,
                        "conditional accepted socket had no matching outbound socket"
                    );
                }
            } else {
                // A deferred or rejected conditional request normally makes
                // WSAAccept fail with one of these transient values.
                let error = unsafe { WSAGetLastError() };
                let generation = context.accepted_generation.load(Ordering::Acquire);
                if generation != 0 {
                    context.reject_claimed_generation(generation);
                } else if error != WSAEWOULDBLOCK && error != WSATRY_AGAIN {
                    context.reject_active_attempt();
                }
                context.reject_terminal_attempt();
                if !is_conditional_client_error(error) {
                    context.stop_and_reject_pending();
                    return Err(socket_error("WSAAccept", error));
                }
                if error != WSAEWOULDBLOCK && error != WSATRY_AGAIN {
                    tracing::debug!(
                        error,
                        "WSAAccept rejected or lost a conditional client request"
                    );
                }
            }
            // SAFETY: the manual-reset event belongs to the still-live
            // context. Resetting after each bounded wait is safe because the
            // next iteration also polls both queues.
            unsafe {
                let result = WaitForSingleObject(context.wake_event, 10);
                if result == WAIT_FAILED {
                    let error = io::Error::last_os_error();
                    context.stop_and_reject_pending();
                    return Err(ProxyError::Io(error));
                }
                if result != WAIT_TIMEOUT && ResetEvent(context.wake_event) == 0 {
                    let error = io::Error::last_os_error();
                    context.stop_and_reject_pending();
                    return Err(ProxyError::Io(error));
                }
            }
        }
        context.stop_and_reject_pending();
        Ok(())
    }

    /// Resolves both layers of a Tokio blocking task that joins a native
    /// thread. A native error or panic is a proxy failure, not a log-only
    /// shutdown observation.
    async fn join_native_thread(
        name: &str,
        task: tokio::task::JoinHandle<std::thread::Result<Result<(), ProxyError>>>,
    ) -> Result<(), ProxyError> {
        match task.await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ProxyError::Control(format!(
                "conditional {name} thread panicked"
            ))),
            Err(error) => Err(ProxyError::Control(format!(
                "conditional {name} join task failed: {error}"
            ))),
        }
    }

    /// Receives native handoffs, converts each pair atomically into Tokio
    /// streams, and joins all bridge tasks before returning to `run_bound`.
    pub(super) async fn run_tcp_conditional<C: MappingClient + 'static>(
        listener: ConditionalListener,
        client: Arc<C>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ProxyError> {
        let ConditionalListener {
            socket,
            context,
            request_receiver,
            ..
        } = listener;
        let (worker_result_sender, worker_result_receiver) = mpsc::channel();
        let worker = spawn_preconnect_worker(
            client,
            context.clone(),
            request_receiver,
            worker_result_sender,
        )?;
        let (handoff_sender, mut handoff_receiver) = tokio_mpsc::channel(context.admissions.limit);
        let coordinator_context = context.clone();
        let coordinator = match thread::Builder::new()
            .name("ssp-conditional-accept".into())
            .spawn(move || {
                let panic_context = coordinator_context.clone();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_coordinator(
                        socket,
                        coordinator_context,
                        worker_result_receiver,
                        handoff_sender,
                    )
                })) {
                    Ok(result) => result,
                    Err(_) => {
                        panic_context.stop_and_reject_pending();
                        Err(ProxyError::Control(
                            "conditional coordinator thread panicked".into(),
                        ))
                    }
                }
            }) {
            Ok(coordinator) => coordinator,
            Err(error) => {
                context.stop_and_reject_pending();
                let worker = tokio::task::spawn_blocking(move || worker.join());
                let startup = ProxyError::Io(error);
                if let Err(cleanup_error) = join_native_thread("preconnect worker", worker).await {
                    return Err(ProxyError::Control(format!(
                        "{startup}; worker cleanup after coordinator startup failure failed: {cleanup_error}"
                    )));
                }
                return Err(startup);
            }
        };
        let coordinator = tokio::task::spawn_blocking(move || coordinator.join());
        let worker = tokio::task::spawn_blocking(move || worker.join());
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                handoff = handoff_receiver.recv() => {
                    let Some(handoff) = handoff else {
                        break;
                    };
                    match handoff.into_tokio() {
                        Ok((accepted, outbound, tuple, destination)) => {
                            sessions.spawn(async move {
                                if let Err(error) = bridge_tcp_streams(
                                    accepted,
                                    outbound,
                                    tuple,
                                    destination,
                                ).await {
                                    tracing::warn!(%error, "conditional TCP forwarding session failed");
                                }
                            });
                        }
                        Err(error) => tracing::warn!(%error, "conditional TCP socket handoff failed"),
                    }
                }
                Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
        context.stop_and_reject_pending();
        // Closing the receiver drops every unconverted handoff and its
        // reservation before waiting for the native workers to finish.
        drop(handoff_receiver);
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
        let coordinator_result = join_native_thread("coordinator", coordinator).await;
        let worker_result = join_native_thread("preconnect worker", worker).await;
        coordinator_result?;
        worker_result
    }

    impl SocketHandoff {
        /// Converts the raw pair into Tokio streams before bridge publication.
        fn into_tokio(self) -> Result<(TcpStream, TcpStream, Tuple, SocketAddr), ProxyError> {
            let tuple = self.tuple;
            let destination = self.outbound.destination;
            // SAFETY: each OwnedSocket transfers sole ownership exactly once
            // into its corresponding standard stream; failures drop both
            // streams before a bridge can be published.
            let accepted =
                unsafe { StdTcpStream::from_raw_socket(self.client.into_raw() as RawSocket) };
            // SAFETY: see the ownership explanation above for the paired
            // preconnected outbound socket.
            let outbound = unsafe {
                StdTcpStream::from_raw_socket(self.outbound.socket.into_raw() as RawSocket)
            };
            accepted.set_nonblocking(true)?;
            outbound.set_nonblocking(true)?;
            Ok((
                TcpStream::from_std(accepted)?,
                TcpStream::from_std(outbound)?,
                tuple,
                destination,
            ))
        }
    }

    /// The condition callback only performs address decoding, bounded atomic
    /// admission, a nonblocking queue operation, and event signalling. It
    /// deliberately performs no Winsock, RPC, blocking, or re-entrant work.
    unsafe extern "system" fn condition_callback(
        caller_id: *mut WsaBuf,
        _caller_data: *mut WsaBuf,
        _caller_qos: *mut c_void,
        _callee_qos: *mut c_void,
        callee_id: *mut WsaBuf,
        _callee_data: *mut WsaBuf,
        _group: *mut u32,
        callback_data: usize,
    ) -> c_int {
        // SAFETY: WSAAccept supplies the same pointer passed as callback data;
        // the coordinator retains an Arc for all possible callback invocations.
        let context = unsafe { &*(callback_data as *const ConditionalContext) };
        let Some(source) = (unsafe { socket_addr_from_wsa_buf(caller_id) }) else {
            return CF_REJECT;
        };
        let Some(destination) = (unsafe { socket_addr_from_wsa_buf(callee_id) }) else {
            return CF_REJECT;
        };
        if source.is_ipv4() != destination.is_ipv4() {
            return CF_REJECT;
        }
        let tuple = Tuple {
            source,
            destination,
            protocol: TCP_PROTOCOL,
        };
        // `try_lock` is essential here: a contended coordinator table is a
        // resource failure, not a reason for callback blocking.
        let Ok(mut attempt) = context.attempt.try_lock() else {
            return CF_REJECT;
        };
        if let Some(slot) = attempt.as_ref() {
            if slot.attempt.id.tuple != tuple {
                return CF_REJECT;
            }
            if !context.accepting.load(Ordering::Acquire) {
                slot.attempt
                    .state
                    .store(ConditionalAttemptState::Cancelled as u8, Ordering::Release);
                return CF_REJECT;
            }
            match slot.attempt.state() {
                ConditionalAttemptState::Deferred => return CF_DEFER,
                ConditionalAttemptState::Ready => {
                    if !context.reserve_handoff() {
                        slot.attempt
                            .state
                            .store(ConditionalAttemptState::Rejected as u8, Ordering::Release);
                        return CF_REJECT;
                    }
                    if claim_ready_attempt(&slot.attempt) {
                        context
                            .accepted_generation
                            .store(slot.attempt.id.generation, Ordering::Release);
                        return CF_ACCEPT;
                    }
                    context.release_handoff_reservation();
                    slot.attempt
                        .state
                        .store(ConditionalAttemptState::Rejected as u8, Ordering::Release);
                    return CF_REJECT;
                }
                ConditionalAttemptState::Claimed => return CF_REJECT,
                ConditionalAttemptState::Rejected | ConditionalAttemptState::Cancelled => {
                    return CF_REJECT
                }
            }
        }
        if !context.accepting.load(Ordering::Acquire) {
            return CF_REJECT;
        }
        let Some(reservation) = context.admissions.reserve(tuple) else {
            return CF_REJECT;
        };
        // `try_send` is bounded and nonblocking. The fixed slot is installed
        // before the worker can observe the queue, so the callback performs
        // no heap allocation.
        *attempt = Some(AttemptSlot::new(reservation));
        if context.request_sender.try_send(()).is_err() {
            let removed = attempt.take().expect("installed conditional attempt");
            drop(attempt);
            context.reject_and_release(removed, ConditionalAttemptState::Rejected);
            return CF_REJECT;
        }
        drop(attempt);
        context.wake();
        CF_DEFER
    }

    /// Decodes the callback's sockaddr bytes without invoking Winsock.
    unsafe fn socket_addr_from_wsa_buf(buffer: *mut WsaBuf) -> Option<SocketAddr> {
        if buffer.is_null() || unsafe { (*buffer).buf.is_null() } {
            return None;
        }
        let buffer = unsafe { &*buffer };
        let bytes =
            unsafe { std::slice::from_raw_parts(buffer.buf.cast::<u8>(), buffer.len as usize) };
        if bytes.len() < 2 {
            return None;
        }
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        let port = bytes
            .get(2..4)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))?;
        match family {
            2 if bytes.len() >= 16 => Some(SocketAddr::from((
                std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
                port,
            ))),
            23 if bytes.len() >= 28 => {
                let address = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?);
                let scope_id = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    address, port, 0, scope_id,
                )))
            }
            _ => None,
        }
    }

    /// Sets nonblocking mode before Tokio takes ownership of a raw socket.
    fn set_nonblocking(socket: Socket) -> Result<(), ProxyError> {
        let mut enabled: c_ulong = 1;
        // SAFETY: socket ownership remains with the caller and `enabled`
        // points to writable storage for this synchronous ioctl.
        if unsafe { ioctlsocket(socket, FIONBIO, &mut enabled) } != 0 {
            return Err(last_socket_error("set accepted socket nonblocking"));
        }
        Ok(())
    }

    /// Converts the calling thread's Winsock error into a typed proxy error.
    fn last_socket_error(operation: &str) -> ProxyError {
        // SAFETY: this is called immediately after a Winsock operation on the
        // same thread, before another Winsock call can overwrite its status.
        socket_error(operation, unsafe { WSAGetLastError() })
    }

    /// Converts a saved Winsock error code without querying thread-local
    /// error state after cleanup may have overwritten it.
    fn socket_error(operation: &str, error: c_int) -> ProxyError {
        ProxyError::Io(io::Error::new(
            io::Error::from_raw_os_error(error).kind(),
            format!("{operation}: {}", io::Error::from_raw_os_error(error)),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{SocketAddrV4, TcpListener};

        fn loopback_sockaddr(address: SocketAddr) -> [u8; 16] {
            let SocketAddr::V4(address) = address else {
                panic!("test requires an IPv4 loopback address");
            };
            let mut bytes = [0_u8; 16];
            bytes[..2].copy_from_slice(&2_u16.to_ne_bytes());
            bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&address.ip().octets());
            bytes
        }

        #[test]
        fn ready_attempt_with_exhausted_handoff_is_released_by_coordinator() {
            let listener = TcpListener::bind(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("bind loopback listener");
            let destination = listener.local_addr().expect("read listener address");
            let outbound = StdTcpStream::connect(destination).expect("connect loopback socket");
            let (request_sender, _request_receiver) = mpsc::sync_channel(1);
            // SAFETY: this test creates and owns the event until `context` drops.
            let wake_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
            assert!(!wake_event.is_null(), "create wake event");
            let context = Arc::new(ConditionalContext::new(request_sender, wake_event));
            let tuple = Tuple {
                source: "127.0.0.1:42019".parse().expect("parse source"),
                destination,
                protocol: TCP_PROTOCOL,
            };
            let attempt = context
                .admissions
                .reserve(tuple.clone())
                .expect("reserve conditional attempt");
            assert!(mark_attempt_ready(&attempt));
            *context.attempt.lock().expect("conditional attempt lock") = Some(AttemptSlot {
                attempt,
                prepared: Some(PreparedSocket {
                    socket: OwnedSocket::new(outbound.into_raw_socket() as Socket),
                    destination,
                }),
            });
            context.handoffs.store(1, Ordering::Release);
            assert!(
                !context.handoff_reserved.load(Ordering::Acquire),
                "model an already queued handoff owner"
            );

            let mut caller = loopback_sockaddr(tuple.source);
            let mut callee = loopback_sockaddr(tuple.destination);
            let mut caller_id = WsaBuf {
                len: caller.len() as u32,
                buf: caller.as_mut_ptr().cast(),
            };
            let mut callee_id = WsaBuf {
                len: callee.len() as u32,
                buf: callee.as_mut_ptr().cast(),
            };
            // SAFETY: the address buffers have the sockaddr layout decoded by
            // `socket_addr_from_wsa_buf`, and `context` remains alive throughout.
            let result = unsafe {
                condition_callback(
                    &mut caller_id,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut callee_id,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    Arc::as_ptr(&context) as usize,
                )
            };

            assert_eq!(result, CF_REJECT);
            {
                let attempt = context.attempt.lock().expect("conditional attempt lock");
                let slot = attempt.as_ref().expect("callback must retain the slot");
                assert_eq!(slot.attempt.state(), ConditionalAttemptState::Rejected);
                assert!(
                    slot.prepared.is_some(),
                    "callback must not drop the prepared socket"
                );
            }

            context.reject_terminal_attempt();

            assert!(context
                .attempt
                .lock()
                .expect("conditional attempt lock")
                .is_none());
            assert_eq!(context.admissions.pending(), 0);
            assert_eq!(context.handoffs.load(Ordering::Acquire), 1);
            assert!(!context.handoff_reserved.load(Ordering::Acquire));
            context.release_handoff();
            assert_eq!(context.handoffs.load(Ordering::Acquire), 0);
        }

        #[test]
        fn saved_winsock_error_conversion_uses_saved_code() {
            let ProxyError::Io(error) = socket_error("saved WSAAccept", WSAECONNREFUSED) else {
                panic!("saved Winsock error must be an I/O error");
            };
            assert_eq!(
                error.kind(),
                io::Error::from_raw_os_error(WSAECONNREFUSED).kind()
            );
            assert!(error.to_string().starts_with("saved WSAAccept: "));
        }
    }
}

#[cfg(all(target_os = "windows", feature = "tls-rustls"))]
mod rustls_client;

#[cfg(all(target_os = "windows", feature = "tls-rustls"))]
pub use rustls_client::TlsRustlsMappingClient;

#[cfg(not(all(target_os = "windows", feature = "tls-rustls")))]
#[derive(Clone)]
/// Placeholder client that reports rustls support is unavailable on this
/// build.
pub struct TlsRustlsMappingClient;

#[cfg(not(all(target_os = "windows", feature = "tls-rustls")))]
impl TlsRustlsMappingClient {
    /// Always returns `UnsupportedPlatform` when the Windows rustls client is
    /// absent.
    pub async fn connect(
        _endpoint: &str,
        _certificate_file: &std::path::Path,
        _key_file: &std::path::Path,
        _peer_cert_sha256: &str,
    ) -> Result<Self, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }

    /// Reports that BPF activation is unavailable without the Windows rustls
    /// client.
    pub async fn activate(
        &self,
        _elf_path: &str,
        _interface: &str,
        _proxy: SocketAddr,
    ) -> Result<(), ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }

    /// Reports that BPF detachment is unavailable without the Windows rustls
    /// client.
    pub async fn detach(&self, _interface: &str) -> Result<(), ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }
}

#[cfg(not(all(target_os = "windows", feature = "tls-rustls")))]
#[async_trait]
impl MappingClient for TlsRustlsMappingClient {
    /// Always returns `UnsupportedPlatform` when the Windows rustls client is
    /// absent.
    async fn get_mapping(&self, _tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }
}

#[cfg(not(all(target_os = "windows", feature = "tls-rustls")))]
#[async_trait]
impl FlowClient for TlsRustlsMappingClient {
    /// Reports that typed flow operations are unavailable without the Windows
    /// rustls client.
    async fn enumerate_flows(
        &self,
        _page_token: Vec<u8>,
        _limit: u32,
    ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
    }

    /// Reports that typed flow operations are unavailable without the Windows
    /// rustls client.
    async fn delete_flow(
        &self,
        _flow_id: u64,
        _generation: u32,
        _observed_last_used_ns: u64,
    ) -> Result<FlowDeleteReport, ProxyError> {
        Err(ProxyError::UnsupportedPlatform)
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
        _observed_last_used_ns: u64,
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

    /// Adds a gRPC deadline and enforces the same deadline locally.
    async fn bounded_rpc<T>(
        operation: impl Future<Output = Result<T, tonic::Status>>,
    ) -> Result<T, ProxyError> {
        time::timeout(CONTROL_RPC_TIMEOUT, operation)
            .await
            .map_err(|_| ProxyError::Control("control RPC timed out".into()))?
            .map_err(|error| ProxyError::Control(error.to_string()))
    }

    /// Builds a tonic request carrying the server-visible deadline.
    fn rpc_request<T>(message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        request.set_timeout(CONTROL_RPC_TIMEOUT);
        request
    }

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
            let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
                .await
                .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
            let attached = bounded_rpc(client.attach(rpc_request(proto::InterfaceRequest {
                elf_path: elf_path.into(),
                interfaces: vec![interface.into()],
            })))
            .await?
            .into_inner();
            if !attached.success {
                return Err(ProxyError::Control(attached.message));
            }
            let configured = async {
                let mut config = bounded_rpc(client.get_config(rpc_request(proto::Empty {})))
                    .await?
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
                bounded_rpc(client.set_config(rpc_request(proto::SetConfigRequest {
                    config: Some(config),
                })))
                .await?;
                Ok(())
            }
            .await;
            if let Err(error) = configured {
                let rollback = bounded_rpc(client.detach(rpc_request(proto::DetachRequest {
                    interfaces: vec![interface.into()],
                    all: false,
                })))
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
            let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
                .await
                .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
            bounded_rpc(client.detach(rpc_request(proto::DetachRequest {
                interfaces: vec![interface.into()],
                all: false,
            })))
            .await?;
            Ok(())
        }

        /// Enumerates one bounded page of typed flow records.
        pub async fn enumerate_flows(
            &self,
            page_token: Vec<u8>,
            limit: u32,
        ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
            let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
                .await
                .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
            let reply = bounded_rpc(client.enumerate_flows(rpc_request(
                proto::EnumerateFlowsRequest { limit, page_token },
            )))
            .await?
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
                    fin_seen_mask: flow.fin_seen_mask,
                    fin_ack_seen_mask: flow.fin_ack_seen_mask,
                });
            }
            Ok((flows, reply.next_page_token))
        }

        /// Deletes one generation-checked flow and converts its typed outcome.
        pub async fn delete_flow(
            &self,
            flow_id: u64,
            generation: u32,
            observed_last_used_ns: u64,
        ) -> Result<FlowDeleteReport, ProxyError> {
            let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
                .await
                .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
            let reply = bounded_rpc(client.delete_flow(rpc_request(proto::DeleteFlowRequest {
                flow_id,
                generation,
                observed_last_used_ns,
            })))
            .await?
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
                proto::delete_flow_reply::Outcome::ObservationMismatch => {
                    FlowDeleteOutcome::ObservationMismatch
                }
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
            let mut client = time::timeout(CONTROL_RPC_TIMEOUT, self.client.lock())
                .await
                .map_err(|_| ProxyError::Control("control client lock timed out".into()))?;
            let mapping = time::timeout(
                CONTROL_RPC_TIMEOUT,
                client.get_mapping(rpc_request(request)),
            )
            .await
            .map_err(|_| ProxyError::Control("control RPC timed out".into()))?
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
            observed_last_used_ns: u64,
        ) -> Result<FlowDeleteReport, ProxyError> {
            self.delete_flow(flow_id, generation, observed_last_used_ns)
                .await
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
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex as StdMutex,
        },
    };
    use tracing::{field::Visit, Event, Subscriber};
    use tracing_subscriber::{
        layer::{Context, Layer},
        prelude::*,
        registry::LookupSpan,
    };

    #[cfg(target_os = "windows")]
    static WINDOWS_CONDITIONAL_TEST_LOCK: Mutex<()> = Mutex::const_new(());

    #[derive(Clone, Default)]
    struct EventRecorder {
        reasons: Arc<StdMutex<Vec<String>>>,
    }

    struct FieldVisitor {
        reasons: Vec<String>,
    }

    impl FieldVisitor {
        fn new() -> Self {
            Self {
                reasons: Vec::new(),
            }
        }
    }

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "reason" {
                self.reasons.push(format!("{value:?}"));
            }
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "reason" {
                self.reasons.push(value.to_owned());
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
    }

    #[derive(Clone)]
    struct MockClient {
        destination: SocketAddr,
        protocol: u8,
    }

    #[cfg(target_os = "windows")]
    #[derive(Clone)]
    struct RecordingClient {
        destination: SocketAddr,
        tuples: Arc<StdMutex<Vec<Tuple>>>,
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
            _observed_last_used_ns: u64,
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

    #[cfg(target_os = "windows")]
    #[async_trait]
    impl MappingClient for RecordingClient {
        async fn get_mapping(&self, tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            self.tuples.lock().unwrap().push(tuple.clone());
            Ok(OriginalDestination {
                address: self.destination,
                protocol: tuple.protocol,
            })
        }
    }

    #[cfg(target_os = "windows")]
    #[async_trait]
    impl FlowClient for RecordingClient {
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
            _observed_last_used_ns: u64,
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

    #[derive(Default)]
    struct RetryClient {
        enumerate_calls: AtomicUsize,
    }

    #[async_trait]
    impl MappingClient for RetryClient {
        async fn get_mapping(&self, _tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            Err(ProxyError::MappingNotFound)
        }
    }

    #[async_trait]
    impl FlowClient for RetryClient {
        async fn enumerate_flows(
            &self,
            _page_token: Vec<u8>,
            _limit: u32,
        ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
            if self.enumerate_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(ProxyError::Control("transient failure".into()))
            } else {
                Ok((Vec::new(), Vec::new()))
            }
        }

        async fn delete_flow(
            &self,
            _flow_id: u64,
            _generation: u32,
            _observed_last_used_ns: u64,
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

    #[derive(Default)]
    struct HangingClient {
        mapping_calls: AtomicUsize,
    }

    #[async_trait]
    impl MappingClient for HangingClient {
        async fn get_mapping(&self, _tuple: &Tuple) -> Result<OriginalDestination, ProxyError> {
            self.mapping_calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    #[async_trait]
    impl FlowClient for HangingClient {
        async fn enumerate_flows(
            &self,
            _page_token: Vec<u8>,
            _limit: u32,
        ) -> Result<(Vec<FlowRecord>, Vec<u8>), ProxyError> {
            std::future::pending().await
        }

        async fn delete_flow(
            &self,
            _flow_id: u64,
            _generation: u32,
            _observed_last_used_ns: u64,
        ) -> Result<FlowDeleteReport, ProxyError> {
            std::future::pending().await
        }
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
            _observed_last_used_ns: u64,
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
            listen_backlog: 1024,
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
            listen_backlog: 1024,
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

    #[test]
    fn configuration_rejects_timeout_that_overflows_nanoseconds() {
        let config = ProxyConfig {
            listen: "127.0.0.1:15000".parse().unwrap(),
            listen_backlog: 1024,
            control_endpoint: "https://127.0.0.1:50051".into(),
            psk_identity: "identity".into(),
            psk_secret: vec![1],
            udp_idle_timeout: Duration::from_secs(5),
            cleanup_interval: Duration::from_secs(5),
            idle_ttl: Duration::from_secs(u64::MAX),
            tcp_terminal_grace: Duration::from_secs(30),
            flow_scan_batch: 256,
        };
        assert!(matches!(
            config.validate(),
            Err(ProxyError::InvalidConfiguration(message)) if message.contains("too large")
        ));
    }

    #[test]
    fn configuration_rejects_invalid_listen_backlog() {
        let mut config = ProxyConfig {
            listen: "127.0.0.1:15000".parse().unwrap(),
            listen_backlog: 0,
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
            Err(ProxyError::InvalidConfiguration(message)) if message.contains("listen backlog")
        ));
        config.listen_backlog = i32::MAX as u32;
        assert!(
            config.validate().is_ok(),
            "a valid native backlog must not allocate internal queues"
        );
        config.listen_backlog = i32::MAX as u32 + 1;
        assert!(matches!(
            config.validate(),
            Err(ProxyError::InvalidConfiguration(message)) if message.contains("listen backlog")
        ));
    }

    #[test]
    fn conditional_admission_releases_exactly_once_and_generates_new_identity() {
        let admissions = ConditionalAdmissions::new(1);
        let tuple = Tuple {
            source: "127.0.0.1:42010".parse().unwrap(),
            destination: "127.0.0.1:15000".parse().unwrap(),
            protocol: TCP_PROTOCOL,
        };
        let first = admissions.reserve(tuple.clone()).unwrap();
        assert!(admissions.reserve(tuple.clone()).is_none());
        admissions.release(&first);
        admissions.release(&first);
        assert_eq!(admissions.pending(), 0);

        let replacement = admissions.reserve(tuple).unwrap();
        assert!(replacement.id.generation > first.id.generation);
        assert_ne!(replacement.id, first.id);
    }

    #[test]
    fn conditional_stale_generation_cannot_claim_replacement_handoff() {
        let admissions = ConditionalAdmissions::new(1);
        let tuple = Tuple {
            source: "127.0.0.1:42011".parse().unwrap(),
            destination: "127.0.0.1:15000".parse().unwrap(),
            protocol: TCP_PROTOCOL,
        };
        let stale = admissions.reserve(tuple.clone()).unwrap();
        admissions.release(&stale);
        let current = admissions.reserve(tuple).unwrap();

        assert!(mark_attempt_ready(&current));
        assert!(claim_ready_attempt(&current));
        assert_ne!(stale.id.generation, current.id.generation);
        assert_eq!(current.state(), ConditionalAttemptState::Claimed);
        assert_eq!(stale.state(), ConditionalAttemptState::Deferred);
    }

    #[test]
    fn conditional_socket_handoff_requires_ready_then_single_claim() {
        let admissions = ConditionalAdmissions::new(1);
        let attempt = admissions
            .reserve(Tuple {
                source: "127.0.0.1:42013".parse().unwrap(),
                destination: "127.0.0.1:15000".parse().unwrap(),
                protocol: TCP_PROTOCOL,
            })
            .unwrap();
        assert!(!claim_ready_attempt(&attempt));
        assert!(mark_attempt_ready(&attempt));
        assert!(claim_ready_attempt(&attempt));
        assert!(!claim_ready_attempt(&attempt));
        assert_eq!(attempt.state(), ConditionalAttemptState::Claimed);
    }

    #[test]
    fn conditional_timeout_and_cancellation_prevent_handoff() {
        let admissions = ConditionalAdmissions::new(1);
        let attempt = admissions
            .reserve(Tuple {
                source: "127.0.0.1:42012".parse().unwrap(),
                destination: "127.0.0.1:15000".parse().unwrap(),
                protocol: TCP_PROTOCOL,
            })
            .unwrap();
        attempt
            .state
            .store(ConditionalAttemptState::Cancelled as u8, Ordering::Release);
        assert!(!mark_attempt_ready(&attempt));
        assert!(!claim_ready_attempt(&attempt));
        assert_eq!(attempt.state(), ConditionalAttemptState::Cancelled);
        assert!(conditional_preconnect_budget(
            std::time::Instant::now() - CONTROL_RPC_TIMEOUT - Duration::from_millis(1)
        )
        .is_err());
    }

    #[tokio::test]
    async fn port_zero_udp_bind_uses_the_actual_tcp_listener_address() {
        let config = ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            listen_backlog: 1,
            control_endpoint: "https://127.0.0.1:50051".into(),
            psk_identity: "identity".into(),
            psk_secret: vec![1],
            udp_idle_timeout: Duration::from_secs(5),
            cleanup_interval: Duration::from_secs(5),
            idle_ttl: Duration::from_secs(60),
            tcp_terminal_grace: Duration::from_secs(30),
            flow_scan_batch: 1,
        };
        let proxy = Proxy::new(
            config,
            Arc::new(MockClient {
                destination: "127.0.0.1:9".parse().unwrap(),
                protocol: TCP_PROTOCOL,
            }),
        )
        .unwrap();
        let (tcp, udp) = proxy.bind().await.unwrap();
        let tcp_address = tcp.local_addr().unwrap();
        let udp_address = udp.local_addr().unwrap();
        assert_ne!(tcp_address.port(), 0);
        assert_eq!(udp_address, tcp_address);
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

    #[cfg(target_os = "windows")]
    #[tokio::test(flavor = "current_thread")]
    async fn conditional_accept_reuses_the_worker_preconnected_socket() {
        let _guard = WINDOWS_CONDITIONAL_TEST_LOCK.lock().await;
        let destination_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = destination_listener.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination_listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &buffer)
                .await
                .unwrap();
        });
        let proxy = Proxy::new(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                listen_backlog: 4,
                control_endpoint: "https://127.0.0.1:50051".into(),
                psk_identity: "identity".into(),
                psk_secret: vec![1],
                udp_idle_timeout: Duration::from_secs(5),
                cleanup_interval: Duration::from_secs(5),
                idle_ttl: Duration::from_secs(60),
                tcp_terminal_grace: Duration::from_secs(30),
                flow_scan_batch: 1,
            },
            Arc::new(MockClient {
                destination,
                protocol: TCP_PROTOCOL,
            }),
        )
        .unwrap();
        let (tcp_listener, udp_socket) = proxy.bind().await.unwrap();
        let proxy_address = tcp_listener.local_addr().unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.run_bound(tcp_listener, udp_socket, shutdown));
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, b"ping")
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response),
        )
        .await
        .expect("conditional accept bridge timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        shutdown_sender.send(true).unwrap();
        time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("conditional accept proxy did not shut down")
            .unwrap()
            .unwrap();
        destination_task.await.unwrap();
    }

    #[cfg(target_os = "windows")]
    #[tokio::test(flavor = "current_thread")]
    async fn conditional_accept_preserves_ipv6_listener_and_mapping_tuple() {
        let _guard = WINDOWS_CONDITIONAL_TEST_LOCK.lock().await;
        let destination_listener = TcpListener::bind("[::1]:0").await.unwrap();
        let destination = destination_listener.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination_listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &buffer)
                .await
                .unwrap();
        });
        let tuples = Arc::new(StdMutex::new(Vec::new()));
        let proxy = Proxy::new(
            ProxyConfig {
                listen: "[::1]:0".parse().unwrap(),
                listen_backlog: 4,
                control_endpoint: "https://[::1]:50051".into(),
                psk_identity: "identity".into(),
                psk_secret: vec![1],
                udp_idle_timeout: Duration::from_secs(5),
                cleanup_interval: Duration::from_secs(5),
                idle_ttl: Duration::from_secs(60),
                tcp_terminal_grace: Duration::from_secs(30),
                flow_scan_batch: 1,
            },
            Arc::new(RecordingClient {
                destination,
                tuples: tuples.clone(),
            }),
        )
        .unwrap();
        let (tcp_listener, udp_socket) = proxy.bind().await.unwrap();
        let proxy_address = tcp_listener.local_addr().unwrap();
        assert!(proxy_address.is_ipv6());
        assert_eq!(udp_socket.local_addr().unwrap(), proxy_address);
        let (shutdown_sender, shutdown) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.run_bound(tcp_listener, udp_socket, shutdown));
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, b"ipv6")
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response),
        )
        .await
        .expect("IPv6 conditional accept bridge timed out")
        .unwrap();
        assert_eq!(&response, b"ipv6");
        let tuple = tuples.lock().unwrap().pop().expect("mapping lookup");
        assert!(tuple.source.is_ipv6());
        assert!(tuple.destination.is_ipv6());
        shutdown_sender.send(true).unwrap();
        time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("IPv6 conditional accept proxy did not shut down")
            .unwrap()
            .unwrap();
        destination_task.await.unwrap();
    }

    #[cfg(target_os = "windows")]
    #[tokio::test(flavor = "current_thread")]
    async fn conditional_shutdown_cancels_a_pending_mapping_without_handoff() {
        let _guard = WINDOWS_CONDITIONAL_TEST_LOCK.lock().await;
        let client = Arc::new(HangingClient::default());
        let proxy = Proxy::new(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                listen_backlog: 4,
                control_endpoint: "https://127.0.0.1:50051".into(),
                psk_identity: "identity".into(),
                psk_secret: vec![1],
                udp_idle_timeout: Duration::from_secs(5),
                cleanup_interval: Duration::from_secs(5),
                idle_ttl: Duration::from_secs(60),
                tcp_terminal_grace: Duration::from_secs(30),
                flow_scan_batch: 1,
            },
            client.clone(),
        )
        .unwrap();
        let (tcp_listener, udp_socket) = proxy.bind().await.unwrap();
        let proxy_address = tcp_listener.local_addr().unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.run_bound(tcp_listener, udp_socket, shutdown));
        let client_connect = tokio::spawn(TcpStream::connect(proxy_address));
        time::timeout(Duration::from_secs(1), async {
            while client.mapping_calls.load(Ordering::SeqCst) == 0 {
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("conditional mapping lookup did not begin");
        shutdown_sender.send(true).unwrap();
        time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("conditional proxy did not stop during a pending mapping")
            .unwrap()
            .unwrap();
        let _ = client_connect.await;
        assert_eq!(client.mapping_calls.load(Ordering::SeqCst), 1);
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
    async fn udp_association_cache_reuses_active_destination() {
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
        assert_eq!(
            association.destination,
            first_destination.local_addr().unwrap()
        );
        assert_eq!(associations.entries.lock().await.len(), 1);
        shutdown_sender.send(true).unwrap();
        associations.shutdown().await;
    }

    #[tokio::test]
    async fn outbound_udp_activity_extends_the_association_lease() {
        let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (shutdown_sender, shutdown) = watch::channel(false);
        let associations = UdpAssociations::new(
            proxy_socket.clone(),
            Arc::new(MockClient {
                destination: destination.local_addr().unwrap(),
                protocol: UDP_PROTOCOL,
            }),
            Duration::from_millis(50),
            shutdown,
        );
        let client_address: SocketAddr = "127.0.0.1:42001".parse().unwrap();
        let tuple = Tuple {
            source: client_address,
            destination: proxy_socket.local_addr().unwrap(),
            protocol: UDP_PROTOCOL,
        };

        associations.forward(client_address, b"one").await.unwrap();
        time::sleep(Duration::from_millis(35)).await;
        associations.forward(client_address, b"two").await.unwrap();
        time::sleep(Duration::from_millis(35)).await;
        assert!(associations.entries.lock().await.contains_key(&tuple));

        time::timeout(Duration::from_millis(250), async {
            loop {
                if !associations.entries.lock().await.contains_key(&tuple) {
                    return;
                }
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("association should expire after outbound activity stops");
        shutdown_sender.send(true).unwrap();
        associations.shutdown().await;
    }

    #[tokio::test]
    async fn association_shutdown_waits_for_relay_socket_cleanup() {
        let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (_shutdown_sender, shutdown) = watch::channel(false);
        let associations = UdpAssociations::new(
            proxy_socket,
            Arc::new(MockClient {
                destination: destination.local_addr().unwrap(),
                protocol: UDP_PROTOCOL,
            }),
            Duration::from_secs(5),
            shutdown,
        );
        let client_address: SocketAddr = "127.0.0.1:42002".parse().unwrap();
        associations
            .forward(client_address, b"request")
            .await
            .unwrap();
        let association = associations
            .entries
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .clone();

        associations.shutdown().await;
        assert!(associations.entries.lock().await.is_empty());
        assert!(*association.relay_done.borrow());
    }

    #[tokio::test]
    async fn maintenance_retry_backoff_controls_the_next_scan() {
        let client = Arc::new(RetryClient::default());
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (shutdown_sender, shutdown) = watch::channel(false);
        let associations = Arc::new(UdpAssociations::new(
            socket,
            client.clone(),
            Duration::from_millis(300),
            shutdown_sender.subscribe(),
        ));
        let maintenance = tokio::spawn(run_maintenance(
            client.clone(),
            associations,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            shutdown,
        ));

        time::timeout(Duration::from_millis(200), async {
            while client.enumerate_calls.load(Ordering::SeqCst) < 2 {
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("retry backoff should run before the fixed cleanup interval");
        shutdown_sender.send(true).unwrap();
        maintenance.await.unwrap();
    }

    #[tokio::test]
    async fn maintenance_shutdown_cancels_a_hanging_control_operation() {
        let client = Arc::new(HangingClient::default());
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (shutdown_sender, shutdown) = watch::channel(false);
        let associations = Arc::new(UdpAssociations::new(
            socket,
            client.clone(),
            Duration::from_secs(1),
            shutdown_sender.subscribe(),
        ));
        let maintenance = tokio::spawn(run_maintenance(
            client,
            associations,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            shutdown,
        ));

        tokio::task::yield_now().await;
        shutdown_sender.send(true).unwrap();
        time::timeout(Duration::from_millis(100), maintenance)
            .await
            .expect("shutdown cancels the pending maintenance RPC")
            .unwrap();
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
