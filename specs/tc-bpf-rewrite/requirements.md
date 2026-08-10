<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Requirements

## Approved Change Set

### CHG-001 — Replace destination policy with global family targets

- **Before:** Eligible ingress flows require an exact destination-policy map
  entry, policy CRUD RPCs, policy capacity, and policy-miss telemetry.
- **After:** Authenticated `GetConfig`/`SetConfig` expose independent IPv4 and
  IPv6 target address/port pairs. A complete pair rewrites all eligible new
  TCP/UDP flows in that family; an unset pair passes unchanged and increments a
  bounded target-miss counter. A partial pair is invalid. Existing flows keep
  their snapped target.
- **Retired:** Destination-policy map/ABI, policy CRUD messages/RPCs, policy
  capacity/status/discovery, policy backend methods, and policy-miss telemetry.
- **Traceability:** `USER-REQUEST: remove destination-policy surface and
  globally DNAT all eligible TCP/UDP except control gRPC traffic.`

### CHG-002 — Exclude authenticated control traffic

- **Before:** The listener address is not represented in the BPF runtime ABI.
- **After:** The immutable `SSP_LISTEN_ADDR` descriptor is present before
  attachment. TCP ingress packets whose destination matches the listener and
  TCP egress packets whose source matches it pass unchanged and increment a
  control-bypass counter. A family wildcard matches every address in that
  family on the listener port. UDP on the same port remains eligible.

### CHG-003 — Version the program and runtime ABI

- **Before:** Program ABI v2 and a policy-bearing runtime map are accepted.
- **After:** Program ABI v3 exports v3 ingress/egress symbols and a versioned
  runtime configuration map containing schema version, v4/v6 targets, listener
  descriptor and wildcard flags, idle TTL, terminal grace, and active-flow cap.
  Flow maps remain v1 where unchanged. Counter slots are target misses, flow
  insertion failures, and control bypasses.
- **Migration:** Attach/readiness rejects stale or mixed v2/policy-only
  artifacts and accepts only the complete v3 contract.

### CHG-004 — Validate listener before startup

- **Before:** `SSP_LISTEN_ADDR` is parsed after runtime startup.
- **After:** It is parsed and validated before transport creation, BPF attach,
  or serving. Invalid values fail startup. `SetConfig` cannot change the
  listener descriptor.

### CHG-005 — Add CI/CD validation and an executable BPF fixture runner

- **Before:** No GitHub Actions workflow validates the two Rust crates and BPF
  artifact together. The `bpf_prog_test_run` integration test delegates to an
  external runner and can only be executed when one is supplied.
- **After:** A GitHub Actions workflow runs on `ubuntu-latest` for pull
  requests and pushes to `main`. It installs required Linux tooling and native
  dependencies, runs formatting, strict workspace clippy, workspace build,
  and workspace tests, builds the canonical BPF object through the existing
  Makefile, and executes the gated BPF fixture sequence. A checked-in Linux
  runner implements `bpf_prog_test_run_opts`, accepts the generated ELF and
  required ordered fixtures, and fails for unavailable capabilities, invalid
  program loading, or unexpected packet/action/checksum/state results. CI
  validates only and does not publish artifacts.
- **Retired:** No existing requirement is retired; the environment-gated BPF
  test becomes executable in CI.
- **Traceability:** `USER-REQUEST: add a CI/CD pass that runs clippy, format
  check, build and test for all the components (both the BPF and the two rust
  crates); follow-up approval to add the missing runner.`

### CHG-006 — Make host-proxy lifecycle observable

- **Before:** Host-proxy lifecycle visibility is inconsistent: startup and
  activation use unconditional stderr messages, some forwarding failures are
  rate-limited, and UDP idle-association removal, relay termination, and
  shutdown do not consistently emit structured lifecycle events.
- **After:** Host-proxy MUST emit filterable structured `tracing` events for
  TCP and UDP lifecycle transitions and operational failures. Normal
  lifecycle events MUST cover TCP forwarding start and termination, UDP
  association creation, replacement, expiry/garbage collection, relay stop,
  and proxy shutdown. Mapping lookup/validation failures, outbound
  connect/send/receive failures, relay delivery failures, and control-service
  detach failures MUST be distinguishable events with error context. Lifecycle
  events MUST include protocol and, where applicable, the synthetic tuple,
  mapped/original destination, association age, idle timeout, reason, and
  error fields. UDP association reuse MUST NOT produce an info event for every
  datagram. Existing unconditional stderr startup and activation messages
  remain unchanged; lifecycle events are controlled by `RUST_LOG`.
- **Retired:** No packet-rewrite, flow-map, control RPC, or forwarding
  semantics are retired or changed by this observability requirement.
- **Traceability:** `USER-REQUEST: add host-proxy lifecycle logging, including
  visible garbage collection of old UDP associations.`

### CHG-007 — Move dataplane lifecycle ownership to host-proxy

- **Before:** BPF flow maintenance and stale-record deletion are owned by the
  Linux control-service maintenance worker, while host-proxy separately owns
  local UDP association expiry and performs UDP mapping lookups on the
  steady-state data path. Lifecycle policy is split across processes.
- **After:** Host-proxy MUST own BPF activation/deactivation orchestration,
  maintenance scheduling, expiry policy, retry policy, flow deletion
  decisions, and local TCP/UDP association lifecycle. The control-service MUST
  be stateless between requests and act as a privileged authenticated adapter
  that translates BPF-agnostic flow/configuration operations into dataplane
  operations. Existing forwarding MUST continue during temporary control-plane
  loss; host-proxy MUST reconnect and retry maintenance visibly.
- **Retired:** Autonomous control-service maintenance scheduling, stale-flow
  policy decisions, and steady-state per-datagram UDP mapping lookups.
- **Traceability:** `USER-REQUEST: issue #12 — Move stale mapping maintenance
  and lifecycle decisions to host-proxy while keeping control-service as a
  thin adapter.`

### CHG-008 — Add BPF-agnostic flow lifecycle primitives

- **Before:** The control API exposes mapping-oriented list/get/delete
  behavior and maintenance-specific service state rather than a complete
  host-owned flow lifecycle contract.
- **After:** The authenticated gRPC contract MUST expose typed,
  BPF-agnostic flow primitives for enumerating flows, reading flow identity
  and lifecycle metadata, and deleting a flow. Flow records MUST include
  opaque flow identity, generation, synthetic/original tuples, protocol,
  last-used time, and TCP lifecycle state where applicable. Deletion MUST
  support generation checking, idempotent outcomes, and a cleanup report that
  distinguishes complete, already-absent, stale-generation, and partial
  cleanup. Enumeration and deletion MUST be sufficient for host-proxy
  maintenance without a required per-flow read RPC.
- **Retired:** Host-proxy dependence on BPF map names, raw key/value ABI, or
  control-service maintenance statistics as lifecycle inputs.
- **Traceability:** `USER-REQUEST: keep the gRPC contract simple and
  BPF-agnostic while the control-service translates flow operations to BPF.`

### CHG-009 — Make host maintenance and UDP caching explicit

- **Before:** Cleanup timing is configured in the control-service runtime and
  UDP associations query the control service for every datagram.
- **After:** Host-proxy MUST accept explicit cleanup interval, idle TTL, TCP
  terminal grace, scan batch, and UDP association timeout settings, with
  current defaults preserved unless overridden. An active UDP association MUST
  reuse its local destination without `GetMapping` on subsequent datagrams.
  Host-proxy MUST re-resolve only after association expiry, explicit flow
  invalidation/deletion, or one controlled outbound-failure retry path for a
  destination-specific failure such as connection refusal, timeout, or
  unreachable destination. Local resource errors MUST NOT discard a healthy
  association.
- **Retired:** Control-service-owned maintenance timing and per-datagram UDP
  mapping RPCs.
- **Traceability:** `USER-REQUEST: issue #12 — make the host UDP mapping
  authoritative while active and avoid a query per UDP packet.`

### CHG-010 — Harden flow deletion and lifecycle transactions

- **Before:** RST teardown can release a slot after state ownership changes,
  deletion guards do not prove packet quiescence, attach/configure requests can
  interleave, and host shutdown/control retries have unbounded edges.
- **After:** Packet updates participate in a generation-addressed in-flight
  protocol. Host deletion freezes a generation, waits for in-flight updates to
  drain, then verifies its observation before deleting canonical state. RST
  teardown deletes indexes only after deleting its own state and only when each
  index still names the same generation; capacity is released only by the
  successful state owner. Guard expiry and unconditional post-insertion cleanup
  prevent a failed delete from blackholing traffic. Attach and configuration
  publication are one serialized transaction. Host-proxy tracks outbound UDP
  activity, waits for forwarding children before detaching, bounds control
  operations, bounds duration conversion, and schedules retry attempts by the
  selected backoff deadline.
- **Traceability:** `USER-REQUEST: consolidated hardening pass for remaining
  concurrency, shutdown, timeout, and specification findings.`

## Stable Requirements

### REQ-TC-001 — Family-preserving global DNAT

Ingress MUST rewrite only the destination address/port of bounds-checkable
TCP/UDP first-fragment packets when the current family target is configured.
Egress MUST reverse-rewrite only the source address/port for the corresponding
active flow. IPv4 and IPv6 targets are independent and cross-family targets
are invalid.

### REQ-TC-002 — Canonical active-flow state

The flow ABI MUST retain one canonical record and three tuple indexes for the
original client-to-destination, synthetic client-to-target, and reverse
target-to-client tuples. New flow state MUST snapshot the current target;
configuration changes MUST NOT mutate active flow targets. Packet updates MUST
enter a generation-addressed in-flight critical section before mutating active
state; host deletion MUST freeze that generation and observe the section
drained before deleting its state or indexes.

### REQ-TC-003 — TCP/UDP lifecycle

TCP MUST record SYN, SYN/ACK, ACK, FIN, and RST observations. RST removes the
flow immediately. Completed bidirectional FIN/ACK teardown is retained until
terminal grace; incomplete TCP, UDP, and QUIC-over-UDP expire through idle TTL.
An RST teardown MUST delete canonical state before indexes, remove only indexes
that still identify its flow ID and generation, and release active-flow
capacity only when its state deletion succeeds.

### REQ-TC-004 — Packet safety

Malformed, truncated, unsupported, non-initial-fragment, and unreadable
packets MUST pass unchanged. Only fully bounds-checkable TCP/UDP packets may
update checksums or flow state. No TCP lifecycle assumptions apply to UDP.

### REQ-TC-005 — Runtime admission and synchronization

Runtime configuration MUST validate atomically, preserve revisions on failure,
bound active-flow capacity by fixed ELF maxima (three indexes per flow), and
publish one coherent ABI record. Changing targets affects only new flows.
Attach and `SetConfig` transactions MUST be serialized so the published
snapshot and BPF runtime map never describe different configurations.

### REQ-TC-006 — Readiness and ownership

The control service MUST validate all v3 symbols/maps, runtime schema, counter
slots, and fixed maxima before readiness. Attach, rollback, detach, maintenance,
and shutdown MUST retain explicit partial-failure behavior. Deletion guards
MUST be cleaned after every post-insertion outcome and expire in the packet
path if host cleanup cannot remove them.

### REQ-TC-007 — Listener immutability

The listener descriptor MUST be family-aware, include address, TCP port, and
wildcard flags, be written before attach, and remain immutable through
`SetConfig`. Concrete listeners match address and port; wildcard listeners
match any address in their family on the TCP port.

### REQ-CI-001 — Reproducible CI triggers and platform

The workflow MUST run on Ubuntu for pull requests and pushes to `main`, use a
lockfile-respecting Rust toolchain, and make all required toolchain and native
dependencies explicit.

### REQ-CI-002 — Rust quality gates

The workflow MUST fail if `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo build --workspace`, or `cargo test --workspace` fails.

### REQ-CI-003 — BPF build gate

The workflow MUST install clang and Linux kernel UAPI headers and build the
canonical BPF object through `crates/bpf/Makefile`. A failed BPF compilation
MUST fail CI.

### REQ-CI-004 — Kernel fixture execution

The checked-in runner MUST execute `target-miss`, `flow-create`,
`forward-rewrite`, `reverse-rewrite`, `control-bypass`, `fin-ack-teardown`,
and `rst` through `bpf_prog_test_run_opts` against the generated BPF ELF.
Missing capabilities, loader/verifier failures, and any fixture mismatch MUST
return nonzero. CI MUST enable this gate and MUST NOT silently skip it.

### REQ-CI-005 — Failure visibility and scope

Toolchain, dependency, capability, loader, verifier, packet, action,
checksum, state, and Rust failures MUST remain visible failures. The workflow
MUST not alter production behavior, publish artifacts to a branch or release,
or introduce a direct-forward fallback. Workflow-run artifacts are permitted
when required by the approved end-to-end validation contract.

### REQ-CI-006 — Reproducible Windows CI environment

The existing workflow MUST include a Windows job for pull requests and pushes
to `main`. The job MUST use the pinned repository actions and Rust 1.96.1,
install `ShiningLight.OpenSSL.Dev` version 4.0.1 through winget, and fail if
the package or installed OpenSSL version does not match.

### REQ-CI-007 — Windows host-proxy quality gates

The Windows job MUST fail if formatting, strict clippy, or the locked
`shadow-socket-proxy-host` build or test command with the `tls-psk` feature
enabled fails.

### REQ-CI-008 — Local Windows validation

Before the change is submitted for review, the same OpenSSL version and
Windows host-proxy validation commands MUST pass on a Windows development
environment.

### REQ-CI-E2E-001 — Separate deployable artifacts

CI MUST upload separate workflow artifacts for the canonical BPF ELF, Linux
control-service executable/runtime manifest, and Windows host-proxy executable
with required runtime DLLs. Artifact contents and names MUST be deterministic
and downloadable by the end-to-end job.

### REQ-CI-E2E-002 — Windows-host/WSL deployment

CI MUST use `windows-latest` as the integration host, use its default WSL
distribution, deploy the BPF ELF and control service inside WSL, and run the
host proxy on Windows. Privileged WSL setup and teardown MUST use explicit
`wsl.exe -u root` execution and MUST not require an interactive sudo password.

### REQ-CI-E2E-003 — Authenticated TCP path

The integration validation MUST generate ephemeral TLS-PSK credentials,
configure the deployed control service, start the deployed host proxy, and
verify that a TCP request originating in WSL reaches a Windows-host test
server through the proxy and returns a predetermined marker.

### REQ-CI-E2E-004 — Exact BPF evidence

The integration validation MUST verify that the control service is ready, that
the exercised mapping contains the Windows test-server original destination
and the host-proxy synthetic destination, that the mapping is observed before
teardown, and that the flow-insertion-failure counter does not increase.

### REQ-CI-E2E-005 — Strict prerequisite handling

The artifact and end-to-end jobs MUST run for pull requests and pushes to
`main`. Missing WSL, package, kernel, BPF, networking, artifact,
authentication, process, marker, mapping, or cleanup prerequisites MUST fail
the job visibly rather than being skipped.

### REQ-CI-E2E-006 — Shared local and CI driver

The repository MUST contain a locally executable Windows/WSL end-to-end driver
that performs the same deployment, TCP flow, exact evidence, and cleanup
assertions used by CI. Local execution MUST require Windows and WSL and MUST
fail clearly when those prerequisites are unavailable.

### REQ-HP-LOG-001 — Structured lifecycle events

The host-proxy MUST emit `tracing` lifecycle events for TCP forwarding start
and termination, UDP association creation, replacement, expiry/garbage
collection, relay stop, and proxy shutdown. UDP association reuse MUST NOT
emit an info event for every datagram.

### REQ-HP-LOG-002 — Failure event visibility

The host-proxy MUST emit distinguishable structured events for mapping lookup
and validation failures, outbound connect/send/receive failures, relay
delivery failures, and control-service detach failures. Failure events MUST
preserve the underlying error context and MUST NOT be silently converted into
successful-looking lifecycle events.

### REQ-HP-LOG-003 — Operational context and filtering

Applicable lifecycle and failure events MUST include protocol and the
synthetic tuple; association events MUST also include the mapped/original
destination, association age when known, idle timeout when relevant, and a
machine-readable reason or error. Lifecycle logging MUST remain filterable by
the existing `RUST_LOG` configuration. Existing unconditional stderr startup
and activation messages are not replaced by this requirement.

### REQ-HP-MAINT-001 — Host-proxy lifecycle ownership

Host-proxy MUST own BPF activation/deactivation orchestration, maintenance
scheduling, expiry policy, retry policy, flow deletion decisions, and local
TCP/UDP association lifecycle. The control-service MUST remain stateless with
respect to maintenance and flow-lifecycle policy between requests and MUST
NOT autonomously schedule or decide stale-flow deletion. Process-local
configuration, health, log, and cumulative operational telemetry state is
allowed and is not lifecycle ownership.

### REQ-HP-MAINT-002 — BPF-agnostic flow primitives

The authenticated control API MUST expose typed `EnumerateFlows` and
`DeleteFlow` primitives without requiring host-proxy to know BPF map names,
raw keys, or raw value layouts. Enumerated records MUST include opaque flow
identity, generation, synthetic/original tuples, protocol, last-used time,
and TCP lifecycle state where applicable. A separate flow-read RPC is not
required when enumeration returns this complete record.

### REQ-HP-MAINT-003 — Generation-safe idempotent deletion

Flow deletion MUST accept flow identity and generation, avoid deleting a
newer incarnation when the generation no longer matches, and return an
idempotent cleanup report distinguishing complete removal, already-absent
state, stale generation, and partial cleanup. Cross-index cleanup MUST
preserve the canonical flow/index consistency invariant or report the
incomplete cleanup explicitly. A partial result MUST remain retryable with
the same identity/generation; a stale-generation result MUST not invalidate
local state.

### REQ-HP-MAINT-004 — Host-owned maintenance policy

Host-proxy MUST accept explicit cleanup interval, idle TTL, TCP terminal grace,
flow scan batch, and UDP association timeout settings. Existing defaults MUST
remain unchanged unless an operator overrides them. The control-service MUST
not own or autonomously apply these policy values. Maintenance passes MUST
not overlap; a failed pass MUST be retried on a later scheduled pass, and
reconnection attempts MUST use bounded backoff capped by the cleanup interval
until control access is restored. Shutdown MUST cancel pending retries.

### REQ-HP-MAINT-005 — Authoritative UDP association cache

After a UDP association is created, host-proxy MUST reuse its local connected
destination without issuing `GetMapping` for each datagram. Host-proxy MUST
perform a new mapping lookup only when no association exists, the association
has expired, host-proxy explicitly invalidates/deletes its flow, or one
controlled outbound-failure retry path requires re-resolution. Eligible
outbound failures are destination-specific refusal, timeout, or unreachable
errors; local resource/configuration errors preserve the association and are
reported without re-resolution.

### REQ-HP-MAINT-006 — Control-plane loss behavior

Temporary control-service loss MUST NOT interrupt existing forwarding. The
host-proxy MUST report scan, deletion, and reconnection failures, retain
active local forwarding state, and retry control-plane maintenance on a later
pass using the bounded backoff policy. It MUST NOT silently delete local state
without control-service confirmation or introduce direct-forward fallback
behavior.

## Acceptance Criteria

- Valid IPv4/IPv6 TCP and UDP packets rewrite with correct L3/L4 checksums.
- Unset targets pass unchanged and increment only the bounded target-miss slot.
- Partial target pairs, invalid schema, invalid listener, and listener changes
  are rejected without changing the prior revision.
- TCP control traffic bypasses on ingress and egress; UDP on that port rewrites.
- Active flows retain their original snapped target after `SetConfig`.
- v2, policy-only, missing, or mixed artifacts fail attach/readiness.
- Flow insertion/full-map failure drops eligible packets and increments its slot.
- RST, FIN/ACK grace, idle TTL, malformed packets, and unsupported protocols
  preserve existing lifecycle and safety invariants.
- A pull request or push to `main` runs all Rust gates, builds the BPF object,
  and executes every required kernel fixture; any failure is reported as a
  failed workflow.
- A pull request or push to `main` installs and verifies OpenSSL 4.0.1 on
  Windows and runs the TLS-PSK host-proxy format, clippy, build, and test
  gates; any failure is reported as a failed workflow.
- Host-proxy logs structured TCP and UDP lifecycle events, visibly reports
  idle UDP association garbage collection, includes the required operational
  context, and reports the specified failure classes without logging every
  UDP reuse at info level.
- Host-proxy owns activation, maintenance, flow deletion, and UDP association
  policy; the control-service performs no autonomous maintenance.
- Flow enumeration and generation-safe deletion use BPF-agnostic typed RPCs
  with complete/idempotent/partial cleanup results.
- Repeated UDP datagrams reuse the local association without steady-state
  mapping RPCs, and control-plane loss preserves existing forwarding while
  maintenance retries.

## Non-Goals

- Cross-family translation, SNAT, wildcard target matching, or QUIC close state.
- Rewriting malformed packets, non-initial fragments, or unsupported protocols.
- Replacing TC, changing host-proxy forwarding, or changing TLS/PSK policy.
- Introducing per-datagram lifecycle logging.
- Replacing the control-service with direct host-side BPF syscalls, exposing
  raw BPF map ABI to host-proxy, or changing packet rewrite semantics.
- Publishing CI build artifacts or changing production packet behavior.
