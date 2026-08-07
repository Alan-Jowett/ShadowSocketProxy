<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Container Control Service Requirements

## Change Set

### CHG-001 — Add the container control-service crate

- **Before:** The repository has no Rust crate implementing the container gRPC
  control service.
- **After:** The repository contains a Linux-targeted Rust crate that owns the
  control-plane lifecycle for the container-side BPF program and its flow
  mapping state.
- **Traceability:** `USER-REQUEST: Create a rust crate for the Container gRPC
  control service as described in the README.md.`

### CHG-002 — Load and control TC BPF attachment

- **Before:** No service loads a supplied BPF ELF or controls its attachment.
- **After:** The service accepts authenticated host commands to attach or
  detach a supplied BPF ELF at TC ingress and egress for host-selected network
  interfaces. Attachment and detachment are idempotent, report failures
  explicitly, and do not leave a partially completed required operation
  undisclosed.
- **Traceability:** `USER-REQUEST: Load and attach a BPF program (provided as an
  ELF file) at the TC control point.` User clarification: host process selects
  interfaces and sends attach/detach commands; the program attaches at both
  ingress and egress.

### CHG-003 — Expose bidirectional original-tuple mappings

- **Before:** The BPF redirection hash is not exposed through a defined
  container control API.
- **After:** Authenticated gRPC clients can list mappings and retrieve one
  mapping by synthetic tuple. Each mapping converts a synthetic/current
  5-tuple to its original 5-tuple and supports IPv4 and IPv6 addresses,
  transport protocol, source port, and destination port.
- **Traceability:** `USER-REQUEST: Expose a gRPC interface to read connection
  mappings (converted 5-tuple -> original 5-tuple) from the BPF program's BPF
  hash table.`

### CHG-004 — Version the BPF map ABI and lifecycle metadata

- **Before:** No stable key/value contract exists between the BPF ELF and
  user mode.
- **After:** The service and placeholder BPF program share a versioned map ABI.
  A value includes `last_seen` packet activity and explicit TCP lifecycle state
  for SYN, SYN/ACK, ACK, FIN, and RST. UDP and QUIC are supported as UDP-based
  flows without assuming TCP state transitions; their protocol-specific
  activity representation is defined by the versioned ABI.
- **Traceability:** User clarification: the BPF program updates last-seen for
  each tuple and tracks explicit TCP state. User selection: TCP, UDP, and QUIC.

### CHG-005 — Periodic stale-flow maintenance

- **Before:** No user-mode process removes stale flow mappings.
- **After:** A periodic maintenance task deletes mappings that have been idle
  longer than the configured interval/TTL. The task reports deletion and
  decode errors, continues processing independent entries, and never treats a
  failed deletion as successful cleanup.
- **Traceability:** `USER-REQUEST: Perform periodic maintenance of the BPF
  hash-table (delete stale entries etc).` User clarification: user mode cleans
  connections idle longer than a configured interval.

### CHG-006 — Host control and runtime configuration API

- **Before:** No authenticated host control endpoint or runtime service
  configuration exists.
- **After:** A TCP gRPC endpoint secured with the requested TLS shared-PSK
  policy exposes attach, detach, mapping, health/status, and configuration
  operations. Cleanup interval, idle TTL, map scan batch size, and bounded log
  capacity can be updated through authenticated configuration RPCs and are
  applied atomically after validation.
- **Traceability:** User clarifications: host sends attach/detach commands;
  TCP endpoint secured with TLS shared PSK; all operational values are exposed
  through gRPC and are runtime-configurable.

### CHG-007 — Optional bounded log synchronization

- **Before:** No control-service log synchronization contract exists.
- **After:** The service optionally retains a bounded log sequence and exposes
  an authenticated pull RPC using a monotonic cursor. Clients can detect
  cursor expiry explicitly rather than receiving an ambiguous partial result.
- **Traceability:** User clarification: host process can pull an optional log
  sync using a monotonic cursor, bounded retention, and explicit
  cursor-expired errors.

## Stable Requirements

### REQ-001 — Linux Rust crate

The deliverable MUST include a buildable Rust crate targeting Linux for the
container control service. The crate MUST isolate platform/BPF operations
behind testable service components and MUST include a placeholder BPF ELF
integration contract.

**Acceptance criteria**

- The crate has a documented Linux build/runtime target.
- The BPF backend can be replaced or exercised through a test double.
- The placeholder ELF/map ABI is versioned and documented.

**Invariant impact:** Preserves separation between packet processing in BPF and
control/maintenance in user mode.

### REQ-002 — TC attachment lifecycle

The service MUST accept authenticated attach and detach commands from the host,
select interfaces from the command, and manage both TC ingress and egress
attachments for the supplied ELF. Required-operation failures MUST be visible
to the caller, and shutdown MUST attempt cleanup of service-owned attachments.

**Acceptance criteria**

- Attach reports success only after required ingress and egress attachments
  are established.
- Detach is safe to repeat and reports any cleanup failure.
- A failure during a multi-interface operation identifies affected interfaces
  and directions.

**Invariant impact:** Prevents a control-plane success response from masking
  incomplete packet interception.

### REQ-003 — Mapping read API

The service MUST expose list and point lookup RPCs for synthetic-to-original
5-tuple mappings. The schema MUST support IPv4, IPv6, TCP, UDP, and QUIC
traffic, with protocol and both ports represented explicitly.

**Acceptance criteria**

- List returns each decodable mapping at a defined consistent-read boundary.
- Point lookup distinguishes not-found from backend failure.
- Malformed or ABI-incompatible entries are surfaced as observable errors or
  explicitly counted skipped entries according to the approved design.

**Invariant impact:** Maintains tuple identity across BPF, gRPC, and host proxy
lookups.

### REQ-004 — Versioned mapping ABI

The service MUST use a versioned BPF key/value ABI. Values MUST contain
last-seen activity. TCP values MUST encode SYN, SYN/ACK, ACK, FIN, and RST
state explicitly. UDP/QUIC values MUST remain activity-trackable without
applying TCP-only state assumptions.

**Acceptance criteria**

- Unsupported ABI versions are rejected explicitly.
- Last-seen values are interpreted with documented clock units and semantics.
- TCP state transitions and terminal states are represented in test fixtures.

**Invariant impact:** Makes stale cleanup and tuple restoration deterministic
across BPF and user-mode versions.

### REQ-005 — Stale-entry maintenance

The service MUST periodically scan the BPF hash table and delete entries whose
last-seen activity is older than the configured idle TTL. Cleanup MUST be
bounded by the configured scan batch size, continue after independent entry
errors, and expose counts/errors through service status and logs.

**Acceptance criteria**

- Idle entries are deleted; recently active entries are retained.
- Repeated maintenance is idempotent.
- Read, decode, clock, and delete failures are not silently converted to
  successful cleanup.

**Invariant impact:** Prevents stale flow-map state from redirecting new or
  unrelated traffic while preserving active mappings.

### REQ-006 — Authenticated host control

The service MUST expose a TCP gRPC endpoint protected by the requested TLS
shared-PSK policy. All mutating and inspection RPCs MUST require successful
authentication. The design MUST identify the selected Rust TLS implementation
and report incompatibility if it cannot implement the requested PSK policy.

**Acceptance criteria**

- Unauthenticated or incorrectly authenticated requests are rejected.
- Attach, detach, mapping, status, and configuration calls share the same
  authenticated endpoint policy.
- TLS/PSK configuration failures prevent a misleading ready state.

**Invariant impact:** Prevents unauthorized BPF attachment, map disclosure, or
  runtime policy changes.

### REQ-007 — Atomic runtime configuration

The service MUST expose authenticated get/set configuration RPCs for cleanup
interval, idle TTL, map scan batch size, and bounded log capacity. Invalid
values MUST be rejected without partially applying the update.

**Acceptance criteria**

- A valid update becomes visible as one coherent configuration revision.
- Invalid, zero, overflowing, or internally contradictory values are rejected.
- Concurrent maintenance observes either the old or new complete configuration,
  never a mixture.

**Invariant impact:** Preserves predictable maintenance and resource behavior
under concurrent host control.

### REQ-008 — Optional bounded log pull

The service MUST optionally retain service log records in bounded storage and
expose a pull RPC using a monotonic cursor. If a cursor falls outside retained
history, the service MUST return an explicit cursor-expired error.

**Acceptance criteria**

- A client can pull records after a cursor and advance its cursor.
- Retention is bounded by configured capacity.
- Cursor expiry is distinguishable from an empty result and transport failure.

**Invariant impact:** Provides observable control-plane synchronization without
  unbounded memory growth.

## Non-Goals

- Implementing the final packet-rewriting BPF logic; the first deliverable uses
  a placeholder ELF/map contract.
- Implementing the host shadow proxy or changing its forwarding behavior.
- Assuming QUIC-specific connection state beyond UDP tuple activity and
  last-seen tracking.
- Introducing a new packet interception mechanism other than TC.

## Open Design Constraints

- The requested TLS shared-PSK mode is not universally supported by Rust gRPC
  TLS stacks. The design phase MUST resolve the concrete backend or identify
  an explicit, user-approved compatibility alternative before implementation.
- The versioned ABI MUST define byte order, address encoding, clock source,
  state encoding, and map pin/ownership behavior.
