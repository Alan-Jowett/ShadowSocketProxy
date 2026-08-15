<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy WSK Kernel Relay Requirements

## Traceability

```text
USER-REQUEST -> REQ-WKR-* -> D-WKR-* -> TC-WKR-* -> implementation/tests
```

The prototype branch `feature/wsk-kernel-relay` is a source of WSK, WDM,
IRP, MDL, cancellation, and failure-continuity lessons only. Its fixed-port,
fixed-capacity, nonce, serialized-wait, and user-owned semantic-state
assumptions are not requirements for this clean implementation.

## Change Set

### CHG-WKR-001 - Exclusive kernel data path

- **Before:** Redirected payloads use the user-mode host proxy data path.
- **After:** Add a compile-time-selected WSK/WDM kernel-relay path. A binary
  selects exactly one data path; kernel-relay mode forwards payloads in the
  driver and does not route payload bytes through user mode.
- **Traceability:** `USER-REQUEST: forwarding operations to occur in kernel mode`.

### CHG-WKR-002 - WSK listeners and exact tuples

- **Before:** No product contract defines kernel-owned listeners or tuple
  extraction.
- **After:** The driver owns configurable IPv4/IPv6 TCP and UDP listeners,
  preserves the observed synthetic tuple, and uses OS-selected outbound
  source endpoints.
- **Traceability:** `USER-REQUEST: operates in kernel mode using WSK`.

### CHG-WKR-003 - Driver-owned mapping protocol

- **Before:** The prototype-specific broker owns mapping exchange details.
- **After:** The driver constructs, sends, validates, and applies the complete
  existing `GetMapping` protobuf request/response. The user agent never
  interprets mapping semantics or owns flow state.
- **Traceability:** `USER-REQUEST: driver building the full protobuf message`.

### CHG-WKR-004 - Opaque tunnel and direct transport alternative

- **Before:** Mapping resolution is coupled to a user-mode semantic broker.
- **After:** The design supports direct kernel gRPC/TLS or an opaque user-mode
  TLS/gRPC tunnel. The first implementation uses the opaque tunnel: the driver
  owns protobuf bytes and semantics; user mode only transports bytes and
  correlates replies.
- **Traceability:** `USER-REQUEST: host-proxy ... only as a TLS/gRPC tunnel`.

### CHG-WKR-005 - Authorized device boundary

- **Before:** The prototype uses session nonces.
- **After:** The device interface is ACL-restricted to administrators or a
  designated service identity. An authorized handle is trusted, but every
  IOCTL still validates version, size, direction, request ID, generation,
  state, and bounds. A nonce is not required.
- **Traceability:** User clarification: `if we ACL the interface ... nonce is
  not needed`.

### CHG-WKR-006 - Kernel-owned TCP/UDP lifecycle

- **Before:** Kernel flow lifecycle is not a product contract.
- **After:** The driver owns admission, mapping, connect, forwarding,
  association expiry, cancellation, and teardown for TCP and UDP. QUIC is
  treated as UDP payload traffic.
- **Traceability:** `USER-REQUEST: full flow tracking state machine`.

### CHG-WKR-007 - Failure isolation

- **Before:** Individual failures may be coupled to process/driver lifetime.
- **After:** Abort, missing mapping, mapping error, WSK error, connect/send/
  receive failure, cancellation, or per-flow resource failure affects only the
  affected flow/request. The driver and agent continue serving other flows.
- **Traceability:** `USER-REQUEST: should not stop ... continue with the other
  connections`.

### CHG-WKR-008 - Low-memory resilience

- **Before:** No complete low-memory safety contract exists.
- **After:** Checked nonpaged allocations, bounded operation buffers, and
  explicit unwind paths prevent bugcheck/panic. Resource exhaustion fails only
  the affected operation.
- **Traceability:** `USER-REQUEST: resilient to out of memory conditions`.

### CHG-WKR-009 - Synchronization and IRQL discipline

- **Before:** Synchronization and execution-level rules are unspecified.
- **After:** Shared kernel state uses OS-provided `KSPIN_LOCK` or `PUSH_LOCK`
  primitives only. Lock domains, hierarchy, and DISPATCH/PASSIVE rules are
  documented and enforced.
- **Traceability:** User clarification: `KSPIN_LOCK or PUSH_LOCK` and
  `DISPATCH vs PASSIVE`.

### CHG-WKR-010 - Replaceable transition telemetry

- **Before:** State transitions have implementation-specific diagnostics.
- **After:** Every accepted or rejected state transition emits through a
  replaceable telemetry sink, initially backed by `DbgPrintEx`.
- **Traceability:** User clarification: `All state transitions should expose
  telemetry`.

## Stable Requirements

### REQ-WKR-001 - Exclusive data-plane mode

The build MUST select exactly one of the existing user-mode data path and the
kernel-relay data path. Both MUST NOT be compiled into or activated by one
binary. Existing user-mode behavior remains unchanged.

### REQ-WKR-002 - Exact WSK tuple and listener behavior

The driver MUST own configurable IPv4/IPv6 TCP and UDP listeners and construct
the exact observed synthetic 5-tuple, including family and protocol. Outbound
sockets MUST use OS-selected local endpoints and MUST NOT impersonate the
original source.

### REQ-WKR-003 - Driver-owned `GetMapping`

The driver MUST construct, issue, validate, and apply every existing
`GetMapping` protobuf request/response. A response MUST match the requesting
flow's family and protocol and contain a valid original destination. Missing,
malformed, mismatched, or unavailable mappings MUST fail closed only for the
affected flow/datagram. No direct-forward fallback is permitted.

### REQ-WKR-004 - Concurrent correlated transport

The selected transport MUST support multiple outstanding resolutions. Each
request and completion MUST correlate by driver-generated request ID and flow
generation. Direct gRPC/TLS and opaque tunnel transports MUST share this
driver-owned state machine.

### REQ-WKR-005 - Authorized and opaque user mode

The device interface MUST be ACL-restricted. Authorized IOCTLs MUST reject
malformed, stale, oversized, or invalid-state messages without corrupting
state. In tunnel mode, user mode MUST only transport opaque protobuf bytes,
manage the authenticated channel, and correlate replies; it MUST NOT interpret
mapping status, choose destinations, cache mappings, own flow tables, or
perform state transitions.

### REQ-WKR-006 - TCP/UDP forwarding and teardown

TCP MUST forward both directions, preserve supported half-close behavior, and
close both peers on fatal failure. UDP MUST maintain per-flow associations
keyed by the complete synthetic tuple and client identity, route replies only
to that client, and expire idle associations. QUIC receives UDP treatment
without TCP-state assumptions.

### REQ-WKR-007 - Failure containment and continuity

The driver and agent MUST remain alive after individual flow aborts, mapping
misses, control-plane failures, WSK failures, connect/send/receive failures,
or cancellations. Existing mapped flows may continue during control-plane loss;
new unresolved flows fail closed. Every affected flow releases its resources.

### REQ-WKR-008 - Low-memory safety

Every allocation, MDL, IRP, queue, socket, and WSK operation MUST have an
explicit failure path. Nonpaged allocations and operation buffers MUST be
bounded and checked. Oversized messages are rejected without truncation.
Resource exhaustion MUST NOT bugcheck, panic, dereference invalid memory, or
produce successful forwarding.

### REQ-WKR-009 - Driver-owned lifecycle and unload

The driver MUST own canonical flow identity, generations, lifecycle state,
socket/buffer ownership, deadlines, cancellation, and teardown. Shutdown MUST
stop admission, cancel pending resolutions, close resources, quiesce callbacks,
and unload within a bounded drain period without use-after-free or indefinite
wait.

### REQ-WKR-010 - Platform and validation scope

Windows x64 is the first implementation target. ARM64 compatibility MUST be
preserved and separately validated. Host-independent tests and gated Windows
integration tests MUST cover positive forwarding, concurrency, malformed
IOCTLs, mapping failures, resource failures, cancellation, and unload.

### REQ-WKR-011 - Synchronization and IRQL

Kernel shared state MUST use only OS-provided `KSPIN_LOCK` and `PUSH_LOCK`
primitives. Every state domain MUST document its lock and acquisition order.
No lock inversion, recursive acquisition, illegal wait, pageable access at
elevated IRQL, or blocking operation while holding a spin lock is permitted.

### REQ-WKR-012 - Transition telemetry

Every accepted and rejected state transition MUST emit a privacy-safe event
containing correlation, generation, protocol, prior state, next state or
rejection, reason, and execution level. The initial sink is `DbgPrintEx`; the
sink is replaceable and its failure MUST NOT affect correctness.

## Non-goals

- Changing Linux BPF rewrite behavior or the existing `GetMapping` schema.
- Direct destination inference or plaintext fallback.
- Binding original source addresses or ports.
- Runtime listener reconfiguration.
- QUIC-specific parsing/state.
- Application-level flow-count caps; bounded safety buffers are not flow caps.
- ARM64 live validation in the first implementation.
