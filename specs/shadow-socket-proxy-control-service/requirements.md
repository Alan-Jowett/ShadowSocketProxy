<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Container Control Service Requirements

## Identifier scope and uniqueness

This control-service specification set is the owning artifact for the
requirements, design, validation, and audit documents in this directory.
`CHG-*` and `REQ-*` definitions are owned by this requirements artifact,
`D-*` definitions by `design.md`, and `TC-*` definitions by `validation.md`.
Each identifier MUST be defined only once within its owning artifact;
references may repeat. New TLS identifiers referenced from another
specification artifact MUST use an artifact-qualified name that is globally
unique across `specs/`, and every cross-artifact reference MUST preserve that
qualified spelling. Existing unqualified `CHG-*` duplicates in independent
legacy specifications are baseline and were not introduced by the TLS change.

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

### CHG-005 — Retired control-service maintenance

The original control-service-owned maintenance worker and its policy were
retired by issue #12. Host-proxy now owns maintenance scheduling, policy,
retry, and flow deletion decisions; the control-service exposes typed flow
enumeration and deletion adapters only.

### CHG-006 — Host control and runtime configuration API

- **Before:** No authenticated host control endpoint or runtime service
  configuration exists.
- **After:** A TCP gRPC endpoint secured with the selected TLS
  policy exposes attach, detach, mapping, health/status, and configuration
  operations. Dataplane idle TTL, TCP terminal grace, active-flow capacity,
  and bounded log capacity can be updated through authenticated configuration
  RPCs and are applied atomically after validation. Host maintenance policy is
  configured only by host-proxy.
- **Traceability:** User clarifications: host sends attach/detach commands;
  TCP endpoint secured with the selected TLS policy; all operational values
  are exposed through gRPC and are runtime-configurable.

### CHG-007 — Optional bounded log synchronization

- **Before:** No control-service log synchronization contract exists.
- **After:** The service optionally retains a bounded log sequence and exposes
  an authenticated pull RPC using a monotonic cursor. Clients can detect
  cursor expiry explicitly rather than receiving an ambiguous partial result.
- **Traceability:** User clarification: host process can pull an optional log
  sync using a monotonic cursor, bounded retention, and explicit
  cursor-expired errors.

### CHG-CS-TLS-001 — Feature-selected rustls certificate pinning

- **Before:** Runnable control-service, host-proxy, and e2e-runner binaries
  expose only the OpenSSL TLS-PSK transport.
- **After:** Each runnable binary selects exactly one mutually exclusive
  `tls-psk` or `tls-rustls` feature; neither is default. The rustls mode uses
  TCP gRPC over h2 with TLS 1.2/1.3, mutual self-signed PEM identities, and a
  normalized SHA-256 pin of the peer leaf certificate DER bytes. Rustls
  validates the pinned leaf's signature, validity, and key usage without a
  hostname requirement, and does not require OpenSSL.
- **Traceability:** `USER-REQUEST: Implement the approved rustls
  certificate-pinning mode ...`

## Stable Requirements

### REQ-CS-001 — Linux Rust crate

The deliverable MUST include a buildable Rust crate targeting Linux for the
container control service. The crate MUST isolate platform/BPF operations
behind testable service components and MUST include a placeholder BPF ELF
integration contract.

**Acceptance criteria**

- The crate has a documented Linux build/runtime target.
- The BPF backend can be replaced or exercised through a test double.
- The placeholder ELF/map ABI is versioned and documented.

**Invariant impact:** Preserves separation between packet processing in BPF and
control in user mode.

### REQ-CS-002 — TC attachment lifecycle

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

### REQ-CS-003 — Mapping read API

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

### REQ-CS-004 — Versioned mapping ABI

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

### REQ-CS-005 — Retired control-service maintenance

This former requirement is retired by issue #12. Host-proxy owns stale-flow
policy and cleanup; the control-service provides typed, generation-safe flow
enumeration and deletion operations. The adapter MUST freeze a requested flow
generation, wait for packet-side in-flight updates to quiesce, atomically
commit against guard expiry, and verify the enumerated observation before
deletion. It MUST remove indexes only while they still encode that generation,
persist capacity release before deleting canonical state, and publish that
generation-addressed release idempotently until BPF consumes it once. It MUST
remove or safely expire every deletion guard and outcome on all outcomes.

### REQ-CS-006 — Authenticated host control

The service MUST expose a TCP gRPC endpoint protected by the selected TLS
policy. All mutating and inspection RPCs MUST require successful
authentication. The existing OpenSSL TLS-PSK behavior is preserved under
`tls-psk`; rustls certificate pinning is defined by REQ-CS-009. The service MUST
report incompatibility if the selected transport cannot be constructed.
Malformed, unauthenticated, or stalled TLS connections MUST be rejected
individually after the listener starts; a failed handshake MUST NOT terminate
the listener, stop the control service, or trigger BPF lifecycle cleanup.

**Acceptance criteria**

- Unauthenticated or incorrectly authenticated requests are rejected.
- Attach, detach, mapping, status, and configuration calls share the same
  authenticated endpoint policy.
- TLS configuration failures prevent a misleading ready state.
- After malformed, unauthenticated, or stalled connection attempts, a later
  valid authenticated RPC succeeds without restarting the service.

**Invariant impact:** Prevents unauthorized BPF attachment, map disclosure, or
  runtime policy changes.

### REQ-CS-007 — Atomic runtime configuration

The service MUST expose authenticated get/set configuration RPCs for dataplane
idle TTL, TCP terminal grace, active-flow capacity, listener/target settings,
and bounded log capacity. Host maintenance interval, scan batch size, and
retry policy are host-proxy settings, not control-service settings. Invalid
values MUST be rejected without partially applying the update.

**Acceptance criteria**

- A valid update becomes visible as one coherent configuration revision.
- Invalid, zero, overflowing, or internally contradictory values are rejected.
- Concurrent dataplane configuration writes observe either the old or new
  complete revision, never a mixture.
- Concurrent attach and configuration transactions leave the BPF runtime map
  consistent with the revision published to readers.

**Invariant impact:** Preserves predictable maintenance and resource behavior
under concurrent host control.

### REQ-CS-008 — Optional bounded log pull

The service MUST optionally retain service log records in bounded storage and
expose a pull RPC using a monotonic cursor. If a cursor falls outside retained
history, the service MUST return an explicit cursor-expired error.

**Acceptance criteria**

- A client can pull records after a cursor and advance its cursor.
- Retention is bounded by configured capacity.
- Cursor expiry is distinguishable from an empty result and transport failure.

**Invariant impact:** Provides observable control-plane synchronization without
  unbounded memory growth.

### REQ-CS-009 — Explicit TLS transport selection and rustls pinning

The runnable control-service, host-proxy, and e2e-runner binaries MUST require
exactly one of the mutually exclusive `tls-psk` or `tls-rustls` features;
neither feature is default. `tls-psk` MUST preserve the existing OpenSSL
TLS-PSK behavior. `tls-rustls` MUST provide TCP gRPC over h2 with TLS 1.2 and
TLS 1.3, mutual self-signed PEM certificate/key authentication, and a
normalized SHA-256 pin over the peer leaf certificate's exact DER bytes.
Normalization is case-insensitive and accepts an optional `0x` prefix plus
whitespace, `:`, or `-` separators.

Rustls peer verification MUST use the pinned leaf as its trust anchor while
validating certificate signature, validity, and appropriate key usage. It MUST
not require hostname matching. The startup-only settings
`--tls-cert-file`/`SSP_TLS_CERT_FILE`,
`--tls-key-file`/`SSP_TLS_KEY_FILE`, and
`--tls-peer-cert-sha256`/`SSP_TLS_PEER_CERT_SHA256` MUST reject missing,
malformed, or duplicate CLI-plus-environment values and MUST never fall back
to another transport or plaintext.

Once startup succeeds, malformed TLS input, peer-authentication failures,
missing h2 negotiation, and handshake timeouts are per-connection rejections.
They MUST NOT propagate as a terminal incoming-stream error or shut down the
control service; only transport configuration, bind, or explicit service
shutdown failures may end the server lifecycle.

The runnable control-service, host-proxy, and e2e-runner binaries built without
either TLS feature MUST exit nonzero with an explicit feature-selection
diagnostic. Supporting library and test targets MAY still compile in that
feature-neutral configuration.

**Invariant impact:** Prevents an ambiguous build or runtime configuration
from weakening control-plane authentication, while leaving the data plane
unchanged.

## Non-Goals

- Implementing the final packet-rewriting BPF logic; the first deliverable uses
  a placeholder ELF/map contract.
- Implementing the host shadow proxy or changing its forwarding behavior.
- Assuming QUIC-specific connection state beyond UDP tuple activity and
  last-seen tracking.
- Introducing a new packet interception mechanism other than TC.

## Open Design Constraints

- The approved transport alternatives are OpenSSL TLS-PSK and rustls pinned
  mutual TLS. The alternatives are compile-time selected and never combined
  in one runnable binary.
- The versioned ABI MUST define byte order, address encoding, clock source,
  state encoding, and map pin/ownership behavior.
