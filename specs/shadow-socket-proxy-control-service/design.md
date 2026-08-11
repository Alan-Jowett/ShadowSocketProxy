<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Container Control Service Design

## Identifier scope and uniqueness

Identifiers are scoped to this control-service specification artifact. Design
definitions (`D-*`) are unique within `design.md`; `CHG-*`, `REQ-*`, and
`TC-*` names are references to their owning sibling artifacts. New TLS names
that cross specification-artifact boundaries use globally unique,
artifact-qualified spellings. Existing unqualified `CHG-*` duplicates across
independent legacy specifications are baseline, not a result of the TLS
change.

## 1. Scope and Traceability

This design implements REQ-CS-001 through REQ-CS-009 from
`requirements.md`. The trace chain is:

```text
USER-REQUEST -> REQ-CS-* -> D-CS-* -> TC-CS-* -> implementation/test artifacts
```

Control-service traceability identifiers use the `REQ-CS-*`, `D-CS-*`, and
`TC-CS-*` namespaces so they remain distinct from the host-proxy and BPF
specifications.

The final BPF packet-rewriting program remains outside this change. The crate
integrates with a supplied ELF through a versioned ABI and a replaceable
backend.

## 2. Component Architecture

### D-CS-001 — Service process

The Linux Rust binary contains:

- `config`: validated immutable snapshots and atomic revision updates.
- `bpf`: `BpfBackend` trait plus the production ELF/TC implementation and an
  in-memory test double.
- `mapping`: versioned key/value ABI codecs and tuple conversion.
- `control`: authenticated gRPC service for lifecycle, mappings, status,
  configuration, and log pull.
- `logs`: bounded sequence ring with cursor validation.
- `lifecycle`: startup, readiness, cancellation, and owned-attachment cleanup.

The gRPC layer depends on traits rather than directly on kernel APIs so RPC
tests can exercise failures deterministically.

### D-CS-002 — Production BPF backend

The production backend loads the supplied ELF, locates the versioned mapping
hash map, and attaches the program to TC ingress and egress for every
interface in an attach command. The backend records ownership by service
instance and interface/direction.

An attach operation is a transaction:

1. Validate ELF path, interface names, ABI version, and requested directions.
2. Load the ELF and locate the required map/program symbols.
3. Attach ingress and egress for each interface.
4. On any failure, detach every attachment created by this operation.
5. Return a structured error containing the failed interface/direction.

Repeated attach of an equivalent owned attachment is success; conflicting
ownership is an explicit error. Detach removes only service-owned attachments.

The production implementation uses Aya 0.14 on Linux. It requires the
versioned symbols `ssp_flow_map_v1`, `ssp_tc_ingress_v1`, and
`ssp_tc_egress_v1`, keeps Aya program/link types inside the adapter, and
exposes only the `BpfBackend`/`LinuxTcAdapter` operations to the gRPC adapter.
Non-Linux builds retain an explicit unsupported adapter.

### D-CS-003 — Versioned mapping ABI

ABI version `1` uses a fixed, endian-defined representation:

- Key: address family, protocol number, source address, destination address,
  source port, destination port.
- Value: original key, `last_seen_ns` from a monotonic BPF clock, protocol
  flags, and TCP state.

Addresses are 16-byte fields; IPv4 values use IPv4-mapped representation.
Ports and integers are network byte order at the map boundary. Protocol flags
identify TCP, UDP, and QUIC-over-UDP. TCP state is an explicit bitset allowing
SYN, SYN/ACK, ACK, FIN, and RST to coexist when observed over a flow lifetime.
UDP and QUIC set activity/protocol flags but do not synthesize TCP states.

The ABI header includes a schema version. Unknown versions fail decoding and
are counted in status/logs rather than silently interpreted.

### D-CS-004 — Mapping consistency

List obtains a bounded snapshot by enumerating the backend map once and
decoding each entry. Point lookup performs an exact key lookup. Entries that
change or disappear between enumeration and response are reported using
per-entry status metadata; a backend failure fails the RPC. The service never
returns an original tuple for a different synthetic key.

### D-CS-006 — Runtime configuration

Configuration is held in an atomic `ArcSwap`-style snapshot with a monotonically
increasing revision. Set-config validates all fields against bounds and
cross-field rules before publishing one new snapshot. Attach and set-config
share a service-level transaction lock: attach writes the validated current
snapshot before readiness, while set-config writes its candidate BPF record
before publishing. They therefore cannot expose a newer snapshot with an older
runtime-map record.

The configuration includes dataplane idle TTL, TCP terminal grace, active-flow
capacity, listener/target settings, and bounded log capacity. Host maintenance
interval, scan batch, and retry policy are not control-service configuration.

### D-CS-007 — Host-owned flow lifecycle adapter

The authenticated control API exposes typed `EnumerateFlows` and `DeleteFlow`
operations for the host-proxy. Enumeration returns bounded, opaque-cursor
pages containing flow identity, generation, tuples, timestamps, and
directional TCP lifecycle masks. Deletion compares both identity and
generation before removing canonical state or tuple indexes and reports
complete, already-absent, stale-generation, or partial outcomes. Packet
updates use a shared in-flight map with an expiring, generation-keyed delete
guard; deletion waits for that section to drain, atomically commits against
packet-side guard expiry, and rechecks its observation before state-first
cleanup. Index removal verifies the current index value still names the
deleted generation. A persistent generation-addressed release journal lets
partial cleanup republish capacity release idempotently; BPF consumes a
journal entry exactly once. The service does not decide when a flow is stale,
retry partial cleanup, or maintain local UDP associations; those policies
remain host-proxy responsibilities.

### D-CS-008 — gRPC API

The protobuf contract includes:

- `Attach`: ELF path plus interface list; establishes ingress and egress.
- `Detach`: interface list or all service-owned attachments.
- `ListMappings`: bounded mapping page and read metadata.
- `GetMapping`: exact synthetic 5-tuple lookup.
- `EnumerateFlows` / `DeleteFlow`: typed host-owned flow lifecycle primitives.
- `GetStatus`: readiness, ABI, attachment, dataplane counters, and map maxima.
- `GetConfig` / `SetConfig`: revisioned atomic configuration.
- `PullLogs`: cursor, limit, records, next cursor, and cursor-expired error.
- `Health`: liveness/readiness response.

All RPCs use the same authenticated server policy. Resource exhaustion,
invalid arguments, not-found, cursor-expired, ABI mismatch, backend failure,
and unauthenticated requests map to distinct gRPC status codes.

### D-CS-009 — Feature-selected TLS transport

The endpoint is TCP gRPC over one compile-time-selected transport. The
`tls-psk` feature uses the existing OpenSSL adapter and its configured PSK
identity/secret callbacks. The `tls-rustls` feature uses a shared rustls
adapter. The features are mutually exclusive and neither is default; a
runnable binary built without a feature fails before serving.

The rustls adapter loads a local PEM certificate chain and private key and
requires a normalized SHA-256 peer-leaf pin. Both sides present their
self-signed certificate and verify the peer's exact DER leaf hash before
validating it with rustls/webpki as a pinned trust anchor. Validation covers
certificate signature, validity, and applicable key-usage checks; hostname
matching is intentionally omitted. TLS 1.2 and 1.3 are enabled and h2 is
required by ALPN. The adapter feeds handshaken streams to tonic with
`serve_with_incoming` and custom connectors. Executable validation uses
authenticated tonic RPCs over those streams for TLS 1.2 and TLS 1.3; raw ALPN
or byte exchanges are only transport-level checks. Rustls builds have no
OpenSSL dependency.

The three rustls settings are startup-only CLI/environment pairs:
`--tls-cert-file`/`SSP_TLS_CERT_FILE`,
`--tls-key-file`/`SSP_TLS_KEY_FILE`, and
`--tls-peer-cert-sha256`/`SSP_TLS_PEER_CERT_SHA256`. A duplicate CLI-plus-
environment value or malformed/missing file or pin is rejected at startup;
a peer handshake pin mismatch is rejected per connection. Startup
configuration and bind failures remain fatal, while post-startup handshake
failures are isolated to the connection that failed.
Each listener stores one peer-leaf pin, so multiple clients connecting to the
same listener MUST share the pinned client certificate. The Windows/WSL E2E
driver uses one client identity for both the host proxy and runner; supporting
multiple peer pins is outside this change.
The incoming stream preserves listener-accept errors for lifecycle handling and
drops only failures after a socket is accepted, before tonic sees them. This
includes malformed, unauthenticated, non-h2, and timed-out handshakes. Those
per-connection rejections do not terminate the listener, stop the control
service, or trigger BPF lifecycle cleanup, and there is no plaintext or
cross-mode fallback. Full-server PSK and rustls tests exercise a wrong
credential or pinned-client failure on the running listener before a valid
authenticated tonic RPC; they start with an owned in-memory attachment and
assert readiness, retained ownership, and zero backend detach calls.

Each runnable TLS-selected binary also has an explicit no-feature startup
failure. CI executes all three binaries built without either TLS feature and
requires their nonzero feature-selection diagnostics while feature-neutral
library and test compilation remains supported.

### D-CS-010 — Log synchronization

The bounded log ring assigns a strictly increasing sequence to each record.
`PullLogs(cursor, limit)` returns records with sequence greater than cursor.
If the cursor is older than the oldest retained sequence, the RPC returns
`FAILED_PRECONDITION` with a cursor-expired detail. Capacity updates retain
the newest records and invalidate cursors that no longer exist.

### D-CS-011 — Lifecycle and shutdown

Startup validates configuration, prepares the TLS endpoint, and initializes
the BPF backend before reporting readiness. Shutdown stops accepting RPCs,
attempts owned detachment, and reports cleanup failures. Host-proxy owns
maintenance cancellation and flow cleanup. A failed post-accept TLS handshake
is not a shutdown signal; a listener-accept error remains a service-level
transport failure, alongside explicit shutdown, for lifecycle cleanup.

## 3. Invariants

| ID | Invariant |
|---|---|
| INV-001 | A successful attach means required ingress and egress attachments exist for every requested interface. |
| INV-002 | A mapping response preserves the exact synthetic-to-original tuple association. |
| INV-003 | The control-service never autonomously deletes flows or applies host maintenance policy. |
| INV-004 | Runtime configuration is published atomically as one revision. |
| INV-005 | Authentication is required for every RPC, including health/status. |
| INV-006 | Service shutdown does not claim clean teardown when owned detach fails. |
| INV-007 | Log cursors are monotonic and cursor expiry is explicit. |

## 4. Impact Map

| Requirement | Design | Validation | Implementation surfaces |
|---|---|---|---|
| REQ-CS-001 | D-CS-001, D-CS-002, D-CS-003 | TC-CS-001, TC-CS-002 | crate, ABI module, backend trait |
| REQ-CS-002 | D-CS-002, D-CS-011 | TC-CS-003–TC-CS-006 | attach/detach RPC, TC backend |
| REQ-CS-003 | D-CS-003, D-CS-004, D-CS-007 | TC-CS-007–TC-CS-011 | protobuf, mapping service |
| REQ-CS-004 | D-CS-003 | TC-CS-012–TC-CS-015 | ABI codec, fixtures |
| REQ-CS-005 | Retired by issue #12 | Host-proxy maintenance validation | no control-service worker |
| REQ-CS-006 | D-CS-007, D-CS-009 | TC-CS-022–TC-CS-025, TC-CS-049 | TLS adapter, auth interceptor, per-connection liveness |
| REQ-CS-009 | D-CS-009 | TC-CS-041–TC-CS-049 | feature selection, rustls adapter, CLI/env startup, authenticated tonic, and handshake-liveness tests |
| REQ-CS-007 | D-CS-006, D-CS-008 | TC-CS-026–TC-CS-029 | config store/RPC |
| REQ-CS-008 | D-CS-010 | TC-CS-030–TC-CS-033 | log ring/PullLogs |

## 5. Explicit No-Impact Decisions

- The host shadow proxy data path is unchanged; it consumes mapping RPCs but is
  not implemented here.
- Packet tuple rewriting remains in the supplied BPF ELF.
- No kernel-derived entry age is used; `last_seen_ns` is authoritative.
- QUIC receives UDP activity treatment and no TCP-state interpretation.
