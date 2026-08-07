<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Container Control Service Design

## 1. Scope and Traceability

This design implements REQ-001 through REQ-008 from
`requirements.md`. The trace chain is:

```text
USER-REQUEST -> REQ-* -> D-* -> TC-* -> implementation/test artifacts
```

The final BPF packet-rewriting program remains outside this change. The crate
integrates with a supplied ELF through a versioned ABI and a replaceable
backend.

## 2. Component Architecture

### D-001 — Service process

The Linux Rust binary contains:

- `config`: validated immutable snapshots and atomic revision updates.
- `bpf`: `BpfBackend` trait plus the production ELF/TC implementation and an
  in-memory test double.
- `mapping`: versioned key/value ABI codecs and tuple conversion.
- `maintenance`: periodic bounded scan/delete worker.
- `control`: authenticated gRPC service for lifecycle, mappings, status,
  configuration, and log pull.
- `logs`: bounded sequence ring with cursor validation.
- `lifecycle`: startup, readiness, cancellation, and owned-attachment cleanup.

The gRPC layer depends on traits rather than directly on kernel APIs so RPC
tests can exercise failures deterministically.

### D-002 — Production BPF backend

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
exposes only the `BpfBackend`/`LinuxTcAdapter` operations to the gRPC and
maintenance layers. Non-Linux builds retain an explicit unsupported adapter.

### D-003 — Versioned mapping ABI

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

### D-004 — Mapping consistency

List obtains a bounded snapshot by enumerating the backend map once and
decoding each entry. Point lookup performs an exact key lookup. Entries that
change or disappear between enumeration and response are reported using
per-entry status metadata; a backend failure fails the RPC. The service never
returns an original tuple for a different synthetic key.

### D-005 — Maintenance worker

A cancellable Tokio task runs at the configured cleanup interval. Each cycle
scans at most `map_scan_batch` entries, compares `now_monotonic_ns -
last_seen_ns` against `idle_ttl`, and deletes only entries proven idle.

The worker records scanned, retained, deleted, decode-failed, read-failed, and
delete-failed counts. It continues after independent entry errors. A clock
regression or future timestamp is retained and surfaced as an anomaly.

### D-006 — Runtime configuration

Configuration is held in an atomic `ArcSwap`-style snapshot with a monotonically
increasing revision. Set-config validates all fields against bounds and
cross-field rules before publishing one new snapshot. Maintenance reads one
snapshot at cycle start, so a cycle observes a coherent revision.

The configuration includes:

- cleanup interval;
- idle TTL;
- map scan batch size;
- bounded log capacity.

### D-007 — gRPC API

The protobuf contract includes:

- `Attach`: ELF path plus interface list; establishes ingress and egress.
- `Detach`: interface list or all service-owned attachments.
- `ListMappings`: bounded mapping page and read metadata.
- `GetMapping`: exact synthetic 5-tuple lookup.
- `GetStatus`: readiness, ABI, attachment, maintenance, and error counters.
- `GetConfig` / `SetConfig`: revisioned atomic configuration.
- `PullLogs`: cursor, limit, records, next cursor, and cursor-expired error.
- `Health`: liveness/readiness response.

All RPCs use the same authenticated server policy. Resource exhaustion,
invalid arguments, not-found, cursor-expired, ABI mismatch, backend failure,
and unauthenticated requests map to distinct gRPC status codes.

### D-008 — TLS-PSK transport

The endpoint is TCP gRPC over a TLS-PSK-capable transport adapter. The
implementation MUST use a TLS stack that supports configured PSK identity and
secret callbacks; it MUST fail startup if the requested mode cannot be
constructed. The PSK is loaded from protected deployment configuration and
never returned by an RPC or logged.

Because common Rust gRPC defaults do not expose TLS-PSK, the transport uses
OpenSSL 0.10 with `tokio-openssl`. The server restricts negotiation to TLS 1.2
PSK cipher `PSK-AES256-GCM-SHA384`, selects h2 through ALPN, and feeds
handshaken streams to tonic with `serve_with_incoming`. The adapter is the
only component permitted to depend on OpenSSL; builds without PSK support fail
startup rather than falling back to metadata authentication, plaintext, or
mTLS.

### D-009 — Log synchronization

The bounded log ring assigns a strictly increasing sequence to each record.
`PullLogs(cursor, limit)` returns records with sequence greater than cursor.
If the cursor is older than the oldest retained sequence, the RPC returns
`FAILED_PRECONDITION` with a cursor-expired detail. Capacity updates retain
the newest records and invalidate cursors that no longer exist.

### D-010 — Lifecycle and shutdown

Startup validates configuration, prepares the TLS endpoint, initializes the
BPF backend, and starts maintenance before reporting readiness. Shutdown
cancels maintenance, stops accepting RPCs, attempts owned detachment, flushes
status/log counters, and reports cleanup failures.

## 3. Invariants

| ID | Invariant |
|---|---|
| INV-001 | A successful attach means required ingress and egress attachments exist for every requested interface. |
| INV-002 | A mapping response preserves the exact synthetic-to-original tuple association. |
| INV-003 | Only idle entries are deleted; active or anomalous future-timestamp entries are retained. |
| INV-004 | Runtime configuration is published atomically as one revision. |
| INV-005 | Authentication is required for every RPC, including health/status. |
| INV-006 | Service shutdown does not claim clean teardown when owned detach fails. |
| INV-007 | Log cursors are monotonic and cursor expiry is explicit. |

## 4. Impact Map

| Requirement | Design | Validation | Implementation surfaces |
|---|---|---|---|
| REQ-001 | D-001, D-002, D-003 | TC-001, TC-002 | crate, ABI module, backend trait |
| REQ-002 | D-002, D-010 | TC-003–TC-006 | attach/detach RPC, TC backend |
| REQ-003 | D-003, D-004, D-007 | TC-007–TC-011 | protobuf, mapping service |
| REQ-004 | D-003 | TC-012–TC-015 | ABI codec, fixtures |
| REQ-005 | D-005 | TC-016–TC-021 | maintenance worker |
| REQ-006 | D-007, D-008 | TC-022–TC-025 | TLS adapter, auth interceptor |
| REQ-007 | D-006, D-007 | TC-026–TC-029 | config store/RPC |
| REQ-008 | D-009 | TC-030–TC-033 | log ring/PullLogs |

## 5. Explicit No-Impact Decisions

- The host shadow proxy data path is unchanged; it consumes mapping RPCs but is
  not implemented here.
- Packet tuple rewriting remains in the supplied BPF ELF.
- No kernel-derived entry age is used; `last_seen_ns` is authoritative.
- QUIC receives UDP activity treatment and no TCP-state interpretation.
