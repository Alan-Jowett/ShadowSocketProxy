<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Container Control Service Validation

## 1. Validation Strategy

Validation covers requirements REQ-001 through REQ-008 and invariants
INV-001 through INV-007. Kernel-dependent behavior is tested through the
`BpfBackend` test double and a small set of Linux integration tests against a
placeholder ELF. Transport tests use an ephemeral TCP endpoint and invalid or
valid TLS-PSK credentials. The concrete production paths are Linux-gated:
Aya/TC tests require a Linux kernel with BPF and TC capabilities, while
OpenSSL tests require a build with PSK support.

## 2. Test Cases

| ID | Requirement | Scenario | Expected result |
|---|---|---|---|
| TC-001 | REQ-001 | Build crate for Linux target | Build succeeds with documented features and no platform leakage |
| TC-002 | REQ-001 | Start with placeholder ELF and ABI v1 map | Service initializes backend and reports ABI/readiness |
| TC-003 | REQ-002 | Attach one interface | Ingress and egress are both owned and status is ready |
| TC-004 | REQ-002 | Attach multiple interfaces, fail one direction | All attachments from the transaction are rolled back; failure identifies location |
| TC-005 | REQ-002 | Repeat equivalent attach | Idempotent success without duplicate attachment |
| TC-006 | REQ-002 | Detach missing/already-detached interface | Safe repeat; any real backend failure remains visible |
| TC-007 | REQ-003 | List IPv4 TCP and IPv6 TCP mappings | Synthetic and original tuples round-trip exactly |
| TC-008 | REQ-003 | List UDP and QUIC-over-UDP mappings | Protocol and ports are preserved; no TCP state is invented |
| TC-009 | REQ-003 | Get existing mapping by exact synthetic tuple | Correct original tuple is returned |
| TC-010 | REQ-003 | Get missing mapping | `NOT_FOUND`, distinct from backend failure |
| TC-011 | REQ-003 | Backend map read failure during list | RPC fails with backend error; no success-shaped partial response |
| TC-012 | REQ-004 | Decode valid ABI v1 key/value | All fields, byte order, and timestamp decode correctly |
| TC-013 | REQ-004 | Decode unknown ABI version | Explicit ABI mismatch; entry is not interpreted |
| TC-014 | REQ-004 | Decode malformed length/address/state | Explicit malformed-entry result and status/log counter |
| TC-015 | REQ-004 | TCP state fixture covers SYN, SYN/ACK, ACK, FIN, RST | Each state is represented and survives map round-trip |
| TC-016 | REQ-005 | Active entry inside TTL | Entry retained |
| TC-017 | REQ-005 | Idle entry beyond TTL | Entry deleted and counted |
| TC-018 | REQ-005 | Future timestamp/clock regression | Entry retained and anomaly surfaced |
| TC-019 | REQ-005 | Delete failure for one entry | Failure counted/logged; other candidates still processed |
| TC-020 | REQ-005 | Scan exceeds batch size | Cycle stops at configured bound and next cycle can continue |
| TC-021 | REQ-005 | Re-run cleanup after deletion | No duplicate success or inconsistent state |
| TC-022 | REQ-006 | Valid TLS-PSK client | Authenticated RPC succeeds |
| TC-023 | REQ-006 | Wrong PSK identity/secret | Request rejected; no service operation occurs |
| TC-024 | REQ-006 | Plaintext or unauthenticated client | Connection/RPC rejected |
| TC-025 | REQ-006 | Unsupported TLS-PSK backend configuration | Startup fails and readiness is false |
| TC-026 | REQ-007 | Valid multi-field config update | One revision publishes all fields atomically |
| TC-027 | REQ-007 | Zero, overflow, contradictory, or oversized values | Update rejected; prior revision remains |
| TC-028 | REQ-007 | Concurrent maintenance and config update | Each maintenance cycle observes one complete revision |
| TC-029 | REQ-007 | Log-capacity reduction | New bounded capacity applies without unbounded allocation |
| TC-030 | REQ-008 | Pull records after valid cursor | Ordered records and next cursor returned |
| TC-031 | REQ-008 | Pull with cursor at current tail | Empty result, not an error |
| TC-032 | REQ-008 | Pull before oldest retained record | Explicit cursor-expired status |
| TC-033 | REQ-008 | Concurrent append and pull | No duplicate or reordered sequence values |
| TC-034 | REQ-002/005 | Shutdown with active maintenance and attachments | Maintenance cancels; detach is attempted; failures are reported |
| TC-035 | REQ-003/005 | Mapping disappears between list and cleanup | No wrong tuple returned; delete is treated as already absent or explicit race |
| TC-036 | REQ-006/007 | Unauthorized config/attach while authorized read is active | Unauthorized mutation is rejected and authorized read remains isolated |

## 3. Property and Invariant Checks

- Tuple conversion is bijective for all IPv4/IPv6 address encodings used by the
  ABI.
- Maintenance never deletes an entry with `now - last_seen < idle_ttl`.
- Configuration revisions are strictly increasing and snapshots are internally
  consistent.
- Attachment ownership prevents detaching another service instance's links.
- Every emitted log sequence is greater than the preceding sequence.
- Every successful lifecycle response satisfies INV-001 and INV-006.

## 4. Failure Semantics

The implementation MUST distinguish:

- invalid request (`INVALID_ARGUMENT`);
- unauthenticated request (`UNAUTHENTICATED`);
- unauthorized/forbidden operation (`PERMISSION_DENIED`);
- missing mapping (`NOT_FOUND`);
- expired log cursor (`FAILED_PRECONDITION`);
- unsupported ABI or TLS capability (`FAILED_PRECONDITION`/startup failure);
- backend/kernel failure (`INTERNAL` or explicit unavailable status);
- resource limit exhaustion (`RESOURCE_EXHAUSTED`).

No test may accept an empty successful response when the backend operation
failed.

## 5. Validation Commands

The implementation phase will use only repository-supported commands discovered
from the created crate manifests. At minimum, the targeted matrix is expected
to include:

```text
cargo fmt --check
cargo check
cargo test
```

Linux-only BPF/TC integration tests MUST be feature- or environment-gated and
MUST fail clearly when required kernel capabilities or the placeholder ELF are
not available. On non-Linux hosts, the explicit unsupported compile path is
expected; the workspace checks remain green without pretending to provide TC
or TLS-PSK there.
