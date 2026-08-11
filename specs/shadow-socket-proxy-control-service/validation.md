<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Container Control Service Validation

## Identifier scope and uniqueness

Identifiers are scoped to this control-service specification artifact. Test
case definitions (`TC-*`) are unique within `validation.md`; `CHG-*`,
`REQ-*`, and `D-*` names remain references to their owning artifacts. New TLS
names that cross specification-artifact boundaries use globally unique,
artifact-qualified spellings. Existing unqualified `CHG-*` duplicates across
independent legacy specifications are baseline, not a result of the TLS
change.

## 1. Validation Strategy

Validation covers requirements REQ-CS-001 through REQ-CS-009 and invariants
INV-001 through INV-007. Kernel-dependent behavior is tested through the
`BpfBackend` test double and a small set of Linux integration tests against a
placeholder ELF. Transport tests cover the preserved TLS-PSK path and the rustls
mutual-certificate/pinned-leaf path. Rustls validation includes executable
tonic RPCs over authenticated h2 for TLS 1.2 and TLS 1.3; raw ALPN/byte tests
are not treated as gRPC validation. The concrete production paths are
Linux-gated: Aya/TC tests require a Linux kernel with BPF and TC capabilities,
while OpenSSL tests require a build with PSK support.

## 2. Test Cases

| ID | Requirement | Scenario | Expected result |
|---|---|---|---|
| TC-CS-001 | REQ-CS-001 | Build crate for Linux target | Build succeeds with documented features and no platform leakage |
| TC-CS-002 | REQ-CS-001 | Start with placeholder ELF and ABI v1 map | Service initializes backend and reports ABI/readiness |
| TC-CS-003 | REQ-CS-002 | Attach one interface | Ingress and egress are both owned and status is ready |
| TC-CS-004 | REQ-CS-002 | Attach multiple interfaces, fail one direction | All attachments from the transaction are rolled back; failure identifies location |
| TC-CS-005 | REQ-CS-002 | Repeat equivalent attach | Idempotent success without duplicate attachment |
| TC-CS-006 | REQ-CS-002 | Detach missing/already-detached interface | Safe repeat; any real backend failure remains visible |
| TC-CS-007 | REQ-CS-003 | List IPv4 TCP and IPv6 TCP mappings | Synthetic and original tuples round-trip exactly |
| TC-CS-008 | REQ-CS-003 | List UDP and QUIC-over-UDP mappings | Protocol and ports are preserved; no TCP state is invented |
| TC-CS-009 | REQ-CS-003 | Get existing mapping by exact synthetic tuple | Correct original tuple is returned |
| TC-CS-010 | REQ-CS-003 | Get missing mapping | `NOT_FOUND`, distinct from backend failure |
| TC-CS-011 | REQ-CS-003 | Backend map read failure during list | RPC fails with backend error; no success-shaped partial response |
| TC-CS-012 | REQ-CS-004 | Decode valid ABI v1 key/value | All fields, byte order, and timestamp decode correctly |
| TC-CS-013 | REQ-CS-004 | Decode unknown ABI version | Explicit ABI mismatch; entry is not interpreted |
| TC-CS-014 | REQ-CS-004 | Decode malformed length/address/state | Explicit malformed-entry result and status/log counter |
| TC-CS-015 | REQ-CS-004 | TCP state fixture covers SYN, SYN/ACK, ACK, FIN, RST | Each state is represented and survives map round-trip |
| TC-CS-019 | REQ-CS-005 | Retired control-service maintenance | No autonomous cleanup worker or maintenance policy remains in the service |
| TC-CS-020 | REQ-CS-006 | Enumerate typed flows | Bounded opaque-cursor pages return identity, generation, tuples, timestamps, and TCP lifecycle masks |
| TC-CS-021 | REQ-CS-006 | Generation-safe delete | Complete, absent, stale-generation, and partial outcomes preserve newer flow indexes |
| TC-CS-022 | REQ-CS-006 | Valid TLS-PSK client | Authenticated RPC succeeds |
| TC-CS-023 | REQ-CS-006 | Wrong PSK identity/secret | Request rejected; no service operation occurs |
| TC-CS-024 | REQ-CS-006 | Plaintext or unauthenticated client | Connection/RPC rejected |
| TC-CS-025 | REQ-CS-006 | Unsupported TLS-PSK backend configuration | Startup fails and readiness is false |
| TC-CS-026 | REQ-CS-007 | Valid multi-field config update | One revision publishes all fields atomically |
| TC-CS-027 | REQ-CS-007 | Zero, overflow, contradictory, or oversized values | Update rejected; prior revision remains |
| TC-CS-029 | REQ-CS-007 | Log-capacity reduction | New bounded capacity applies without unbounded allocation |
| TC-CS-030 | REQ-CS-008 | Pull records after valid cursor | Ordered records and next cursor returned |
| TC-CS-031 | REQ-CS-008 | Pull with cursor at current tail | Empty result, not an error |
| TC-CS-032 | REQ-CS-008 | Pull before oldest retained record | Explicit cursor-expired status |
| TC-CS-033 | REQ-CS-008 | Concurrent append and pull | No duplicate or reordered sequence values |
| TC-CS-035 | REQ-CS-003/005 | Mapping disappears between list and cleanup | No wrong tuple returned; delete is treated as already absent or explicit race |
| TC-CS-036 | REQ-CS-006/007 | Unauthorized config/attach while authorized read is active | Unauthorized mutation is rejected and authorized read remains isolated |
| TC-CS-037 | REQ-CS-005 | Packet/delete quiescence and guard failure | In-flight packet updates drain before observation verification; guard expiry and host commit atomically select abort or cleanup, and post-insertion failures remove or expire the guard without blackholing a later packet. |
| TC-CS-038 | REQ-CS-005 | Replaced generation and release repair | State-first cleanup does not remove an index or release capacity for a newer generation sharing the tuple; a release journal retries failed publication without double release. |
| TC-CS-039 | REQ-CS-007 | Concurrent attach and set-config | Serialization leaves the BPF map's runtime fields equal to the final published snapshot. |
| TC-CS-040 | REQ-CS-007 | Unrepresentable duration | A duration that cannot fit the fixed-width nanosecond ABI is rejected before publication or map write. |
| TC-CS-041 | REQ-CS-009 | Build each runnable binary with `tls-psk` | The existing OpenSSL TLS-PSK path remains available and no rustls path is selected. |
| TC-CS-042 | REQ-CS-009 | Build each runnable binary with `tls-rustls` | The build succeeds without OpenSSL and includes TLS 1.2/1.3 h2 transport support. |
| TC-CS-043 | REQ-CS-009 | Build with both TLS features | Compilation fails with an explicit mutually-exclusive feature diagnostic. |
| TC-CS-044 | REQ-CS-009 | Build and run each runnable binary without either TLS feature | `shadow-socket-proxy-control`, `shadow-socket-proxy-host`, and `shadow-socket-proxy-e2e-runner` each exit nonzero with the explicit `requires exactly one of the tls-psk or tls-rustls features` diagnostic; supporting library/test compilation remains allowed. |
| TC-CS-045 | REQ-CS-009 | Valid mutual self-signed PEM identities and matching pins | An authenticated tonic RPC succeeds over h2 with TLS 1.2 and TLS 1.3; raw ALPN/bytes are not used as the gRPC assertion. |
| TC-CS-046 | REQ-CS-009 | Wrong/malformed/normalized peer pin | Pin parsing or the authenticated tonic connection fails; a different certificate is never accepted. |
| TC-CS-047 | REQ-CS-009 | Expired, bad-signature, or wrong-key-usage peer certificate | Rustls/webpki rejects the peer even when the DER pin matches; hostname is not required. |
| TC-CS-048 | REQ-CS-009 | Duplicate CLI/environment TLS settings or mismatched private key | Startup/configuration fails before readiness and does not fall back to another transport. |
| TC-CS-049 | REQ-CS-006/REQ-CS-009 | Malformed, stalled, non-h2, and authenticated-failure TLS connections followed by a valid authenticated client | A PSK handshake without h2, PSK wrong credentials, and rustls wrong pinned-client credentials are rejected independently on the same running server; the listener and control service remain live/ready, the test double retains owned attachments with zero detach calls, and a subsequent authenticated tonic RPC succeeds. |

## 3. Property and Invariant Checks

- Tuple conversion is bijective for all IPv4/IPv6 address encodings used by the
  ABI.
- The control-service never autonomously deletes a flow; host-proxy owns cleanup
  policy and uses generation-safe typed deletion.
- A rustls handshake accepts only the exact pinned leaf DER and a valid
  signature/validity/key-usage result; it does not depend on a hostname.
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
- malformed, unauthenticated, non-h2, or stalled TLS handshakes are
  per-connection rejections; they MUST NOT terminate the listener or trigger
  control-service/BPF lifecycle shutdown, and later valid connections remain
  admissible.

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

TLS-mode validation additionally runs isolated Linux and Windows
`tls-rustls` checks for the control-service, host-proxy, and e2e-runner, plus
the shared rustls tests and authenticated tonic coverage. The `tls-psk`
artifact and Windows/WSL end-to-end path remain separate so the existing
OpenSSL behavior is not silently replaced. Both-feature rejection is checked
in PSK-capable jobs rather than through an all-features workspace gate.

The feature-neutral validation job builds and executes every TLS-selected
runnable binary without either feature, requiring a nonzero exit and the
explicit feature-selection diagnostic. Library and test targets continue to be
compiled through the feature-neutral workspace gates.

Linux-only BPF/TC integration tests MUST be feature- or environment-gated and
MUST fail clearly when required kernel capabilities or the placeholder ELF are
not available. On non-Linux hosts, the explicit unsupported compile path is
expected; the workspace checks remain green without pretending to provide TC
or TLS-PSK there.

Privileged live TC attach/link validation is a pre-existing,
Linux-environment-gated deferred item outside the TLS change scope. No
privileged integration test is added or represented as passing by this TLS
change. This deferral has no impact on the rustls/PSK verdict: those paths are
validated through the existing transport, feature-selection, and in-memory
service coverage, and no BPF attach/link behavior is changed.
