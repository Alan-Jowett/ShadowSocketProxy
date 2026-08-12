<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Control Service Specification Audit

## Scope

This audit covers the approved requirements, design, and validation artifacts
for REQ-CS-001 through REQ-CS-009, including the feature-selected TLS matrix.

## Identifier audit basis

CHG/REQ/D/TC identifiers are scoped to their owning specification artifact and
must be unique within that artifact; references may repeat. New TLS IDs that
cross artifact boundaries use globally unique, artifact-qualified names,
including `CHG-CS-TLS-001`, `CHG-HP-TLS-001`, `CHG-CI-TLS-001`,
`REQ-CS-009`, `REQ-CI-009`, `D-CS-009`, `TC-CS-041`–`TC-CS-049`,
`TC-HP-TLS-001`–`TC-HP-TLS-004`, and `TC-CI-011`–`TC-CI-014`.
Existing unqualified CHG duplicates across independent legacy specifications
are baseline and were not introduced by this TLS change.

The privileged live TC attach/link check remains a pre-existing,
Linux-environment-gated deferred item outside the TLS scope. It has no impact
on this audit because the TLS evidence uses transport-level, authenticated
tonic, feature-selection, and in-memory ownership coverage without changing
BPF attach/link behavior; no privileged integration test is being added or
claimed.

## Findings

| ID | Category | Severity | Evidence | Impact | Confidence | Remediation |
|---|---|---|---|---|---|---|
| F-001 | D1 traceability | None | Every REQ appears in the design impact map and validation cases | No missing upstream/downstream link found | High | None |
| F-002 | D2 completeness | None | D-CS-009 selects mutually exclusive OpenSSL TLS-PSK or rustls pinned mutual TLS; TC-CS-045 uses authenticated tonic RPCs for TLS 1.2/1.3, TC-CS-049 covers non-h2 and wrong-credential/pin rejection followed by authenticated liveness and ownership, while TC-CS-041–TC-CS-044 and TC-CS-048 cover feature/startup failures. The OpenSSL-capable Linux artifact job also runs the control-service TLS-PSK tests. | No unresolved transport selection or unsupported gRPC claim remains | High | None |
| F-003 | D3 contradiction | None | D-CS-003 explicitly limits TCP states to TCP and treats QUIC as UDP activity | Avoids unsupported QUIC state assumptions | High | None |
| F-004 | D4 failure semantics | None | Validation distinguishes invalid input, auth failure, not-found, cursor expiry, ABI mismatch, and backend failure | Prevents success-shaped silent failures | High | None |
| F-005 | D5 invariant coverage | None | INV-001 through INV-007 are exercised by positive, negative, concurrent, teardown, authenticated tonic, certificate-verification, and full-server ownership/liveness cases that retain attachments and observe zero cleanup calls after auth failures | Core tuple, lifecycle, cleanup, auth, and cursor invariants are covered | High | None |
| F-006 | D6 scope creep | None | Host proxy data path and final BPF packet rewriting are explicitly no-impact/non-goal items | Keeps implementation bounded to control service | High | None |
| F-007 | D7 acceptance quality | None | Validation includes malformed ABI, attachment rollback, stale/future timestamps, concurrency, shutdown, duplicate CLI/environment settings, all-runnable-binary no-feature smoke diagnostics, the executable `crates/host-proxy/tests/rustls_startup.rs` negative tests for missing/malformed certificate and key files, missing peer pins, and incomplete TLS configuration, per-connection authenticated-failure rejection/liveness, and authenticated tonic h2 RPCs | Acceptance criteria are falsifiable without treating raw ALPN/bytes as gRPC evidence | High | None |
| F-008 | D4 failure semantics | High | The transport contract did not state that malformed, unauthenticated, non-h2, or stalled handshakes are rejected per connection rather than terminating the incoming stream | A single invalid client could otherwise stop the control service and its BPF lifecycle | High | Resolved: requirements, design, and TC-CS-049 now require post-accept per-connection rejection, including PSK handshakes without h2, while listener-accept errors remain lifecycle-visible; later authenticated-RPC liveness is covered |

## Audit Verdict

**PASS**

The specification set is internally aligned. The concrete transport
alternatives are recorded in D-CS-009, with Linux/non-Linux capability
boundaries, feature-selection, pinning, startup-failure behavior, and
per-connection handshake rejection/liveness covered by validation. The
rustls and preserved TLS-PSK implementation is clean within this audit scope;
the deferred live TC attach/link item is pre-existing and does not weaken that
verdict.
