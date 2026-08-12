<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Control Service Implementation Audit

## Identifier audit basis

CHG/REQ/D/TC identifiers are scoped to their owning specification artifact and
must be unique within that artifact; references may repeat. New TLS IDs that
cross artifact boundaries use globally unique, artifact-qualified names.
Existing unqualified CHG duplicates across independent legacy specifications
are baseline and were not introduced by this TLS change.

## Findings

| ID | Category | Severity | Evidence | Impact | Confidence | Remediation |
|---|---|---|---|---|---|---|
| F-101 | D8 unimplemented behavior | None | Aya 0.14 is selected on Linux; it loads the ELF, validates `ssp_flow_map_v1`, `ssp_tc_ingress_v1`, and `ssp_tc_egress_v1`, attaches both TC directions, performs map CRUD, and rolls back partial links | Approved BPF loader behavior is implemented behind the backend trait | High | None |
| F-102 | D8 unimplemented behavior | None | The `tls-psk` path preserves OpenSSL/tokio-openssl TLS 1.2 PSK with `PSK-AES256-GCM-SHA384` and rejects a successful PSK handshake that did not negotiate h2; rustls builds TLS 1.2/1.3 h2 with pinned mutual PEM authentication. `transport::tests::rustls_authenticated_tonic_h2_supports_tls12_and_tls13` and `transport::tests::psk_invalid_handshake_does_not_stop_full_server` now reject non-h2/wrong authenticated credentials on the running server, assert retained in-memory attachments/zero detach calls, and execute a later valid authenticated tonic RPC; `rustls_client::tests::rustls_client_authenticates_tonic_h2_rpc` and shared tests cover the remaining client/pin/validity/signature/key-usage failures | Approved transport security is implemented without metadata/plaintext/fallback or an ALPN-only gRPC claim | High | None |
| F-103 | D9 undocumented behavior | None | Runtime, README, BPF README, design, and validation identify Linux-only kernel behavior and fail-closed non-Linux behavior | Platform behavior is documented | High | None |
| F-104 | D10 constraint violation | None | TC detach retains ownership on failure, removes successful partial detaches, and shutdown invokes cleanup after graceful server termination | Attachment ownership and teardown invariants hold | High | None |
| F-105 | D11 missing validation | Low | Deferred, Linux compilation, the OpenSSL-capable Linux control-service TLS-PSK test invocation, rustls authenticated tonic tests, the executable `crates/host-proxy/tests/rustls_startup.rs` certificate/key/pin/incomplete-configuration negative tests, and feature-selection checks cover the control-plane paths; privileged live kernel attach/link remains gated on a supplied ABI-v1 ELF and Linux capabilities | Pre-existing Linux-environment validation is outside the TLS change scope and has no impact on rustls/PSK behavior or evidence | High | Deferred; run the existing Aya/ELF integration gate on the supported Linux deployment image |
| F-106 | D12 untested acceptance | Low | Deferred, the isolated Linux rustls job executes server/client tonic coverage and the isolated Windows job executes the rustls host-proxy client path; no ABI-v1 ELF is required for those tests and no Windows execution is claimed by Linux evidence | The pre-existing privileged TC link/map acceptance item is deployment verification only; it does not change or weaken the clean TLS verdict | High | Deferred outside TLS scope; do not add or claim a privileged integration test in the TLS change |
| F-107 | D13 assertion mismatch | None | Mapping, maintenance, config, log cursor, rollback, auth/config, shutdown, duplicate CLI/environment, no-feature executable diagnostics, tonic h2, certificate-verification, and per-connection authenticated-failure/liveness tests match the approved validation cases; no test accepts backend failure as success | Assertions align with requirements and design | High | None |
| F-108 | D10 constraint violation | High | Phase 6 found that `buffer_unordered` exposed post-accept TLS handshake failures as `Err` items to tonic, which treats an incoming-stream error as terminal; malformed, unauthenticated, non-h2, or stalled clients could therefore stop the service before a later valid RPC | A connection-local failure could terminate the control service and trigger the BPF lifecycle shutdown path | High | Resolved: both TLS incoming streams now log and drop failures after socket acceptance, including the OpenSSL PSK h2 check, while preserving listener-accept errors; TC-CS-049 plus the full-server rustls and PSK liveness tests verify a later authenticated tonic RPC succeeds |

## Deferred validation boundary

Privileged live TC attach/link validation is a pre-existing,
Linux-environment-gated deferred item outside the TLS change scope. It remains
deployment verification for the existing BPF/TC path and is not a missing
rustls/PSK implementation feature. **No-impact rationale:** the TLS evidence
uses transport, authenticated tonic, feature-selection, and in-memory
ownership tests; it does not require or alter live TC attach/link behavior.
No privileged integration test is added or claimed.

## Verdict

**PASS**

The implementation is traceable to the approved requirements and design. The
Phase 6 transport failure is resolved by per-connection filtering for both
TLS modes, with full-server liveness coverage. One environment-dependent
validation item remains explicitly deferred: pre-existing privileged execution
against a real Linux kernel/TC subsystem using an ABI-v1 ELF. It is outside
the TLS change scope and has no impact on the clean rustls/PSK verdict. The
rustls and preserved TLS-PSK implementation is clean within this
implementation-audit scope. Rustls gRPC evidence is provided by executable
tonic RPC tests, and Windows-specific rustls evidence is isolated to the
Windows job rather than inferred from raw ALPN/byte tests or Linux execution.
No privileged integration test is added or claimed by this change.
