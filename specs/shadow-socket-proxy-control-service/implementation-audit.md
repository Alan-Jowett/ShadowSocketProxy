<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Control Service Implementation Audit

## Findings

| ID | Category | Severity | Evidence | Impact | Confidence | Remediation |
|---|---|---|---|---|---|---|
| F-101 | D8 unimplemented behavior | None | Aya 0.14 is selected on Linux; it loads the ELF, validates `ssp_flow_map_v1`, `ssp_tc_ingress_v1`, and `ssp_tc_egress_v1`, attaches both TC directions, performs map CRUD, and rolls back partial links | Approved BPF loader behavior is implemented behind the backend trait | High | None |
| F-102 | D8 unimplemented behavior | None | OpenSSL/tokio-openssl builds TLS 1.2 PSK with `PSK-AES256-GCM-SHA384`, h2 ALPN, and tonic `serve_with_incoming`; unsupported PSK builds fail closed | Approved transport security is implemented without metadata/plaintext/mTLS fallback | High | None |
| F-103 | D9 undocumented behavior | None | Runtime, README, BPF README, design, and validation identify Linux-only kernel behavior and fail-closed non-Linux behavior | Platform behavior is documented | High | None |
| F-104 | D10 constraint violation | None | TC detach retains ownership on failure, removes successful partial detaches, and shutdown invokes cleanup after graceful server termination | Attachment ownership and teardown invariants hold | High | None |
| F-105 | D11 missing validation | Low | Linux compilation, OpenSSL PSK context construction, and Linux-gated tests pass in Ubuntu WSL; actual kernel attach remains gated on a supplied ABI-v1 ELF and kernel capability | Runtime evidence covers the concrete code paths but not a live packet hook | High | Run the Aya integration test with `SSP_TEST_BPF_ELF` on the deployment kernel |
| F-106 | D12 untested acceptance | Low | Ubuntu WSL passes `cargo fmt --all --check`, `cargo check --workspace`, `cargo test --workspace` (13 tests), and `cargo build --workspace`; no ABI-v1 ELF was available for live attach | Kernel link/map acceptance remains deployment verification work | High | Execute the ELF-backed integration matrix on the supported Linux deployment image |
| F-107 | D13 assertion mismatch | None | Mapping, maintenance, config, log cursor, rollback, auth/config, and shutdown tests match the approved validation cases; no test accepts backend failure as success | Assertions align with requirements and design | High | None |

## Verdict

**PASS**

The implementation is traceable to the approved requirements and design. One environment-dependent validation item remains explicitly deferred:
execution against a real Linux kernel/TC subsystem using an ABI-v1 ELF. The
OpenSSL TLS-PSK context path and Linux build/test matrix were executed
successfully in Ubuntu WSL.
