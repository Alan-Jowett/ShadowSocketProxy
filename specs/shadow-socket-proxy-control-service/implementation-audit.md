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
| F-105 | D11 missing validation | Low | Actual Linux kernel attach and PSK handshake cannot execute in this Windows session; both are covered by Linux-gated code/tests and the validation matrix | Runtime environment evidence is incomplete, not implementation evidence | High | Run the Linux integration matrix on a host with CAP_BPF/CAP_NET_ADMIN, OpenSSL PSK, and an ABI-v1 ELF |
| F-106 | D12 untested acceptance | Low | Windows validation passes 11 tests; Linux-only Aya and OpenSSL tests are cfg-gated and were not executable because WSL has no Cargo toolchain | Kernel/transport acceptance remains deployment verification work | High | Execute `cargo test --workspace` on the supported Linux deployment image |
| F-107 | D13 assertion mismatch | None | Mapping, maintenance, config, log cursor, rollback, auth/config, and shutdown tests match the approved validation cases; no test accepts backend failure as success | Assertions align with requirements and design | High | None |

## Verdict

**PASS**

The implementation is traceable to the approved requirements and design. Two
environment-dependent validation items remain explicitly deferred: execution
against a real Linux kernel/TC subsystem and an end-to-end TLS-PSK client
handshake. The code does not claim those runtime results were observed here.
