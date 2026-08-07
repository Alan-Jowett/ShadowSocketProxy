<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Validation

## Strategy

Rust ABI, backend, service, and lifecycle tests run on every supported host.
Linux ELF, verifier, TC attachment, checksum, and `bpf_prog_test_run_opts`
tests are environment-gated and must fail clearly when explicitly requested
without the required kernel/toolchain. Ordered packet fixtures cover target
miss, flow creation, forward/reverse rewrite, control bypass, FIN/ACK, and
RST.

## Test Cases

| ID | Requirement | Scenario | Expected result |
|---|---|---|---|
| TC-TC-001 | REQ-TC-006 | Build/load v3 artifact | v3 programs, v1 flow maps, v3 runtime map, three counter slots, scratch, and active-flow maps are discovered. |
| TC-TC-002 | REQ-TC-006 | v2/policy-only/mixed artifact | Attach/readiness rejects stale v2 symbols, policy map artifacts, missing v3 runtime map, or incomplete counters. |
| TC-TC-003 | REQ-TC-006 | Non-Linux backend | Unsupported TC behavior remains explicit; readiness is never falsely reported. |
| TC-TC-004 | REQ-TC-001 | IPv4 TCP/UDP global target | Complete v4 target rewrites destination only and fixes checksums. |
| TC-TC-005 | REQ-TC-001 | IPv6 TCP/UDP global target | Complete v6 target rewrites destination only and fixes checksums. |
| TC-TC-006 | REQ-TC-001 | Unset/partial target | Unset family passes and increments target-miss; partial pair is rejected atomically. |
| TC-TC-007 | REQ-TC-002 | Target replacement with active flow | Existing flow uses snapped target; a new flow uses the replacement target. |
| TC-TC-008 | REQ-TC-001 | Egress reverse rewrite | Reverse target-to-client packet restores original destination as source. |
| TC-TC-009 | REQ-TC-003 | Concrete TCP listener bypass | Matching ingress destination and egress source pass unchanged and increment bypasses. |
| TC-TC-010 | REQ-TC-003 | Wildcard TCP listener bypass | Any same-family TCP address on listener port bypasses; other family does not. |
| TC-TC-011 | REQ-TC-003 | UDP listener-port traffic | UDP on the same port remains DNAT-eligible and is not counted as TCP bypass. |
| TC-TC-012 | REQ-TC-004 | Malformed/fragment/unsupported packet | Packet passes unchanged with no unsafe access or checksum mutation. |
| TC-TC-013 | REQ-TC-002 | Concurrent first packets | Both directions converge on one canonical flow and three consistent indexes. |
| TC-TC-014 | REQ-TC-002 | Flow insertion/full-map failure | Attempt-owned entries roll back, packet drops, and flow-failure counter increments. |
| TC-TC-015 | REQ-TC-003 | TCP state progression | SYN, SYN/ACK, ACK, FIN, FIN/ACK, and RST encode/decode correctly. |
| TC-TC-016 | REQ-TC-003 | Terminal cleanup | RST deletes immediately; completed FIN/ACK waits for grace; incomplete TCP expires by idle TTL. |
| TC-TC-017 | REQ-TC-003 | UDP/QUIC lifecycle | Last-used updates; no TCP flags; idle TTL is the only cleanup path. |
| TC-TC-018 | REQ-TC-005 | Runtime validation | Invalid schema, zero/overflow durations, partial targets, invalid listener, and oversized cap preserve prior revision. |
| TC-TC-019 | REQ-TC-007 | Listener immutability | SetConfig rejects address, family, port, or wildcard changes. |
| TC-TC-020 | REQ-TC-007 | Invalid startup listener | Invalid `SSP_LISTEN_ADDR` fails before runtime start, attach, or serve. |
| TC-TC-021 | REQ-TC-005 | Runtime ABI encoding | Schema, targets, listener flags, TTLs, grace, and active cap round-trip to the v3 map layout. |
| TC-TC-022 | REQ-TC-006 | Status counters | Status exposes target misses, flow insertion failures, control bypasses, and flow-map maxima only. |
| TC-TC-023 | REQ-TC-006 | Maintenance partial cleanup | Idle/terminal deletion, decode failures, races, and backend errors remain explicit. |
| TC-TC-024 | REQ-TC-006 | Attach/rollback/detach/shutdown | Owned links and runtime state roll back transactionally and report partial cleanup. |
| TC-TC-025 | REQ-TC-004/006 | Kernel test-run sequence | `bpf_prog_test_run_opts` asserts bytes, action, checksums, flow state, target miss, control bypass, FIN/ACK, and RST. |
| TC-TC-026 | REQ-TC-006 | Protobuf wire compatibility | Retired policy tags are reserved; active legacy fields retain their original tags; new fields use fresh tags. |
| TC-CI-001 | REQ-CI-001 | Workflow triggers and platform | Pull requests and pushes to `main` select Ubuntu and use locked repository/toolchain inputs. |
| TC-CI-002 | REQ-CI-002 | Rust format/lint/build/test gates | Any failure of the four exact workspace commands fails the workflow. |
| TC-CI-003 | REQ-CI-003 | Canonical BPF build | Required native tools are installed and `make -C crates/bpf clean all` produces the expected ELF; compile failure fails the workflow. |
| TC-CI-004 | REQ-CI-004 | Runner loading and capability failure | The checked-in runner loads the ELF and exits nonzero for missing capabilities, invalid symbols/maps, verifier rejection, or setup failure. |
| TC-CI-005 | REQ-CI-004 | Ordered kernel fixture sequence | The runner executes target miss, flow creation, forward/reverse rewrite, control bypass, FIN/ACK teardown, and RST; every expected action, packet byte, checksum, and map-state assertion passes. |
| TC-CI-006 | REQ-CI-005 | No silent skip/artifact publication | Enabled fixture execution cannot be skipped and the workflow publishes no build artifact or changes production behavior. |
| TC-CI-007 | REQ-CI-006 | Windows OpenSSL installation | The Windows job installs the exact `ShiningLight.OpenSSL.Dev` 4.0.1 package, verifies the package and `openssl version`, and fails on mismatch or missing PSK capability. |
| TC-CI-008 | REQ-CI-007 | Windows host-proxy build | With TLS-PSK enabled and the pinned OpenSSL environment, formatting, strict clippy, and the locked host-proxy build succeed. |
| TC-CI-009 | REQ-CI-007 | Windows host-proxy tests | `cargo test --locked -p shadow-socket-proxy-host --features tls-psk` succeeds on `windows-latest`. |
| TC-CI-010 | REQ-CI-008 | Local Windows reproduction | The pinned OpenSSL installation and the Windows host-proxy validation commands pass locally before the PR is opened. |

## Impact Map

| Requirement | Design | Validation | Implementation surfaces |
|---|---|---|---|
| REQ-TC-001 | D-TC-001..005, D-TC-009 | TC-TC-004..008, TC-TC-011..012, TC-TC-025 | BPF parser/path, mapping ABI, packet fixtures |
| REQ-TC-002 | D-TC-001..003, D-TC-005..006 | TC-TC-007, TC-TC-013..014 | Flow maps, backend, service |
| REQ-TC-003 | D-TC-003..005 | TC-TC-009..011, TC-TC-015..017 | BPF listener/lifecycle, maintenance |
| REQ-TC-004 | D-TC-005, D-TC-009 | TC-TC-012, TC-TC-015..017, TC-TC-025 | Parser/checksum/lifecycle |
| REQ-TC-005 | D-TC-002, D-TC-005 | TC-TC-006, TC-TC-018, TC-TC-021 | Runtime config/store/backend |
| REQ-TC-006 | D-TC-001, D-TC-006, D-TC-008 | TC-TC-001..003, TC-TC-022..024, TC-TC-026 | Loader, attach, protobuf, service |
| REQ-TC-007 | D-TC-002, D-TC-004, D-TC-007 | TC-TC-009..010, TC-TC-019..020 | Main, lifecycle, config, BPF |
| REQ-CI-001 | D-CI-001, D-CI-004 | TC-CI-001 | Workflow |
| REQ-CI-002 | D-CI-001, D-CI-002 | TC-CI-002 | Workflow |
| REQ-CI-003 | D-CI-001, D-CI-002 | TC-CI-003 | Workflow, BPF Makefile |
| REQ-CI-004 | D-CI-003, D-CI-004 | TC-CI-004..005 | BPF runner, integration test, workflow |
| REQ-CI-005 | D-CI-001, D-CI-004 | TC-CI-006 | Workflow |
| REQ-CI-006 | D-CI-005, D-CI-006 | TC-CI-007 | Windows workflow, winget/OpenSSL setup |
| REQ-CI-007 | D-CI-005, D-CI-007 | TC-CI-008..009 | Windows workflow, host-proxy crate |
| REQ-CI-008 | D-CI-006, D-CI-007 | TC-CI-010 | Local Windows environment and validation commands |

## Explicit No-Impact Decisions

- Host-proxy forwarding, mapping lookup, source binding, and UDP association
  behavior remain unchanged.
- Flow map layouts, TCP teardown semantics, maintenance bounds, and TLS/PSK
  authentication remain unchanged except for the specified status/config
  fields.
- No direct-forward fallback is added when a target is unset or a mapping is
  missing.
- The workflow does not publish artifacts; it only reports validation status.
- Linux/BPF gates, host-proxy forwarding, control-plane protocol behavior, and
  TLS/PSK policy are unchanged; this change only adds Windows build coverage.
