<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Validation

## Identifier scope and uniqueness

Identifiers are scoped to this TC/BPF specification artifact. Test case
definitions (`TC-*`) are unique within `validation.md`; `CHG-*`, `REQ-*`, and
`D-*` names remain references to their owning artifacts. New TLS names that
cross specification-artifact boundaries use globally unique,
artifact-qualified spellings. Existing unqualified `CHG-*` duplicates across
independent legacy specifications are baseline, not a result of the TLS
change.

## Strategy

Rust ABI, backend, service, and lifecycle tests run on every supported host.
Linux ELF, verifier, TC attachment, checksum, and `bpf_prog_test_run_opts`
tests are environment-gated and must fail clearly when explicitly requested
without the required kernel/toolchain. Ordered packet fixtures cover target
miss, flow creation, forward/reverse rewrite, control bypass, FIN/ACK, and
RST.

Privileged live TC attach/link validation is a pre-existing,
Linux-environment-gated deferred item outside the TLS change scope. The
existing ELF/kernel gate remains documented and is not replaced with a fake
or newly added privileged integration test. This has no impact on the TLS
change: rustls/PSK validation is isolated to transport and CI feature paths,
and no BPF packet or attach/link behavior is modified.

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
| TC-TC-016 | REQ-TC-003 | Terminal cleanup | RST remains enumerable for host cleanup; completed FIN/ACK waits for grace; incomplete TCP expires by idle TTL. |
| TC-TC-017 | REQ-TC-003 | UDP/QUIC lifecycle | Last-used updates; no TCP flags; idle TTL is the only cleanup path. |
| TC-TC-018 | REQ-TC-005 | Runtime validation | Invalid schema, zero/overflow durations, partial targets, invalid listener, and oversized cap preserve prior revision. |
| TC-TC-019 | REQ-TC-007 | Listener immutability | SetConfig rejects address, family, port, or wildcard changes. |
| TC-TC-020 | REQ-TC-007 | Invalid startup listener | Invalid `SSP_LISTEN_ADDR` fails before runtime start, attach, or serve. |
| TC-TC-021 | REQ-TC-005 | Runtime ABI encoding | Schema, targets, listener flags, TTLs, grace, and active cap round-trip to the v3 map layout. |
| TC-TC-022 | REQ-TC-006 | Status counters | Status exposes target misses, flow insertion failures, control bypasses, and flow-map maxima only. |
| TC-TC-023 | REQ-HP-MAINT-003 | Dataplane cleanup primitive | Canonical state/index deletion, decode failures, races, and backend errors remain explicit; lifecycle policy is not executed by the control-service. |
| TC-TC-024 | REQ-TC-006 | Attach/rollback/detach/shutdown | Owned links and runtime state roll back transactionally and report partial cleanup. |
| TC-TC-025 | REQ-TC-004/006 | Kernel test-run sequence | `bpf_prog_test_run_opts` asserts bytes, action, checksums, retained RST state, target miss, control bypass, FIN/ACK, and deletion commit/abort behavior. |
| TC-TC-026 | REQ-TC-006 | Protobuf wire compatibility | Retired policy tags are reserved; active legacy fields retain their original tags; new fields use fresh tags. |
| TC-CI-001 | REQ-CI-001 | Workflow triggers and platform | Pull requests and pushes to `main` select Ubuntu and use locked repository/toolchain inputs. |
| TC-CI-002 | REQ-CI-002 | Feature-neutral Rust format/lint/build/test gates | Any failure of the feature-neutral workspace commands fails the workflow; TLS alternatives are validated by their isolated jobs. |
| TC-CI-003 | REQ-CI-003 | Canonical BPF build | Required native tools are installed and `make -C crates/bpf clean all` produces the expected ELF; compile failure fails the workflow. |
| TC-CI-004 | REQ-CI-004 | Runner loading and capability failure | The checked-in runner loads the ELF and exits nonzero for missing capabilities, invalid symbols/maps, verifier rejection, or setup failure. |
| TC-CI-005 | REQ-CI-004 | Ordered kernel fixture sequence | The runner executes target miss, flow creation, forward/reverse rewrite, control bypass, FIN/ACK teardown, RST retention, and deletion commit/abort; every expected action, packet byte, checksum, and map-state assertion passes. |
| TC-CI-006 | REQ-CI-005 | No silent skip/artifact publication | Enabled fixture execution cannot be skipped and the workflow publishes no build artifact or changes production behavior. |
| TC-CI-007 | REQ-CI-006 | Windows OpenSSL installation | The Windows job installs the exact `ShiningLight.OpenSSL.Dev` 4.0.1 package, verifies the package and `openssl version`, and fails on mismatch or missing PSK capability. |
| TC-CI-008 | REQ-CI-007 | Windows host-proxy build | With TLS-PSK enabled and the pinned OpenSSL environment, formatting, strict clippy, and the locked host-proxy build succeed. |
| TC-CI-009 | REQ-CI-007 | Windows host-proxy tests | `cargo test --locked -p shadow-socket-proxy-host --features tls-psk` succeeds on `windows-latest`. |
| TC-CI-010 | REQ-CI-008 | Local Windows reproduction | The pinned OpenSSL installation and the Windows host-proxy validation commands pass locally before the PR is opened. |
| TC-CI-011 | REQ-CI-009 | Isolated rustls Linux/Windows jobs | Linux runs control-service authenticated tonic h2 coverage plus shared rustls tests; Windows runs the rustls host-proxy client, executable startup-negative, and e2e-runner checks; neither job installs or configures OpenSSL. |
| TC-CI-012 | REQ-CI-009 | Mutually exclusive feature selection | Separate PSK-capable jobs build each runnable package with both TLS features and require the explicit mutually-exclusive diagnostic. |
| TC-CI-013 | REQ-CI-009 | No-TLS runnable binary smoke | The feature-neutral job builds and executes the control-service, host-proxy, and e2e-runner binaries without either TLS feature; each exits nonzero with the explicit feature-selection diagnostic while library/test compilation remains supported. |
| TC-CI-014 | REQ-CI-009 | Linux control-service TLS-PSK tests | The OpenSSL-capable Linux control artifact job runs `cargo test --locked -p shadow-socket-proxy-control --no-default-features --features tls-psk` in addition to its PSK release build. |
| TC-CI-E2E-001 | REQ-CI-E2E-001 | Build/upload BPF artifact | Canonical ELF is downloadable and valid. |
| TC-CI-E2E-002 | REQ-CI-E2E-001 | Build/upload control artifact | Linux control executable and runtime manifest are downloadable. |
| TC-CI-E2E-003 | REQ-CI-E2E-001 | Build/upload host artifact | Windows host executable and required runtime assets are downloadable. |
| TC-CI-E2E-004 | REQ-CI-E2E-002/006 | Local Windows/WSL driver execution | The checked-in driver completes deployment, TCP flow, exact evidence checks, and cleanup locally; missing prerequisites fail visibly. |
| TC-CI-E2E-005 | REQ-CI-E2E-002 | CI Windows/WSL driver execution | CI invokes the same driver with downloaded artifacts and explicit WSL-root setup. |
| TC-CI-E2E-006 | REQ-CI-E2E-003 | Authenticated attach/configure/marker path | Attach succeeds, target configuration is accepted, and the WSL TCP request receives the known marker. |
| TC-CI-E2E-007 | REQ-CI-E2E-004 | Exact mapping/status evidence | Ready status, original tuple, synthetic tuple, pre-teardown mapping, and non-increasing flow-insertion failures all pass. |
| TC-CI-E2E-008 | REQ-CI-E2E-005 | Missing prerequisite/failure cleanup | Driver exits nonzero and attempts independent process/BPF cleanup. |
| TC-CI-E2E-009 | REQ-CI-E2E-005 | PR/main trigger coverage | Artifact and E2E jobs run for both supported event types. |
| TC-CI-E2E-010 | REQ-CI-E2E-006 | Local/CI command parity | CI calls the same checked-in driver and assertion path documented for local execution. |
| TC-HP-LOG-001 | REQ-HP-LOG-001/003 | TCP lifecycle logging | A TCP session emits structured start and termination events with protocol and synthetic tuple context; no lifecycle event is emitted as unconditional stderr. |
| TC-HP-LOG-002 | REQ-HP-LOG-001/003 | UDP association lifecycle logging | Creation, replacement, idle expiry, relay stop, and proxy shutdown emit structured events with destination, age/timeout, and reason fields; ordinary datagram reuse does not emit an info event. |
| TC-HP-LOG-003 | REQ-HP-LOG-002/003 | Mapping and forwarding failures | Lookup/validation, connect, send/receive, and relay delivery failures emit distinguishable structured records retaining the underlying error and tuple/protocol context. |
| TC-HP-LOG-004 | REQ-HP-LOG-002 | Detach failure visibility | Control-service detach failure remains an explicit error event and non-success result; it is not hidden by normal shutdown logging. |
| TC-HP-LOG-005 | REQ-HP-LOG-001/003 | Log filtering and field contract | `RUST_LOG` controls lifecycle visibility, while existing startup/activation stderr messages remain present; required event fields are stable and machine-readable. |
| TC-HP-MAINT-001 | REQ-HP-MAINT-001 | Control-service statelessness | Starting the control-service creates no autonomous maintenance worker; attach, config, flow, and detach requests perform only requested adapter operations. |
| TC-HP-MAINT-002 | REQ-HP-MAINT-002 | Flow enumeration contract | `EnumerateFlows` returns bounded, paginated typed flow records containing opaque identity, generation, synthetic/original tuples, protocol, last-used timestamp, and TCP lifecycle state without exposing BPF map ABI; malformed, expired, and over-limit tokens fail explicitly. |
| TC-HP-MAINT-003 | REQ-HP-MAINT-003 | Generation mismatch | Deleting an older generation cannot remove a newer flow incarnation and returns an explicit stale-generation outcome without invalidating a local association. |
| TC-HP-MAINT-004 | REQ-HP-MAINT-003 | Idempotent and partial deletion | Repeating a completed delete returns already-absent; backend/index failure returns counts plus a retryable partial outcome; retrying the same identity/generation does not affect a newer generation. |
| TC-HP-MAINT-005 | REQ-HP-MAINT-004 | Host maintenance policy | Host-proxy accepts cleanup interval, idle TTL, TCP grace, scan batch, and UDP timeout with current defaults, serializes non-overlapping scans, and retries failures with bounded backoff capped by the cleanup interval. |
| TC-HP-MAINT-006 | REQ-HP-MAINT-005 | UDP lookup caching | Repeated datagrams for one active association perform one mapping lookup; expiry or host invalidation permits recreation and a new lookup; one refusal/timeout/unreachable failure permits one re-resolution retry, while local resource errors preserve the association. |
| TC-HP-MAINT-007 | REQ-HP-MAINT-006 | Control-plane loss | Existing TCP/UDP forwarding continues during RPC loss; reconnect and maintenance retry use bounded backoff and are visible, pending retries stop at shutdown, and local state is not silently discarded. |
| TC-HP-MAINT-008 | REQ-HP-MAINT-001/003 | Host-driven TCP cleanup | Host policy deletes incomplete idle TCP, RST, and completed FIN/ACK flows using generation-safe flow operations and verifies no indexes remain. |
| TC-HP-MAINT-009 | REQ-HP-MAINT-001/003 | Host-driven UDP cleanup | Host policy expires idle UDP, deletes the corresponding dataplane flow, and invalidates the local association only after the deletion outcome is known. |
| TC-HP-MAINT-010 | REQ-HP-MAINT-001/006 | Activation and shutdown ownership | Host-proxy initiates attach/configure and detach; control-service shutdown does not independently run cleanup or alter host policy. |
| TC-TC-027 | REQ-TC-002/003/006 | Host deletion and release recovery | State-first deletion, generation-owned index checks, and a persistent release journal preserve a replacement incarnation; a failed publication retries without double capacity release. |
| TC-TC-028 | REQ-TC-002/003 | Packet/delete quiescence | A packet that crossed the first guard check increments in-flight before its final check; guard expiry and host commit race through an atomic outcome record, so only a committed operation can delete state. |
| TC-TC-029 | REQ-TC-005 | Concurrent attach/configure | The final BPF runtime record equals the final published snapshot irrespective of attach/set-config ordering. |
| TC-HP-MAINT-011 | REQ-HP-MAINT-004/006 | Retry, timeout, and shutdown bounds | Retry schedules the next scan at its exponential-backoff deadline; pending RPCs cancel at shutdown or fail at their deadline before BPF detach. |
| TC-HP-MAINT-012 | REQ-HP-MAINT-005 | Outbound UDP activity | Continuous client-to-destination sends extend association lifetime without extra mapping lookups; expiry still cancels the matching relay. |

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
| REQ-CI-009 | D-CI-005, D-CI-006, D-CI-007 | TC-CI-011..014 | Isolated rustls jobs, Windows PSK workflow, Linux control-service PSK tests, and feature-selection/no-TLS guards |
| REQ-CI-E2E-001 | D-CI-E2E-001 | TC-CI-E2E-001..003 | Separate workflow artifacts only; no branch/release publication. |
| REQ-CI-E2E-002 | D-CI-E2E-002 | TC-CI-E2E-004..005 | WSL-root deployment and Windows host execution. |
| REQ-CI-E2E-003 | D-CI-E2E-003 | TC-CI-E2E-006 | Authenticated TCP marker path. |
| REQ-CI-E2E-004 | D-CI-E2E-003 | TC-CI-E2E-007 | Exact mapping/status assertions. |
| REQ-CI-E2E-005 | D-CI-E2E-002, D-CI-E2E-003 | TC-CI-E2E-008..009 | Strict failure and trigger behavior. |
| REQ-CI-E2E-006 | D-CI-E2E-002 | TC-CI-E2E-004, TC-CI-E2E-010 | Shared local/CI executable driver. |
| REQ-HP-LOG-001 | D-HP-LOG-001, D-HP-LOG-003 | TC-HP-LOG-001..002, TC-HP-LOG-005 | Host-proxy TCP/UDP lifecycle and shutdown logging. |
| REQ-HP-LOG-002 | D-HP-LOG-002 | TC-HP-LOG-003..004 | Host-proxy mapping, forwarding, relay, and detach failure logging. |
| REQ-HP-LOG-003 | D-HP-LOG-001..003 | TC-HP-LOG-001..005 | Structured context, filtering, and no per-datagram info logs. |
| REQ-HP-MAINT-001 | D-HP-MAINT-001, D-HP-MAINT-004 | TC-HP-MAINT-001, TC-HP-MAINT-005, TC-HP-MAINT-008..010 | Host-proxy runtime, control-service lifecycle, and activation/shutdown. |
| REQ-HP-MAINT-002 | D-HP-MAINT-002 | TC-HP-MAINT-002 | Protobuf flow records and paginated adapter RPCs. |
| REQ-HP-MAINT-003 | D-HP-MAINT-003 | TC-HP-MAINT-003..004, TC-HP-MAINT-008..009 | Flow cleanup backend and host retry handling. |
| REQ-HP-MAINT-004 | D-HP-MAINT-004 | TC-HP-MAINT-005 | Host-proxy CLI/configuration and maintenance scheduler. |
| REQ-HP-MAINT-005 | D-HP-MAINT-005 | TC-HP-MAINT-006, TC-HP-MAINT-009 | UDP association cache and mapping client. |
| REQ-HP-MAINT-006 | D-HP-MAINT-006 | TC-HP-MAINT-007, TC-HP-MAINT-010 | Control reconnect, forwarding tasks, and shutdown. |

## Explicit No-Impact Decisions

- Packet rewrite and tuple restoration remain unchanged; this propagation
  moves lifecycle ownership and adds typed flow control operations.
- Flow map layouts and TCP teardown observations remain unchanged; deletion
  authority, policy configuration ownership, and control RPCs change as
  specified.
- No direct-forward fallback is added when a target is unset or a mapping is
  missing.
- Workflow artifacts are retained only for the workflow run and are not
  published to a branch or release.
- Linux/BPF packet-path gates, TLS/PSK authentication, and no-direct-forward
  behavior remain unchanged. Control-plane protocol and maintenance behavior
  are intentionally affected by CHG-007..009.
