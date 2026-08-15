<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy WSK Kernel Relay Validation

## Validation strategy

Host-independent state, tuple, framing, correlation, bounds, and telemetry
tests run on the normal workspace target. Windows tests are gated on WDK,
signing, privileges, and a live Linux control service. Missing prerequisites
fail explicitly and never count as successful forwarding.

## Test cases

| ID | Requirement | Scenario | Expected result |
|---|---|---|---|
| TC-WKR-001 | REQ-WKR-001 | Build data-path feature combinations | Exactly one path is selected; invalid combinations fail |
| TC-WKR-002 | REQ-WKR-002 | IPv4/IPv6 TCP and UDP tuple extraction | Family, addresses, ports, and protocol remain exact |
| TC-WKR-003 | REQ-WKR-002 | Outbound source selection | OS-selected source is used; original source is never bound |
| TC-WKR-004 | REQ-WKR-003 | Serialize valid `GetMapping` request | Complete protobuf matches the synthetic tuple |
| TC-WKR-005 | REQ-WKR-003 | Parse valid mapping response | Driver applies only matching original destination |
| TC-WKR-006 | REQ-WKR-003 | Missing mapping | Only affected TCP flow closes or UDP drops |
| TC-WKR-007 | REQ-WKR-003 | Malformed/wrong-family/wrong-protocol mapping | Response rejected and no connect occurs |
| TC-WKR-008 | REQ-WKR-004 | Concurrent mapping requests | Replies correlate by request ID/generation |
| TC-WKR-009 | REQ-WKR-004/005 | Opaque tunnel request/reply | Agent transports bytes without semantic interpretation |
| TC-WKR-010 | REQ-WKR-004/005 | Stale/duplicate/cancelled completion | Completion is rejected and owned resources clean |
| TC-WKR-011 | REQ-WKR-005 | Unauthorized open and malformed IOCTL | Access/message rejected without state corruption |
| TC-WKR-012 | REQ-WKR-006 | Bidirectional UDP associations | Replies remain isolated to their client |
| TC-WKR-013 | REQ-WKR-006 | QUIC-over-UDP payload | Forwards without TCP-state logic |
| TC-WKR-014 | REQ-WKR-006 | UDP idle expiry | Association sockets/buffers/state are released |
| TC-WKR-015 | REQ-WKR-007 | TCP abort during mapping/connect/relay | Only affected flow fails; driver continues |
| TC-WKR-016 | REQ-WKR-007 | Agent/control-plane disconnect | Existing mapped flows continue; new flows fail closed |
| TC-WKR-017 | REQ-WKR-008 | Injected allocation/MDL/IRP failure | No bugcheck/panic; ownership unwinds |
| TC-WKR-018 | REQ-WKR-008 | Buffer/queue exhaustion | No truncation or success-shaped forwarding |
| TC-WKR-019 | REQ-WKR-009 | Concurrent TCP/UDP teardown | Generations and resource ownership remain isolated |
| TC-WKR-020 | REQ-WKR-011 | Lock-domain race stress | No inversion, deadlock, or use-after-free |
| TC-WKR-021 | REQ-WKR-011 | DISPATCH callback paths | No blocking/pageable work; PASSIVE work is queued |
| TC-WKR-022 | REQ-WKR-012 | Capturing telemetry sink | Every transition emits required fields |
| TC-WKR-023 | REQ-WKR-012 | Telemetry sink failure | State correctness is unchanged |
| TC-WKR-024 | REQ-WKR-009 | Shutdown with pending mappings/relays | Admission stops and resources release |
| TC-WKR-025 | REQ-WKR-009 | Late callback during unload | Context remains valid until quiescence |
| TC-WKR-026 | REQ-WKR-010 | Signed/test-signed Windows x64 integration | Driver forwards against Linux service |
| TC-WKR-027 | REQ-WKR-010 | Missing Windows/Linux prerequisites | Test is explicitly gated/fails |
| TC-WKR-028 | REQ-WKR-010 | ARM64 compatibility build | Compatibility result is reported separately |
| TC-WKR-029 | REQ-WKR-002 | Invalid config/reconfiguration | Startup fails; changes require restart |
| TC-WKR-030 | REQ-WKR-002 | Bind ordering/local tuple | Actual bound local address is authoritative |
| TC-WKR-031 | REQ-WKR-006 | Bidirectional TCP payload | Both payload directions arrive unchanged |
| TC-WKR-032 | REQ-WKR-006 | TCP half-close | One direction closes while reverse direction completes |
| TC-WKR-033 | REQ-WKR-006/007 | TCP EOF/fatal relay error | Paired flow cleans without affecting others |
| TC-WKR-034 | REQ-WKR-004/009 | Mapping/connect/send/receive timeout | Affected operation cancels within its deadline |
| TC-WKR-035 | REQ-WKR-004/005 | Tunnel channel loss/reconnect | No implicit replay; driver sees epoch change |
| TC-WKR-036 | REQ-WKR-004/005 | Duplicate/stale/wrong-epoch reply | Reply is rejected without cross-flow mutation |
| TC-WKR-037 | REQ-WKR-004/007 | Tunnel backpressure | Explicit rejection; unrelated requests continue |
| TC-WKR-038 | REQ-WKR-008 | Oversized wire/buffer/envelope | Explicit bounded failure without truncation |
| TC-WKR-039 | REQ-WKR-011/012 | DISPATCH telemetry | No allocation/blocking/pageable operation |
| TC-WKR-040 | REQ-WKR-012 | PASSIVE telemetry queue unavailable | State remains correct; loss is observable |
| TC-WKR-041 | REQ-WKR-009 | Bounded shutdown drain | No published work remains after unload |
| TC-WKR-042 | REQ-WKR-013 | Invoke `cargo xtask build --release` on a clean checkout | Workspace alias resolves the xtask package without a global executable |
| TC-WKR-043 | REQ-WKR-013/020 | Run xtask after provisioning, then run the equivalent plain Cargo package command | Both paths produce the same selected component artifacts |
| TC-WKR-044 | REQ-WKR-014 | Select each valid feature combination | Normalized plan contains exactly one TLS mode and one data path |
| TC-WKR-045 | REQ-WKR-014 | Select conflicting/unknown features | Command fails before provisioning, mutation, or artifact publication |
| TC-WKR-046 | REQ-WKR-015 | Restore absent pinned WDK/SDK packages | Exact versions are installed or restored idempotently and environment paths validate |
| TC-WKR-047 | REQ-WKR-015 | Detect LLVM/libclang below major 18 | Exact `LLVM.LLVM` installation is attempted or an actionable `winget` error is returned |
| TC-WKR-048 | REQ-WKR-015 | Build PSK with absent OpenSSL | Exact `ShiningLight.OpenSSL.Dev` installation is attempted and all OpenSSL paths validate |
| TC-WKR-049 | REQ-WKR-015/020 | Native WDK and PSK child Cargo builds | Dependency build scripts receive the required WDK/SDK and OpenSSL environment |
| TC-WKR-050 | REQ-WKR-016/019 | Missing WSL distro, Cargo, or package | Preflight or root package phase fails with distro/package-specific diagnostics |
| TC-WKR-051 | REQ-WKR-016 | Build BPF/control service in Ubuntu WSL | Locked Linux artifacts are produced through the shared repository mount |
| TC-WKR-052 | REQ-WKR-017 | Build user-mode feature set | Host/Linux artifacts publish and no driver artifact is listed |
| TC-WKR-053 | REQ-WKR-017 | Build kernel-relay feature set | Host and signed/unsigned driver artifacts publish with deterministic names |
| TC-WKR-054 | REQ-WKR-018 | Run kernel build without `test-signing` | Driver is unsigned and manifest records `unsigned` |
| TC-WKR-055 | REQ-WKR-018 | Run kernel build with `test-signing` | Certificate/signature verify; elevation and reboot state are reported accurately |
| TC-WKR-056 | REQ-WKR-019 | Remove a prerequisite or required privilege | Correct phase fails, no success manifest is published, and no unrelated files change |
| TC-WKR-057 | REQ-WKR-015/018 | Override or discover package/signing-tool versions and paths | Manifest records resolved versions, tool paths, and certificate thumbprint without repository writes |

## Properties

- Forwarding is impossible without a driver-validated mapping.
- A stale identity cannot mutate a current flow.
- Every state transition has one telemetry event.
- Every owned resource has exactly one release path.
- No DISPATCH path waits, pages, blocks, or performs an unbounded operation.
- One failure cannot terminate unrelated flows.

## Failure semantics

Invalid configuration and malformed IOCTLs fail explicitly. Missing mappings
drop/close only the affected flow. Control transport failures, WSK failures,
connect/send/receive failures, timeouts, cancellation, and resource
exhaustion are observable and clean only their owning flow/request. No test
accepts direct forwarding, truncation, empty success, bugcheck, panic, or
driver-wide termination as a valid result.

## Validation commands

```text
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Windows WDK/signing and live Windows/WSL commands are documented by the
implementation and are environment-gated.

## Build-orchestration validation commands

```text
cargo xtask build --release --features wsl tls-psk
cargo xtask build --release --features wsl tls-rustls
cargo xtask build --release --features wsl tls-psk kernel-relay
cargo xtask build --release --features wsl tls-rustls kernel-relay test-signing
```

The xtask parser accepts repeated feature tokens after `--features`; quoted
feature lists are also accepted. This syntax is intentionally handled by the
workspace xtask rather than Cargo's package feature parser.

The test-signing cases MUST run in an elevated Windows session when enabling
test-signing configuration. A changed boot configuration is a successful
configuration result only when the manifest reports `reboot_required`; it is
not a successful live-driver-load result before reboot.
