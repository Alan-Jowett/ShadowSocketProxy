<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy WSK Kernel Relay Requirements

## Traceability

```text
USER-REQUEST -> REQ-WKR-* -> D-WKR-* -> TC-WKR-* -> implementation/tests
```

The prototype branch `feature/wsk-kernel-relay` is a source of WSK, WDM,
IRP, MDL, cancellation, and failure-continuity lessons only. Its fixed-port,
fixed-capacity, nonce, serialized-wait, and user-owned semantic-state
assumptions are not requirements for this clean implementation.

## Change Set

### CHG-WKR-001 - Exclusive kernel data path

- **Before:** Redirected payloads use the user-mode host proxy data path.
- **After:** Add a compile-time-selected WSK/WDM kernel-relay path. A binary
  selects exactly one data path; kernel-relay mode forwards payloads in the
  driver and does not route payload bytes through user mode.
- **Traceability:** `USER-REQUEST: forwarding operations to occur in kernel mode`.

### CHG-WKR-002 - WSK listeners and exact tuples

- **Before:** No product contract defines kernel-owned listeners or tuple
  extraction.
- **After:** The driver owns configurable IPv4/IPv6 TCP and UDP listeners,
  preserves the observed synthetic tuple, and uses OS-selected outbound
  source endpoints.
- **Traceability:** `USER-REQUEST: operates in kernel mode using WSK`.

### CHG-WKR-003 - Driver-owned mapping protocol

- **Before:** The prototype-specific broker owns mapping exchange details.
- **After:** The driver constructs, sends, validates, and applies the complete
  existing `GetMapping` protobuf request/response. The user agent never
  interprets mapping semantics or owns flow state.
- **Traceability:** `USER-REQUEST: driver building the full protobuf message`.

### CHG-WKR-004 - Opaque tunnel and direct transport alternative

- **Before:** Mapping resolution is coupled to a user-mode semantic broker.
- **After:** The design supports direct kernel gRPC/TLS or an opaque user-mode
  TLS/gRPC tunnel. The first implementation uses the opaque tunnel: the driver
  owns protobuf bytes and semantics; user mode only transports bytes and
  correlates replies.
- **Traceability:** `USER-REQUEST: host-proxy ... only as a TLS/gRPC tunnel`.

### CHG-WKR-005 - Authorized device boundary

- **Before:** The prototype uses session nonces.
- **After:** The device interface is ACL-restricted to administrators or a
  designated service identity. An authorized handle is trusted, but every
  IOCTL still validates version, size, direction, request ID, generation,
  state, and bounds. A nonce is not required.
- **Traceability:** User clarification: `if we ACL the interface ... nonce is
  not needed`.

### CHG-WKR-006 - Kernel-owned TCP/UDP lifecycle

- **Before:** Kernel flow lifecycle is not a product contract.
- **After:** The driver owns admission, mapping, connect, forwarding,
  association expiry, cancellation, and teardown for TCP and UDP. QUIC is
  treated as UDP payload traffic.
- **Traceability:** `USER-REQUEST: full flow tracking state machine`.

### CHG-WKR-007 - Failure isolation

- **Before:** Individual failures may be coupled to process/driver lifetime.
- **After:** Abort, missing mapping, mapping error, WSK error, connect/send/
  receive failure, cancellation, or per-flow resource failure affects only the
  affected flow/request. The driver and agent continue serving other flows.
- **Traceability:** `USER-REQUEST: should not stop ... continue with the other
  connections`.

### CHG-WKR-008 - Low-memory resilience

- **Before:** No complete low-memory safety contract exists.
- **After:** Checked nonpaged allocations, bounded operation buffers, and
  explicit unwind paths prevent bugcheck/panic. Resource exhaustion fails only
  the affected operation.
- **Traceability:** `USER-REQUEST: resilient to out of memory conditions`.

### CHG-WKR-009 - Synchronization and IRQL discipline

- **Before:** Synchronization and execution-level rules are unspecified.
- **After:** Shared kernel state uses OS-provided `KSPIN_LOCK` or `PUSH_LOCK`
  primitives only. Lock domains, hierarchy, and DISPATCH/PASSIVE rules are
  documented and enforced.
- **Traceability:** User clarification: `KSPIN_LOCK or PUSH_LOCK` and
  `DISPATCH vs PASSIVE`.

### CHG-WKR-010 - Replaceable transition telemetry

- **Before:** State transitions have implementation-specific diagnostics.
- **After:** Every accepted or rejected state transition emits through a
  replaceable telemetry sink, initially backed by `DbgPrintEx`.
- **Traceability:** User clarification: `All state transitions should expose
  telemetry`.

## Stable Requirements

### REQ-WKR-001 - Exclusive data-plane mode

The build MUST select exactly one of the existing user-mode data path and the
kernel-relay data path. Both MUST NOT be compiled into or activated by one
binary. Existing user-mode behavior remains unchanged.

### REQ-WKR-002 - Exact WSK tuple and listener behavior

The driver MUST own configurable IPv4/IPv6 TCP and UDP listeners and construct
the exact observed synthetic 5-tuple, including family and protocol. Outbound
sockets MUST use OS-selected local endpoints and MUST NOT impersonate the
original source.

### REQ-WKR-003 - Driver-owned `GetMapping`

The driver MUST construct, issue, validate, and apply every existing
`GetMapping` protobuf request/response. A response MUST match the requesting
flow's family and protocol and contain a valid original destination. Missing,
malformed, mismatched, or unavailable mappings MUST fail closed only for the
affected flow/datagram. No direct-forward fallback is permitted.

### REQ-WKR-004 - Concurrent correlated transport

The selected transport MUST support multiple outstanding resolutions. Each
request and completion MUST correlate by driver-generated request ID and flow
generation. Direct gRPC/TLS and opaque tunnel transports MUST share this
driver-owned state machine.

### REQ-WKR-005 - Authorized and opaque user mode

The device interface MUST be ACL-restricted. Authorized IOCTLs MUST reject
malformed, stale, oversized, or invalid-state messages without corrupting
state. In tunnel mode, user mode MUST only transport opaque protobuf bytes,
manage the authenticated channel, and correlate replies; it MUST NOT interpret
mapping status, choose destinations, cache mappings, own flow tables, or
perform state transitions.

### REQ-WKR-006 - TCP/UDP forwarding and teardown

TCP MUST forward both directions, preserve supported half-close behavior, and
close both peers on fatal failure. UDP MUST maintain per-flow associations
keyed by the complete synthetic tuple and client identity, route replies only
to that client, and expire idle associations. QUIC receives UDP treatment
without TCP-state assumptions.

### REQ-WKR-007 - Failure containment and continuity

The driver and agent MUST remain alive after individual flow aborts, mapping
misses, control-plane failures, WSK failures, connect/send/receive failures,
or cancellations. Existing mapped flows may continue during control-plane loss;
new unresolved flows fail closed. Every affected flow releases its resources.

### REQ-WKR-008 - Low-memory safety

Every allocation, MDL, IRP, queue, socket, and WSK operation MUST have an
explicit failure path. Nonpaged allocations and operation buffers MUST be
bounded and checked. Oversized messages are rejected without truncation.
Resource exhaustion MUST NOT bugcheck, panic, dereference invalid memory, or
produce successful forwarding.

### REQ-WKR-009 - Driver-owned lifecycle and unload

The driver MUST own canonical flow identity, generations, lifecycle state,
socket/buffer ownership, deadlines, cancellation, and teardown. Shutdown MUST
stop admission, cancel pending resolutions, close resources, quiesce callbacks,
and unload within a bounded drain period without use-after-free or indefinite
wait.

### REQ-WKR-010 - Platform and validation scope

Windows x64 is the first implementation target. ARM64 compatibility MUST be
preserved and separately validated. Host-independent tests and gated Windows
integration tests MUST cover positive forwarding, concurrency, malformed
IOCTLs, mapping failures, resource failures, cancellation, and unload.

### REQ-WKR-011 - Synchronization and IRQL

Kernel shared state MUST use only OS-provided `KSPIN_LOCK` and `PUSH_LOCK`
primitives. Every state domain MUST document its lock and acquisition order.
No lock inversion, recursive acquisition, illegal wait, pageable access at
elevated IRQL, or blocking operation while holding a spin lock is permitted.

### REQ-WKR-012 - Transition telemetry

Every accepted and rejected state transition MUST emit a privacy-safe event
containing correlation, generation, protocol, prior state, next state or
rejection, reason, and execution level. The initial sink is `DbgPrintEx`; the
sink is replaceable and its failure MUST NOT affect correctness.

### CHG-WKR-011 - Unified build orchestration

- **Before:** Building WSL, host, driver, and signing artifacts requires
  separate environment-specific commands.
- **After:** A Cargo-native `xtask` provisions prerequisites, validates feature
  combinations, builds all selected components, signs when explicitly
  requested, and publishes a deterministic artifact manifest.
- **Traceability:** `USER-REQUEST: simple and intuitive building process from a
  fresh machine`.

### REQ-WKR-013 - Cargo-native build entry point

The workspace MUST provide `cargo xtask build`. The command MUST be exposed by
an `xtask` workspace package and a checked-in Cargo alias
`xtask = "run --package shadow-socket-proxy-xtask --"`; it MUST NOT depend on a
globally installed executable. The command MUST accept Cargo-compatible
`--release` and space-separated `--features` arguments.

### REQ-WKR-014 - Supported feature contract

The public build features MUST be `wsl`, `tls-psk`, `tls-rustls`,
`kernel-relay`, and `test-signing`. `tls-psk` and `tls-rustls` are mutually
exclusive. `kernel-relay` and user-mode forwarding are mutually exclusive;
user-mode forwarding is selected when `kernel-relay` is absent.
`test-signing` is valid only with `kernel-relay`. Invalid combinations MUST
fail before provisioning or building.

The orchestrator MUST map these public features to the existing package
features: `tls-psk`/`tls-rustls` on the host proxy and Linux control service,
`linux-bpf` on the control service for WSL builds, and `wdk-native` on the
kernel-relay crate.

### REQ-WKR-015 - Deterministic Windows provisioning

When required, the orchestrator MUST idempotently restore pinned NuGet
packages `microsoft.windows.wdk.x64`,
`microsoft.windows.wdk.arm64`, and `microsoft.windows.sdk.cpp`, all at
`10.0.28000.2526`, into the configured NuGet global package root. It MUST
discover or install LLVM/libclang major version 18 or newer and a PSK-capable
OpenSSL development package when `tls-psk` is selected. The default Windows
package identifiers are `LLVM.LLVM` and `ShiningLight.OpenSSL.Dev`; package
installation MUST use exact IDs and accept agreements non-interactively.
The orchestrator MUST accept `SSP_LLVM_PACKAGE_VERSION` and
`SSP_OPENSSL_PACKAGE_VERSION` overrides; when unset, it MUST record the exact
resolved package versions in the manifest. Missing `winget` MUST produce an
actionable prerequisite error.

For native driver builds, the orchestrator MUST set `SSP_WSK_NUGET_ROOT`,
`SSP_WSK_WDK_ROOT`, `SSP_WSK_SDK_ROOT`, and `WDKContentRoot` in the same
process that invokes Cargo. For PSK builds it MUST set
`OPENSSL_DIR`, `OPENSSL_INCLUDE_DIR`, and `OPENSSL_LIB_DIR` after validating
the headers, libraries, and `openssl.exe`.

### REQ-WKR-016 - Deterministic WSL provisioning and builds

For `wsl` builds, the default distribution MUST be `Ubuntu`, overridable by
`SSP_WSL_DISTRO`. The orchestrator MUST verify `wsl.exe`, the distribution,
and WSL 2 availability before mutation. It MUST install missing packages as
root using the exact package set
`build-essential clang llvm linux-libc-dev libssl-dev pkg-config make
iproute2 python3 ca-certificates`, then build the BPF artifact and Linux
control service inside WSL using the repository checkout and locked
dependencies. Package-install or build failures MUST identify the failed phase
and MUST NOT publish a successful manifest.

### REQ-WKR-017 - Component and artifact selection

The orchestrator MUST build the Linux BPF/control artifacts when `wsl` is
selected, the Windows host proxy for every build, and the native kernel driver
only when `kernel-relay` is selected. User-mode builds MUST NOT build or
publish a driver. All outputs MUST be copied to
`target\ssp-build\<profile>\` under deterministic component names.

Publication MUST use a temporary staging directory followed by an atomic
manifest replacement. The manifest MUST list profile, selected features,
target triples, absolute artifact paths, SHA-256 hashes, signing state, and
whether a reboot is required. Stale artifacts MUST NOT appear in a new
manifest.

### REQ-WKR-018 - Signing and test-signing safety

Without `test-signing`, the driver MUST remain unsigned and the manifest MUST
state `unsigned`. With `test-signing`, the orchestrator MUST locate
`signtool.exe` from the restored WDK/SDK contents or an explicitly configured
path, create or reuse a local test certificate outside the repository, sign,
verify the signature, and report the certificate thumbprint. Enabling Windows
test-signing mode MUST require an explicit elevated action; the tool MUST report
`reboot_required` when the setting changed and MUST NOT claim the driver is
loadable until reboot.

### REQ-WKR-019 - Fresh-machine diagnostics

The orchestrator MUST perform non-mutating prerequisite checks before each
mutation phase and emit phase-specific, actionable diagnostics. It MUST fail
closed when Rust/MSVC, WSL, NuGet, LLVM/libclang, OpenSSL, signing tools, or
required privileges are unavailable. It MUST preserve existing user changes
and MUST NOT commit secrets, certificates, or generated bindings.

### REQ-WKR-020 - Post-bootstrap plain Cargo builds

After successful provisioning, the orchestrator MUST invoke the same ordinary
Cargo package builds that a developer can run directly. The README MUST
document `cargo xtask build` as the fresh-machine/provisioning entry point and
plain `cargo build` as a post-bootstrap command, including the required
environment variables for native WDK and PSK builds.

## Non-goals

- Changing Linux BPF rewrite behavior or the existing `GetMapping` schema.
- Direct destination inference or plaintext fallback.
- Binding original source addresses or ports.
- Runtime listener reconfiguration.
- QUIC-specific parsing/state.
- Application-level flow-count caps; bounded safety buffers are not flow caps.
- ARM64 live validation in the first implementation.
