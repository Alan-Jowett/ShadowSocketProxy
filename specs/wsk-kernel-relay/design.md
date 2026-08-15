<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy WSK Kernel Relay Design

## Traceability

```text
USER-REQUEST -> REQ-WKR-* -> D-WKR-* -> TC-WKR-* -> implementation/tests
```

This is a clean design. `feature/wsk-kernel-relay` is consulted for WSK/WDM,
IRP, MDL, cancellation, and failure-continuity lessons but is not reused as
the implementation.

## Design

### D-WKR-001 - Build modes

The workspace exposes mutually exclusive `user-mode-data-path` and
`kernel-relay` data-plane selections. Kernel-relay mode owns payload
forwarding in the WSK driver and does not publish a user-mode forwarding
listener.

### D-WKR-002 - Driver ownership domains

The driver owns WSK listeners, admission callbacks, the flow table, the full
flow state machine, tuple/protobuf codec, mapping transport adapter, outbound
sockets, relay buffers, deadlines, cancellation, teardown, unload, and
telemetry. User mode is never a canonical state owner.

### D-WKR-003 - Mapping transports

The transport trait supports direct kernel gRPC/TLS and the first
implementation's opaque user-mode tunnel. The driver serializes the complete
`Control/GetMapping` protobuf request and validates the complete response.
The opaque agent uses a raw/generic gRPC codec and method path, forwarding
bytes without semantic protobuf decoding or mutation.

### D-WKR-004 - Versioned device ABI

The device ABI defines open/close, opaque request submission, response
completion, cancellation, transport status, request ID, generation, epoch,
exact byte lengths, and bounded payload limits. Every message validates
version, direction, size, identity, state, and bounds. Multiple requests may
be pending concurrently.

### D-WKR-005 - Flow state machine

The states are:

```text
Admitted -> ResolvingMapping -> Connecting -> MappedTcp/MappedUdp
          -> Closing -> Released
```

Any active state may enter `Closing` for failure, timeout, cancellation, or
shutdown. Only the owning request ID and generation may advance or release a
state. Late completions clean only their own resources.

### D-WKR-006 - WSK listeners and tuples

The driver validates immutable startup configuration, binds configured
IPv4/IPv6 TCP and UDP listeners, and extracts the exact observed local/remote
tuple from WSK callbacks. Outbound sockets use OS-selected local endpoints.
Runtime listener reconfiguration requires restart.

### D-WKR-007 - TCP relay

After mapping validation and outbound connect, the driver atomically publishes
the paired sockets to the flow. It forwards both directions with bounded
provider-compatible buffers/MDLs, preserves supported half-close behavior,
and closes both peers on fatal failure.

### D-WKR-008 - UDP associations

An association is keyed by the complete synthetic tuple and client identity.
It owns the mapped destination, outbound socket, response route, buffers, and
idle deadline. Replies route only to the owning client. QUIC remains ordinary
UDP payload traffic.

### D-WKR-009 - Failure isolation

Flow/request failures transition only the affected owner to cleanup. Agent or
control-plane loss leaves the driver/listeners and existing mapped relays
alive; new unresolved flows fail closed.

### D-WKR-010 - Memory ownership

All kernel allocations use checked nonpaged pool with a driver tag. Serialized
requests/responses, TCP buffers, UDP queues, and transport envelopes have
separate startup-validated safety limits. Oversized data is rejected, never
truncated. Ownership unwinds in reverse order on every failure.

### D-WKR-011 - Locks and IRQL

Only `KSPIN_LOCK` and `PUSH_LOCK` protect shared state. Domains and hierarchy
are:

```text
driver lifecycle -> transport registry -> flow table -> per-flow resources
```

Lower domains never acquire higher domains. Spin locks protect short
IRQL-safe sections and are not held across WSK calls, waits, allocation,
pageable access, or blocking telemetry. Push locks are PASSIVE-only. WSK
callbacks declare their execution level and queue PASSIVE-only work.

### D-WKR-012 - Telemetry

The replaceable telemetry sink emits at the linearized transition point.
`DbgPrintEx` is the initial sink. DISPATCH-level sinks use fixed nonpageable
fields without allocation or blocking; richer future sinks use a bounded
PASSIVE-level queue. Telemetry failure cannot affect state correctness.

### D-WKR-013 - Shutdown

Shutdown closes admission, cancels/completes pending mappings, marks active
flows closing, closes listeners, cancels WSK/IRP work, quiesces callbacks, and
releases sockets/buffers before bounded unload. No callback context is freed
until callback and completion quiescence.

### D-WKR-014 - Configuration and deadlines

The kernel-relay executable owns immutable startup configuration and passes it
to the driver before readiness. Each mapping, connect, send/receive, idle,
and shutdown operation has an explicit deadline. Shutdown cancellation wins
over timeout; no operation remains published after the bounded drain period.

### D-WKR-015 - Opaque tunnel epochs

Opaque transport responses carry a connection epoch plus request ID and
generation. Agent reconnect does not replay requests. The driver decides
retry/fail/cancel, rejects duplicate/stale/wrong-epoch responses, and sees
backpressure without partial enqueue or truncation.

### D-WKR-016 - Cargo xtask boundary

The workspace contains `tools/xtask` as package
`shadow-socket-proxy-xtask`. `.cargo/config.toml` defines the alias
`xtask = "run --package shadow-socket-proxy-xtask --"`. The xtask parses
`build`, `--release`, and space-separated feature values before any
provisioning. It executes child processes with explicit environments rather
than relying on persistent shell state.

### D-WKR-017 - Feature normalization

The xtask normalizes public features into a typed build plan:

| Public feature | Host proxy | Linux control service | Kernel relay |
|---|---|---|---|
| `tls-psk` | `tls-psk` | `tls-psk` | — |
| `tls-rustls` | `tls-rustls` | `tls-rustls` | — |
| `wsl` | — | `linux-bpf` | — |
| `kernel-relay` | — | — | `wdk-native` |

User-mode forwarding is the host-proxy default. The plan rejects conflicting
TLS modes, `test-signing` without `kernel-relay`, and unknown features before
side effects.

### D-WKR-018 - Provisioning providers

Windows provisioning uses NuGet package restore for the pinned WDK/SDK
packages and `winget` exact package IDs `LLVM.LLVM` and
`ShiningLight.OpenSSL.Dev` when detection fails. WSL provisioning invokes
`wsl.exe -d <distro> -u root -- apt-get ...` for the pinned package set.
Detection is idempotent and records discovered paths in the build plan.
Optional `SSP_LLVM_PACKAGE_VERSION` and `SSP_OPENSSL_PACKAGE_VERSION` values
pin winget resolution; otherwise the resolved versions are recorded in the
manifest. Unavailable package managers produce phase-specific errors rather
than falling back silently.

### D-WKR-019 - Environment handoff

The xtask computes and validates WDK/SDK, LLVM/libclang, and OpenSSL roots,
then passes them directly to every Cargo child process. Native WDK children
receive `SSP_WSK_NUGET_ROOT`, `SSP_WSK_WDK_ROOT`, `SSP_WSK_SDK_ROOT`, and
`WDKContentRoot`. PSK children receive `OPENSSL_DIR`,
`OPENSSL_INCLUDE_DIR`, and `OPENSSL_LIB_DIR`. This avoids the dependency
build-script ordering limitation of the parent crate's `build.rs`.

### D-WKR-020 - WSL artifact bridge

WSL builds run from the repository mounted at `/mnt/<drive>/...` and publish
Linux artifacts into a staging directory represented by the Windows
`target\ssp-build\<profile>\` path. The bridge copies BPF ELF, control-service,
and fixture-runner outputs through the shared mount, verifies existence and
hashes, and rejects stale files not produced in the current staging run.

### D-WKR-021 - Atomic artifact manifest

Each run creates `target\ssp-build\<profile>\.staging-<run-id>\`, writes
artifacts and `manifest.json` there, fsyncs where supported, and replaces the
published manifest only after all selected components and validations succeed.
The manifest records feature plan, target triples, artifact paths, SHA-256,
driver signing state, certificate thumbprint when applicable, and
`reboot_required`.

### D-WKR-022 - Signing state machine

Signing is a distinct final phase. Unsigned mode only records the unsigned
driver. Test-signing mode creates/reuses a local certificate outside the
repository, signs with the discovered WDK `signtool`, verifies the embedded
signature, and optionally requests elevated test-signing configuration.
Configuration changes are reported as reboot-pending; no loadability claim is
made before reboot.

## Invariants

| ID | Invariant |
|---|---|
| INV-WKR-001 | Only one data-plane implementation owns a binary. |
| INV-WKR-002 | Every forwarding action uses a driver-validated mapping for the exact observed tuple. |
| INV-WKR-003 | User mode never owns canonical flow state or semantic mapping decisions. |
| INV-WKR-004 | A stale request ID/generation/epoch cannot mutate a current flow. |
| INV-WKR-005 | No partial socket handoff is published. |
| INV-WKR-006 | One flow/request failure cannot terminate unrelated work. |
| INV-WKR-007 | Bounded allocation failure unwinds without bugcheck/panic or leak. |
| INV-WKR-008 | Lock acquisition follows the documented hierarchy and IRQL rules. |
| INV-WKR-009 | Every state transition emits replaceable telemetry. |
| INV-WKR-010 | Shutdown frees no context before callback/completion quiescence. |

## Impact map

| Requirement | Design | Validation |
|---|---|---|
| REQ-WKR-001 | D-WKR-001 | TC-WKR-001 |
| REQ-WKR-002 | D-WKR-006/D-WKR-014 | TC-WKR-002/003/029/030 |
| REQ-WKR-003 | D-WKR-003/D-WKR-005 | TC-WKR-004-007 |
| REQ-WKR-004 | D-WKR-003/D-WKR-004/D-WKR-015 | TC-WKR-008-010/034-037 |
| REQ-WKR-005 | D-WKR-004/D-WKR-015 | TC-WKR-011/035-037 |
| REQ-WKR-006 | D-WKR-007/D-WKR-008 | TC-WKR-012-014/031-033 |
| REQ-WKR-007 | D-WKR-009/D-WKR-014/D-WKR-015 | TC-WKR-015/016/033-037/041 |
| REQ-WKR-008 | D-WKR-010 | TC-WKR-017/018/038 |
| REQ-WKR-009 | D-WKR-005/D-WKR-013/D-WKR-014 | TC-WKR-019/024/025/041 |
| REQ-WKR-010 | D-WKR-001/D-WKR-013 | TC-WKR-026-028 |
| REQ-WKR-011 | D-WKR-011 | TC-WKR-020/021 |
| REQ-WKR-012 | D-WKR-012 | TC-WKR-022/023/039/040 |
| REQ-WKR-013 | D-WKR-016 | TC-WKR-042/043 |
| REQ-WKR-014 | D-WKR-017 | TC-WKR-044/045 |
| REQ-WKR-015 | D-WKR-018/D-WKR-019 | TC-WKR-046-049/057 |
| REQ-WKR-016 | D-WKR-018/D-WKR-020 | TC-WKR-050/051 |
| REQ-WKR-017 | D-WKR-017/D-WKR-020/D-WKR-021 | TC-WKR-052/053 |
| REQ-WKR-018 | D-WKR-022 | TC-WKR-054/055/057 |
| REQ-WKR-019 | D-WKR-016/D-WKR-018/D-WKR-019 | TC-WKR-046/050/056 |
| REQ-WKR-020 | D-WKR-019 | TC-WKR-043/049 |
