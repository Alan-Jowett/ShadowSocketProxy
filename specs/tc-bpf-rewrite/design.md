<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Design

## Traceability

```text
USER-REQUEST -> CHG-001..004 -> REQ-TC-001..007
             -> CHG-005 -> REQ-CI-001..005
             -> CHG-006 -> REQ-HP-LOG-001..003
             -> CHG-007..009 -> REQ-HP-MAINT-001..006
             -> D-TC-001..009, D-CI-001..004, D-HP-LOG-001..003,
                D-HP-MAINT-001..006
             -> TC-TC-001..026, TC-CI-001..006, TC-HP-LOG-001..005,
                TC-HP-MAINT-001..010
             -> BPF, backend, protobuf, service, lifecycle, logging,
                maintenance, and test changes
```

## Design

### D-TC-001 — v3 artifact contract

The ELF exports `ssp_tc_ingress_v3` and `ssp_tc_egress_v3`,
`ssp_flow_index_v1`, `ssp_flow_state_v1`, `ssp_runtime_config_v3`,
`ssp_tc_counters_v1`, `ssp_tc_active_flows_v1`, and the scratch map.
There is no destination-policy map. Flow keys/state retain their v1 layout.
The loader rejects v2 program symbols, policy-only maps, missing v3 runtime
configuration, missing counter slots, and incomplete flow-map contracts.

### D-TC-002 — Runtime configuration ABI

The runtime array contains schema version 3, independent v4/v6 target-set
flags, target addresses and network-order ports, listener family/address/port,
v4/v6 wildcard flags, idle TTL, terminal grace, and active-flow capacity.
Target address and port are encoded atomically as one complete runtime record.
The listener descriptor is encoded before attachment and cannot be changed by
`SetConfig`. Rust validation rejects partial targets, unsupported schema,
unspecified targets, invalid listener flags, zero durations, and oversized
capacities.

### D-TC-003 — Global ingress/egress path

Ingress parses a safe first-fragment TCP/UDP packet, checks the immutable
listener exclusion, then finds an existing flow or creates one from the
current family target. If no complete family target exists, it passes and
increments counter slot 0. A new flow snapshots the original and target
tuples, creates three index entries, publishes `ACTIVE`, and rewrites the
destination with checksum updates.

Egress first checks the listener exclusion against packet source for TCP, then
looks up the reverse target-to-client tuple. An active flow updates lifecycle
state and rewrites only the source back to the original destination. Missing
state passes unchanged.

### D-TC-004 — Control listener matching

For TCP only, ingress compares destination and egress compares source. A
concrete listener requires matching family, address, and port. An IPv4 or IPv6
wildcard requires only the matching family and TCP port. A bypass increments
counter slot 2 and never performs a flow lookup or rewrite. UDP uses the
normal target path even when its port equals the listener port.

### D-TC-005 — Flow lifecycle and bounded failure

Flow creation uses the existing creating/state/index/publish protocol. Any
insertion failure rolls back attempt-owned entries, drops the eligible packet,
and increments counter slot 1. The active-flow cap accounts for three indexes
per flow and never resizes maps. Flow timestamps and TCP lifecycle state remain
dataplane observations; host-proxy owns cleanup decisions.

### D-TC-006 — Backend and service surface

Remove policy types, map discovery, policy backend methods, capacity checks,
CRUD RPC implementations, and policy status fields. Add target/listener config
conversion, immutable-listener enforcement, v3 counter decoding, and v3
runtime-map encoding. `GetConfig` and `SetConfig` remain authenticated.
Retired protobuf field numbers remain reserved; all new target/listener and
telemetry fields use previously unused tags so older clients cannot decode a
new field as a different legacy field.

### D-TC-007 — Startup and readiness

The binary parses `SSP_LISTEN_ADDR` before constructing/starting the runtime.
The listener descriptor is stored in the initial `RuntimeConfig`; attach writes
it together with targets and TTLs before readiness is published. Invalid
listener values fail before transport creation, attach, or serve.

### D-TC-008 — Compatibility and migration

The loader uses explicit v3 symbol names and checks for stale v2/policy
artifacts. A v2 ELF, policy-only ELF, mixed v2/v3 ELF, missing runtime map,
or counters map with fewer than three slots fails closed. No legacy fallback
or direct-forward behavior is introduced.

### D-TC-009 — Safety and checksums

All reads/writes remain verifier-safe and bounds checked. IPv4 header checksum,
IPv4/IPv6 pseudo-header checksum, and TCP/UDP port updates use the existing
helpers. Unsupported, malformed, non-initial, and non-linear packets return
`TC_ACT_OK` without map or packet mutation.

### D-HP-LOG-001 — Lifecycle event taxonomy

Host-proxy lifecycle records use the existing `tracing` subscriber and
machine-readable event names and fields. TCP emits start and termination
events for each forwarding session. UDP emits association-created,
association-replaced, association-expired, relay-stopped, and proxy-shutdown
events. Association reuse is not emitted per datagram at info level.
Existing unconditional stderr startup and activation messages remain the
bootstrap path.

### D-HP-LOG-002 — Failure event taxonomy

Mapping lookup and validation failures, outbound connect/send/receive
failures, relay delivery failures, and control-service detach failures are
recorded as distinct `warn` or `error` events according to whether the
affected operation is recoverable. Each event retains the source error and
relevant protocol and tuple context. Rate limiting may prevent repeated
data-plane failures from overwhelming logs, but MUST NOT hide the first
failure or convert it into a success event.

### D-HP-LOG-003 — Structured context and lifecycle timing

Event fields include protocol and synthetic tuple whenever a tuple exists.
Association events include mapped/original destination, association age when
known, idle timeout when relevant, and a machine-readable reason. Reaping
captures the removed association's last-used age before deletion so idle UDP
garbage collection is visible. Shutdown emits one proxy lifecycle event after
forwarding tasks stop and before or alongside control-service detachment.

### D-HP-MAINT-001 — Ownership and activation boundary

Host-proxy is the stateful controller. It authenticates to the control-service,
orchestrates attach/configure/detach, schedules maintenance, owns local
association state, and decides when a flow is expired or deleted. The
control-service keeps no maintenance worker or lifecycle policy state between
requests; it validates request safety, translates typed operations, and
reports dataplane outcomes.

### D-HP-MAINT-002 — Typed BPF-agnostic flow contract

The control API adds typed `EnumerateFlows` and `DeleteFlow` operations. A
flow record contains an opaque flow identity, generation, synthetic/original
tuples, protocol, last-used timestamp, and TCP lifecycle flags/state. The
contract does not expose BPF map names, map keys, encoded values, or
Aya/libbpf-specific types to host-proxy. Enumeration returns the complete
record needed for maintenance, so a separate `GetFlow` operation is not
required.

`EnumerateFlows` accepts a bounded limit and an opaque continuation token and
returns a server-issued token when more records remain. The adapter orders a
maintenance scan by opaque flow identity and generation; the token carries
the scan cursor and expires when the enumeration pass ends or the control
session is lost. The scan is best-effort rather than a global snapshot:
records deleted during enumeration may be omitted, newly created records may
appear on a later pass, and the host treats repeated identities as harmless.
Malformed, expired, or over-limit tokens are explicit request errors.

### D-HP-MAINT-003 — Generation-safe cleanup primitive

`DeleteFlow` accepts flow identity and generation and performs the adapter's
canonical state-plus-index cleanup as one backend operation. It returns
complete removal, already absent, stale generation, or partial cleanup
outcomes and never deletes a newer generation when the supplied generation no
longer matches. A partial result includes the state/index removal counts and a
retryable indication; host-proxy retries the same identity/generation. An
already-absent result is idempotent success. Host-proxy invalidates a matching
local UDP association only for complete or already-absent results, never for a
stale-generation, partial, or transport-error result.

### D-HP-MAINT-004 — Host maintenance loop

Host-proxy owns cleanup interval, idle TTL, TCP terminal grace, scan batch,
and UDP association timeout configuration. A single maintenance scheduler
serializes passes so they never overlap. Each pass enumerates bounded flow
pages, applies TCP/UDP retention policy to the returned observations, issues
generation-checked deletes, and coordinates local association invalidation
only after the selected flow outcome is known. Failed enumeration/deletion
operations are logged and retried on a later pass. Reconnect attempts use
bounded exponential backoff capped at the cleanup interval and reset after a
successful control operation; shutdown cancels the scheduler and retries.
The control-service does not apply these policies autonomously.

### D-HP-MAINT-005 — UDP association cache and invalidation

The first datagram for a synthetic UDP tuple performs one flow lookup and
creates a connected local association. Subsequent datagrams reuse it without
RPCs. Expiry, host-selected flow deletion, or a controlled outbound failure
invalidates the association; a later datagram may create a fresh lookup. A
destination-specific refusal, timeout, or unreachable error permits one
re-resolution/retry for that datagram. Local resource, configuration, and
unrelated I/O errors preserve the current association and are surfaced.
Mapping and deletion errors preserve the current association until the
host-policy retry/invalidating decision is made.

### D-HP-MAINT-006 — Control loss and retry behavior

Existing forwarding tasks continue while the control channel is unavailable.
Host-proxy records reconnect, enumeration, deletion, and partial-cleanup
failures, retries control operations on later passes, and does not remove local
forwarding state solely because an RPC failed. No direct-forward fallback is
introduced. Operational counters, health state, and logs may remain process
local in the control-service, but they cannot drive lifecycle policy.

### D-CI-001 — GitHub Actions workflow

The workflow runs on pull requests and pushes to `main` on `ubuntu-latest`.
It checks out the repository, installs the pinned lockfile-respecting Rust
toolchain, installs clang, LLVM, Linux kernel UAPI headers,
OpenSSL/pkg-config development dependencies, and the build tools needed by the
workspace. It runs the four Rust gates and then the BPF build and fixture
execution gates.

### D-CI-002 — Canonical command ownership

Rust validation uses the exact workspace commands in REQ-CI-002. BPF
compilation uses `make -C crates/bpf clean all`, preserving the repository
Makefile as the source of compiler flags and output naming. The generated ELF
path is passed to the integration test through `SSP_TEST_BPF_ELF`.

### D-CI-003 — Checked-in privileged runner

The BPF test runner is a small Linux-only executable built by the BPF
component. It uses Aya to open/load the generated ELF, resolves the v3 ingress
and egress classifier programs, initializes runtime and flow maps with fixture
configuration, and invokes Aya's `SchedClassifier::test_run` wrapper over
`bpf_prog_test_run_opts` for each named fixture. It owns fixture packet
construction, expected action/bytes/checksums, and map-state assertions; setup,
capability, verifier, or assertion failure exits nonzero.

### D-CI-004 — Explicit privilege and no-skip behavior

The workflow invokes the runner with the least privilege supported by the
hosted Linux runner and exports all three gate variables required by the Rust
integration test. The integration test remains a hard failure when enabled:
missing runner, missing capability, or failed fixture is never treated as a
skip.

### D-CI-005 — Windows host-proxy workflow job

The existing workflow adds a `windows-latest` job with the same pull-request
and `main` push triggers as the Linux job. It uses the pinned repository
actions and Rust 1.96.1, but limits validation to formatting, strict clippy,
and the Windows host-proxy TLS-PSK build and test gates.

### D-CI-006 — Pinned Windows OpenSSL setup

The Windows job installs `ShiningLight.OpenSSL.Dev` version 4.0.1 with winget
using the exact package ID and version. It verifies the installed package and
OpenSSL version, configures the OpenSSL environment expected by the
`openssl-sys` build, and fails explicitly if the installation or TLS-PSK
capability is unavailable.

### D-CI-007 — Locked Windows commands

Windows validation runs `cargo fmt --all -- --check`,
`cargo clippy --locked -p shadow-socket-proxy-host --features tls-psk
--all-targets -- -D warnings`, `cargo build --locked
-p shadow-socket-proxy-host --features tls-psk`, and
`cargo test --locked -p shadow-socket-proxy-host --features tls-psk`.

### D-CI-E2E-001 — Deployable workflow artifacts

Three independent build jobs upload deterministic workflow artifacts:
`shadow-socket-proxy-bpf`, `shadow-socket-proxy-control`, and
`shadow-socket-proxy-host`. The BPF artifact contains the canonical ELF, the
control artifact contains the release Linux executable and runtime manifest,
and the host artifact contains the release Windows executable and required
OpenSSL DLLs.

### D-CI-E2E-002 — Shared Windows/WSL driver

`scripts/run-windows-wsl-e2e.ps1` provisions the default WSL distribution and
invokes `wsl.exe -u root` for package installation, process deployment, and
cleanup. It launches the Windows marker server and host proxy, then invokes
the checked-in `shadow-socket-proxy-e2e-runner` executable. CI downloads the
three deployable artifacts and builds only this test driver from source;
developers can invoke the same script locally.

### D-CI-E2E-003 — Ordered deployment and evidence

The driver performs `Attach`, then `SetConfig`, then generates the WSL TCP
flow after the host proxy is ready. It asserts ready status, the marker,
original and synthetic tuple fields, mapping presence before teardown, and
non-increasing flow-insertion failures. Any assertion or prerequisite failure
returns nonzero.

## Invariants

| ID | Invariant |
|---|---|
| INV-TC-001 | A rewritten packet has one complete current-family target and one active canonical flow. |
| INV-TC-002 | Existing flows retain their snapped target across configuration updates. |
| INV-TC-003 | Ingress and egress tuple transformations are symmetric and checksum-correct. |
| INV-TC-004 | One flow ID owns original, synthetic, and reverse indexes plus one lifecycle state. |
| INV-TC-005 | Target miss passes; insertion failure drops; control bypass passes and is counted. |
| INV-TC-006 | No malformed, non-initial, unsupported, or non-linear packet is partially rewritten. |
| INV-TC-007 | TCP terminal grace precedes idle cleanup; RST deletes immediately; UDP remains idle-TTL managed. |
| INV-TC-008 | Readiness requires the complete v3 artifact and rejects stale/mixed policy artifacts. |
| INV-TC-009 | The listener descriptor is present before attach and immutable through SetConfig. |
| INV-CI-001 | Every required Rust, BPF-build, and explicitly enabled kernel-fixture gate is executed and failures remain visible. |
| INV-CI-002 | CI uses the canonical Makefile and generated ELF; workflow artifacts do not alter production runtime behavior or publish branches/releases. |
| INV-CI-003 | Windows TLS-PSK validation requires the pinned PSK-capable OpenSSL installation and never falls back to plaintext or unauthenticated transport. |
| INV-CI-004 | The local and CI E2E paths use the same driver and exact assertions. |
| INV-HP-LOG-001 | Lifecycle and failure events preserve protocol/tuple context and retain underlying errors. |
| INV-HP-LOG-002 | UDP idle-association removal and relay termination are observable without per-datagram info-level logging. |
| INV-HP-MAINT-001 | Host-proxy is the sole lifecycle-policy owner; control-service requests are stateless adapters. |
| INV-HP-MAINT-002 | A flow identity/generation maps to one canonical state and all tuple indexes during adapter cleanup. |
| INV-HP-MAINT-003 | Control-plane loss does not interrupt existing forwarding or cause unconfirmed local deletion. |
