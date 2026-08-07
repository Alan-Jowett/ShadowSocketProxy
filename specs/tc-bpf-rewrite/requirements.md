<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Requirements

## Approved Change Set

### CHG-001 — Replace destination policy with global family targets

- **Before:** Eligible ingress flows require an exact destination-policy map
  entry, policy CRUD RPCs, policy capacity, and policy-miss telemetry.
- **After:** Authenticated `GetConfig`/`SetConfig` expose independent IPv4 and
  IPv6 target address/port pairs. A complete pair rewrites all eligible new
  TCP/UDP flows in that family; an unset pair passes unchanged and increments a
  bounded target-miss counter. A partial pair is invalid. Existing flows keep
  their snapped target.
- **Retired:** Destination-policy map/ABI, policy CRUD messages/RPCs, policy
  capacity/status/discovery, policy backend methods, and policy-miss telemetry.
- **Traceability:** `USER-REQUEST: remove destination-policy surface and
  globally DNAT all eligible TCP/UDP except control gRPC traffic.`

### CHG-002 — Exclude authenticated control traffic

- **Before:** The listener address is not represented in the BPF runtime ABI.
- **After:** The immutable `SSP_LISTEN_ADDR` descriptor is present before
  attachment. TCP ingress packets whose destination matches the listener and
  TCP egress packets whose source matches it pass unchanged and increment a
  control-bypass counter. A family wildcard matches every address in that
  family on the listener port. UDP on the same port remains eligible.

### CHG-003 — Version the program and runtime ABI

- **Before:** Program ABI v2 and a policy-bearing runtime map are accepted.
- **After:** Program ABI v3 exports v3 ingress/egress symbols and a versioned
  runtime configuration map containing schema version, v4/v6 targets, listener
  descriptor and wildcard flags, idle TTL, terminal grace, and active-flow cap.
  Flow maps remain v1 where unchanged. Counter slots are target misses, flow
  insertion failures, and control bypasses.
- **Migration:** Attach/readiness rejects stale or mixed v2/policy-only
  artifacts and accepts only the complete v3 contract.

### CHG-004 — Validate listener before startup

- **Before:** `SSP_LISTEN_ADDR` is parsed after runtime startup.
- **After:** It is parsed and validated before transport creation, BPF attach,
  or serving. Invalid values fail startup. `SetConfig` cannot change the
  listener descriptor.

### CHG-005 — Add CI/CD validation and an executable BPF fixture runner

- **Before:** No GitHub Actions workflow validates the two Rust crates and BPF
  artifact together. The `bpf_prog_test_run` integration test delegates to an
  external runner and can only be executed when one is supplied.
- **After:** A GitHub Actions workflow runs on `ubuntu-latest` for pull
  requests and pushes to `main`. It installs required Linux tooling and native
  dependencies, runs formatting, strict workspace clippy, workspace build,
  and workspace tests, builds the canonical BPF object through the existing
  Makefile, and executes the gated BPF fixture sequence. A checked-in Linux
  runner implements `bpf_prog_test_run_opts`, accepts the generated ELF and
  required ordered fixtures, and fails for unavailable capabilities, invalid
  program loading, or unexpected packet/action/checksum/state results. CI
  validates only and does not publish artifacts.
- **Retired:** No existing requirement is retired; the environment-gated BPF
  test becomes executable in CI.
- **Traceability:** `USER-REQUEST: add a CI/CD pass that runs clippy, format
  check, build and test for all the components (both the BPF and the two rust
  crates); follow-up approval to add the missing runner.`

## Stable Requirements

### REQ-TC-001 — Family-preserving global DNAT

Ingress MUST rewrite only the destination address/port of bounds-checkable
TCP/UDP first-fragment packets when the current family target is configured.
Egress MUST reverse-rewrite only the source address/port for the corresponding
active flow. IPv4 and IPv6 targets are independent and cross-family targets
are invalid.

### REQ-TC-002 — Canonical active-flow state

The flow ABI MUST retain one canonical record and three tuple indexes for the
original client-to-destination, synthetic client-to-target, and reverse
target-to-client tuples. New flow state MUST snapshot the current target;
configuration changes MUST NOT mutate active flow targets.

### REQ-TC-003 — TCP/UDP lifecycle

TCP MUST record SYN, SYN/ACK, ACK, FIN, and RST observations. RST removes the
flow immediately. Completed bidirectional FIN/ACK teardown is retained until
terminal grace; incomplete TCP, UDP, and QUIC-over-UDP expire through idle TTL.

### REQ-TC-004 — Packet safety

Malformed, truncated, unsupported, non-initial-fragment, and unreadable
packets MUST pass unchanged. Only fully bounds-checkable TCP/UDP packets may
update checksums or flow state. No TCP lifecycle assumptions apply to UDP.

### REQ-TC-005 — Runtime admission and synchronization

Runtime configuration MUST validate atomically, preserve revisions on failure,
bound active-flow capacity by fixed ELF maxima (three indexes per flow), and
publish one coherent ABI record. Changing targets affects only new flows.

### REQ-TC-006 — Readiness and ownership

The control service MUST validate all v3 symbols/maps, runtime schema, counter
slots, and fixed maxima before readiness. Attach, rollback, detach, maintenance,
and shutdown MUST retain explicit partial-failure behavior.

### REQ-TC-007 — Listener immutability

The listener descriptor MUST be family-aware, include address, TCP port, and
wildcard flags, be written before attach, and remain immutable through
`SetConfig`. Concrete listeners match address and port; wildcard listeners
match any address in their family on the TCP port.

### REQ-CI-001 — Reproducible CI triggers and platform

The workflow MUST run on Ubuntu for pull requests and pushes to `main`, use a
lockfile-respecting Rust toolchain, and make all required toolchain and native
dependencies explicit.

### REQ-CI-002 — Rust quality gates

The workflow MUST fail if `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo build --workspace`, or `cargo test --workspace` fails.

### REQ-CI-003 — BPF build gate

The workflow MUST install clang and Linux kernel UAPI headers and build the
canonical BPF object through `crates/bpf/Makefile`. A failed BPF compilation
MUST fail CI.

### REQ-CI-004 — Kernel fixture execution

The checked-in runner MUST execute `target-miss`, `flow-create`,
`forward-rewrite`, `reverse-rewrite`, `control-bypass`, `fin-ack-teardown`,
and `rst` through `bpf_prog_test_run_opts` against the generated BPF ELF.
Missing capabilities, loader/verifier failures, and any fixture mismatch MUST
return nonzero. CI MUST enable this gate and MUST NOT silently skip it.

### REQ-CI-005 — Failure visibility and scope

Toolchain, dependency, capability, loader, verifier, packet, action,
checksum, state, and Rust failures MUST remain visible failures. The workflow
MUST not alter production behavior, publish artifacts, or introduce a
direct-forward fallback.

## Acceptance Criteria

- Valid IPv4/IPv6 TCP and UDP packets rewrite with correct L3/L4 checksums.
- Unset targets pass unchanged and increment only the bounded target-miss slot.
- Partial target pairs, invalid schema, invalid listener, and listener changes
  are rejected without changing the prior revision.
- TCP control traffic bypasses on ingress and egress; UDP on that port rewrites.
- Active flows retain their original snapped target after `SetConfig`.
- v2, policy-only, missing, or mixed artifacts fail attach/readiness.
- Flow insertion/full-map failure drops eligible packets and increments its slot.
- RST, FIN/ACK grace, idle TTL, malformed packets, and unsupported protocols
  preserve existing lifecycle and safety invariants.
- A pull request or push to `main` runs all Rust gates, builds the BPF object,
  and executes every required kernel fixture; any failure is reported as a
  failed workflow.

## Non-Goals

- Cross-family translation, SNAT, wildcard target matching, or QUIC close state.
- Rewriting malformed packets, non-initial fragments, or unsupported protocols.
- Replacing TC, changing host-proxy forwarding, or changing TLS/PSK policy.
- Publishing CI build artifacts or changing production packet behavior.
