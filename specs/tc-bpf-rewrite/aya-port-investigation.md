<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# Aya TC Dataplane Port Investigation

## Recommendation

**Defer a Rust/Aya dataplane port.** Retain
`crates/bpf/shadow-socket-proxy.bpf.c` as the only production artifact. Aya
can express the required TC classifier and most of the required helpers, but
the repository cannot reproducibly compile an Aya eBPF program with its pinned
Rust 1.96.1 toolchain. `rustup target add bpfel-unknown-none` fails because
that toolchain has no prebuilt target. The repository also does not pin an
alternative target-building workflow or linker.

Consequently, a checked-in prototype would not meet the requirement that it
compile in CI, and must not be presented as a feasibility implementation.
Resolve the build-toolchain blocker, then perform the staged prototype below
before considering a rewrite.

## Findings

| Area | Result | Evidence |
|---|---|---|
| TC classifier | Supported | Aya userspace already loads `SchedClassifier`; `aya-ebpf` 0.2.1 provides `TcContext` and a classifier macro. |
| Packet access | Supported with explicit failure paths | `TcContext::load`, `load_bytes`, and `store` use skb helpers. Every offset and result must be checked before access. |
| IPv4 checksum | Supported | `TcContext::l3_csum_replace` and `l4_csum_replace` are available. |
| IPv6 checksum | Requires a prototype check | The current program uses `bpf_csum_diff` plus `l4_csum_replace`; the checked `aya-ebpf` API exposes the replacement helpers but not a `csum_diff` wrapper. A raw helper binding and its verifier result must be validated. |
| Map operations | Supported | Aya eBPF hash maps expose lookup, mutable lookup, update, and remove; arrays and per-CPU arrays expose checked pointers. |
| Existing loader | Compatible only with the current ABI | The Aya userspace loader already loads TC ELF files, but it deliberately accepts only the complete C v3 program/map names. |
| Reproducible eBPF build | Blocked | Rust 1.96.1 has no installable `bpfel-unknown-none` target, and CI installs neither a source-built target nor a BPF linker. |
| Kernel measurement | Blocked in this environment | The fixture runner cannot raise `RLIMIT_MEMLOCK` (`Operation not permitted`), so it cannot load the object for verifier or load-time measurement. |

The evaluated eBPF library is `aya-ebpf` 0.2.1 (its declared Rust minimum is
1.87). It is distinct from the repository's pinned userspace loader
dependency, `aya` 0.14.0. Any experiment must lock both dependency families
and prove that the emitted ELF remains loadable by the production Aya loader.

## Current ABI and Coexistence Rules

The production object exports `ssp_tc_ingress_v3`, `ssp_tc_egress_v3`,
`ssp_flow_index_v1`, `ssp_flow_state_v1`, `ssp_runtime_config_v3`,
`ssp_tc_counters_v1`, `ssp_tc_scratch_v1`, and
`ssp_tc_active_flows_v1`. The two hash maps, three arrays, and one per-CPU
array have fixed key/value layouts and maxima. The control service rejects
stale and mixed artifacts before attachment.

The prototype must not reuse any of those names or maps. Its initial names
should be `ssp_aya_probe_ingress_v1` and
`ssp_aya_probe_observations_v1`; the latter must have an independently
versioned layout. It must load only through a prototype-specific test runner,
not through the production control-service attachment path. This preserves the
existing v3 contract and prevents a probe from sharing state with production.

Today, the control-service attach request selects an explicit ELF path, but
the loader validates that path as the C v3 ABI. Therefore there is no
production Rust-artifact selection behavior to preserve or enable. A future
opt-in must be an explicit artifact kind in the attach contract, default to
`c-v3`, and reject an unknown kind or an artifact whose complete, matching ABI
is absent. It must never infer an artifact from a filename or fall back from a
failed Rust attach to C.

## Rust eBPF Constraints

- The eBPF crate is `no_std`: no allocation, I/O, unwinding, or panics in the
  packet path. Set an aborting panic handler and return `TC_ACT_OK` for every
  parse/helper failure.
- Use byte arrays or unaligned reads only after bounded `TcContext` loads.
  `repr(C)` does not make direct packet pointers aligned or verifier-safe.
- Treat Ethernet, IPv4 IHL, IPv6 extension/fragment handling, TCP data offset,
  and UDP length as independently bounded. Do not translate the C parser into
  unchecked slices or pointer casts.
- Preserve network byte order at the map and packet boundary. In particular,
  map ABI versions and ports are big-endian, while counters and time values
  follow their existing native map representations.
- Map value pointers are unsafe. Keep their scopes short, avoid aliases across
  helper calls, and retain the C program's rollback order for multi-map flow
  insertion and deletion.
- Do not add loops whose bounds depend on packet data unless the generated
  verifier proof is captured. The C implementation's fixed 16-byte address
  copy and bounded parsing are intentional.

## Baseline Measurements

The canonical C object was built on 2026-08-09 with:

```sh
make -C crates/bpf clean shadow-socket-proxy.bpf.o
llvm-objdump-18 -d crates/bpf/shadow-socket-proxy.bpf.o
```

The disassembly contains 2,581 instructions across the object. This is a
baseline only, not a per-entrypoint verifier instruction count. No kernel
verifier log or load-time measurement was captured because the fixture runner
failed before loading with `failed to raise RLIMIT_MEMLOCK: Operation not
permitted (os error 1)`. Runtime comparison is therefore intentionally
unreported.

After the build blocker is resolved, CI must record the Rust and C object
disassembly counts by entrypoint, full verifier logs, load duration, and
fixture execution time for the same kernel. A decision to port must compare
those measurements rather than infer performance from source language.

## Required Staged Validation and Rollout

1. **Toolchain gate:** Add a locked, CI-tested BPF target build and linker.
   It must build a minimal Aya classifier with the pinned Rust toolchain before
   any packet code or production dependency is added.
2. **Isolated parser:** Build `ssp_aya_probe_ingress_v1` with only a bounded
   Ethernet/IPv4 TCP/UDP parser and a private observation map. Run it through
   `bpf_prog_test_run_opts`; malformed, truncated, IPv4 TCP, IPv4 UDP, IPv6
   TCP, and IPv6 UDP fixtures must all return `TC_ACT_OK` unchanged.
3. **Parity gate:** Capture the measurements above and compare the isolated
   parser against the C artifact. Add IPv4 and IPv6 checksum fixtures before
   adding a rewrite.
4. **Private-state rewrite:** Implement rewrite and lifecycle behavior against
   newly versioned private maps only. Validate checksums, flow lifecycle, map
   consistency, control bypass, and the existing Windows/WSL E2E coverage.
5. **Explicit migration decision:** Only after an approved ABI migration may a
   Rust artifact use production names. Deploy it as an explicit opt-in, retain
   the C artifact and its maps, and roll back by detaching the Rust links,
   discarding its private state, and explicitly attaching `c-v3`. Never share,
   reinterpret, or silently migrate maps between artifacts.

## Compatibility Matrix

| Requirement | C v3 implementation | Aya prototype status | Required proof before port |
|---|---|---|---|
| `SCHED_CLS` ingress/egress | `classifier` sections | Supported by `TcContext`/classifier | Kernel load and TC attach |
| Hash flow index/state maps | Two ABI-v1 hash maps | Supported map kind | Private maps first; byte-exact ABI test before reuse |
| Array config/counters/active-flow maps | ABI-v3/v1 arrays | Supported map kind | Value size, alignment, and endianness test |
| Per-CPU scratch | Per-CPU array | Supported map kind | Pointer lifetime and verifier test |
| Lookup/update/delete | C helper calls with rollback | Supported map operations | Full-map and rollback fixtures |
| Packet read/write | skb load/store helpers | Supported `TcContext` methods | Malformed/truncated pass-through fixtures |
| Incremental checksums | L3/L4 plus `csum_diff` | L3/L4 supported; diff needs confirmation | IPv4 and IPv6 checksum fixtures and verifier log |
| Linux test tooling | Aya fixture runner + test-run | Reusable for separate names | Capability-enabled CI run |
| Windows/WSL E2E | Canonical C artifact | Not applicable until migration | Existing E2E suite against selected artifact |
