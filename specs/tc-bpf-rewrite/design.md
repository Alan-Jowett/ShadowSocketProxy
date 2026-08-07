<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Design

## Scope and Traceability

```text
USER-REQUEST -> REQ-TC-* -> D-TC-* -> TC-TC-* -> implementation/test artifacts
```

The design covers the Linux TC packet path, policy/flow map ABI, control
service integration, and lifecycle cleanup. Existing host-proxy forwarding
behavior remains unchanged.

## Design

### D-TC-001 — Versioned BPF artifact and map set

The Linux BPF artifact exports:

- `ssp_tc_ingress_v2`;
- `ssp_tc_egress_v2`;
- `ssp_destination_policy_map_v1`;
- `ssp_flow_index_v1`;
- `ssp_flow_state_v1`.

The control service validates all required symbols before attachment and
rejects partial ABI availability. Policy keys contain ABI version, address
family, protocol, destination address, and destination port. Policy values
contain target address and target port. Integers use network byte order; IPv4
uses IPv4-mapped 16-byte encoding; timestamps use monotonic nanoseconds from
the BPF monotonic clock. Policy and target address families must match.

### D-TC-002 — Packet path and tuple model

Ingress parses bounds-checkable IPv4/IPv6 TCP/UDP first fragments, performs an
exact policy lookup by original destination and protocol, and creates or finds
one canonical flow record. It rewrites only destination IP/port to the
snapped target and recomputes IPv4/IPv6 and TCP/UDP checksums.

Egress looks up the reverse directional key containing target source, client
destination, protocol, and ports. After validating the canonical flow, it
rewrites only source IP/port back to the original destination and recomputes
checksums. Source addresses/ports and return destination addresses/ports are
not translated.

### D-TC-003 — Canonical active-flow state

`ssp_flow_index_v1` contains three lookup entries per flow, each mapping a
full 5-tuple to a stable flow ID: the original client-to-destination tuple,
the synthetic client-to-target tuple used by the host proxy, and the reverse
target-to-client tuple.
`ssp_flow_state_v1` contains one canonical record per flow:

- original client-to-destination tuple;
- snapped target tuple;
- reverse tuple identity;
- protocol;
- last-used monotonic nanoseconds;
- TCP state bitset;
- per-direction FIN/ACK/terminal flags;
- terminal-deadline metadata.

Concurrent first packets use atomic map-update discipline so they converge on
one flow ID or fail closed. Mapping list/get operations decode canonical state
and never combine data from different flow IDs.

### D-TC-004 — Policy lifecycle and flow snapshots

Authenticated `SetDestinationPolicy`, `DeleteDestinationPolicy`, and
`ListDestinationPolicies` operations validate exact TCP/UDP protocol, address
family, nonzero ports, supported addresses, and configured capacity. Updates
are idempotent and replace one complete value atomically. Existing flow state
retains its snapped target; a policy change affects only new flows.

A policy miss passes the packet unchanged and increments bounded miss
telemetry. Active-flow insertion or full-map failure drops the packet and
increments bounded failure telemetry.

### D-TC-005 — TCP and UDP lifecycle

TCP updates SYN, SYN/ACK, ACK, FIN, and RST bits for both directions. RST
removes both directional index entries and canonical state immediately. FIN
records direction-specific FIN and required ACK observations; after both
directions complete FIN/ACK, state remains until the configured terminal grace
deadline and is then removed.

UDP and QUIC-over-UDP update last-used/protocol activity only and are removed
by idle-TTL maintenance. They never synthesize TCP state.

### D-TC-006 — Safety and unsupported traffic

All packet reads and writes are verifier-safe and bounds checked. Malformed,
truncated, non-linear, unreadable, unsupported, non-initial-fragment, and
family-mismatched packets pass unchanged. Only eligible TCP/UDP first
fragments with valid headers are rewritten. There is no wildcard policy
matching, SNAT, cross-family translation, or QUIC-specific close tracking.

### D-TC-007 — Control-service integration

Extend the BPF backend and Linux Aya adapter with policy operations, new map
discovery, canonical-flow decoding, and ABI-v2 program validation. Extend the
protobuf service with policy messages/RPCs and policy/flow counters. Extend
runtime configuration with destination-policy capacity, active-flow capacity,
and TCP terminal grace period, validating all fields atomically.

Maintenance scans canonical flow state, applies idle TTL and terminal
deadlines, and treats index/state deletion as one cleanup operation with
explicit partial-failure reporting. Existing host-proxy `GetMapping` behavior
remains compatible: it queries the ingress synthetic client-to-target tuple
and receives the snapped original destination.

All new policy/configuration RPCs use the existing authenticated endpoint and
authentication interceptor. The protobuf and backend changes are additive or
explicitly ABI-versioned; existing `GetMapping` behavior remains compatible.

Runtime policy and active-flow capacities are admission caps below fixed
load-time ELF map maxima. Changing a cap does not resize a kernel map or
require re-attachment. The service rejects a cap greater than the discovered
map maximum.

### D-TC-008 — Build and attachment

Add a documented Linux BPF build path for the C source/ELF and environment-
gated integration tests for kernel, clang, and libbpf availability. Non-Linux
builds retain explicit unsupported behavior and no insecure control fallback.

### D-TC-009 — Multi-map flow creation protocol

Flow creation uses a stable flow ID and a `CREATING` state marker:

1. Reserve the canonical state with `CREATING` and the expected generation.
2. Add the original, synthetic, and reverse index entries, each pointing to
   that flow ID.
3. Publish the state as `ACTIVE` only after both indexes are present.
4. If any update fails, delete every entry created by the attempt and expose
   the failure; no packet is rewritten from a `CREATING` record.

Index lookups validate flow ID, generation, and `ACTIVE` state. Maintenance
repairs or removes orphaned `CREATING` records and indexes. A race with a
concurrent creator is resolved by stable flow ID/generation comparison; the
losing creator rolls back without deleting the winner's entries.

### D-TC-010 — Test-run and terminal-state semantics

`bpf_prog_test_run`/`bpf_prog_test_run_opts` tests use ordered fixture
sequences for policy miss, flow creation, forward packet, reverse packet,
FIN/ACK progression, and RST. They assert packet bytes, action, checksums,
and map state after each step. Because test-run may not model every attached
TC context or metadata field, a small attached-TC integration test remains
required when the target kernel exposes materially different behavior.

For terminal cleanup, an RST always wins and removes the flow immediately.
After both directional FIN/ACK requirements are observed, the terminal grace
deadline is authoritative; idle TTL cannot delete the flow earlier, and a
late packet before the deadline updates activity but does not reopen the TCP
state. A late packet after terminal deletion starts a new flow only if a
current policy matches.

## Invariants

| ID | Invariant |
|---|---|
| INV-TC-001 | A rewritten packet has an exact, validated policy and canonical flow record. |
| INV-TC-002 | Ingress and egress tuple transformations are symmetric and checksum-correct. |
| INV-TC-003 | One flow ID owns both directional lookups and one canonical lifecycle state. |
| INV-TC-004 | Existing flows retain their snapped target across policy updates. |
| INV-TC-005 | Missing policy passes unchanged; map-capacity/insertion failure drops and is observable. |
| INV-TC-006 | No malformed, non-initial, or unsupported packet causes unsafe access or partial rewrite. |
| INV-TC-007 | TCP terminal cleanup removes all owned indexes/state; UDP/QUIC use idle TTL only. |
| INV-TC-008 | Readiness requires all v2 programs and v1 policy/index/state maps. |
