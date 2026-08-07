<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Design

## Traceability

```text
USER-REQUEST -> CHG-001..004 -> REQ-TC-001..007
             -> D-TC-001..009 -> TC-TC-001..025
             -> BPF, backend, protobuf, service, lifecycle, and test changes
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
per flow and never resizes maps. Existing TCP/UDP lifecycle and maintenance
cleanup semantics remain unchanged.

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
