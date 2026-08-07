<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Requirements

## Change Set

### CHG-001 — Implement TC ingress/egress rewriting and destination policy

- **Before:** The repository has only a placeholder BPF ELF contract; no
  packet-rewriting program or writable destination-policy map exists.
- **After:** A buildable Linux BPF artifact exports versioned destination-policy
  and active-flow maps plus ingress/egress TC classifiers. Authenticated
  control-service RPCs validate, atomically set/delete/list policy entries
  keyed by exact protocol, original destination IP, and destination port.
  New flows snapshot the target IP/port; policy changes affect only new flows.
- **Traceability:** `USER-REQUEST: create a spec and implementation for the
  ingress and egress TC BPF programs that perform rewrite of the TCP/UDP and
  IPv4/IPv6 headers...`

## Stable Requirements

### REQ-TC-001 — Bidirectional same-family DNAT

Ingress MUST rewrite only the destination IP/port for parseable TCP/UDP
first-fragment packets matching a policy. Egress MUST reverse-rewrite only the
source IP/port for the corresponding target-to-client flow. Client source and
return destination tuples MUST be preserved. IPv4 policies apply only to IPv4
packets and IPv6 policies only to IPv6 packets; cross-family translation is
unsupported.

**Acceptance criteria**

- TCP and UDP IPv4/IPv6 rewrites update all required checksums.
- Egress restores the original destination as the packet source.
- No-policy and family-mismatch behavior is safe and observable.

**Invariant impact:** Packet tuple identity remains consistent across TC, the
flow map, and the host proxy.

### REQ-TC-002 — Destination-policy ABI and control API

The versioned ABI MUST add a destination-policy map containing the original
destination family/address/port, protocol, target family/address/port, and
schema version. Authenticated set/delete/list RPCs MUST validate entries,
support idempotent operations, enforce configured bounds, and replace one
complete value atomically from the BPF lookup perspective.

**Acceptance criteria**

- TCP/UDP IPv4/IPv6 policy entries round-trip through set/list/delete.
- Duplicate set/delete operations are idempotent.
- Malformed, cross-family, unsupported-protocol, capacity, and concurrent
  update failures are explicit and leave prior state intact.

**Invariant impact:** BPF observes either the old or new complete policy.

### REQ-TC-003 — Canonical bidirectional active-flow state

The active-flow map MUST maintain one canonical flow record linked to three
lookup keys: the original client-to-destination tuple, the synthetic
client-to-target tuple used by the host proxy, and the reverse target-to-client
tuple. It MUST cover TCP and UDP with the original tuple, snapped target tuple,
reverse tuple, protocol, last-used monotonic time, and lifecycle metadata.
Active-flow insertion/full-map failure MUST drop the
eligible packet and expose bounded counters/logs. Policy misses and safely
unparseable or unsupported packets MUST pass unchanged.

**Acceptance criteria**

- Concurrent bidirectional packets converge on one flow record.
- Missing policy passes unchanged.
- Insertion/full-map failure drops and is observable.
- ABI decode errors are explicit.

**Invariant impact:** No duplicate or inconsistent flow state is exposed.

### REQ-TC-004 — TCP lifecycle and cleanup

TCP state MUST record SYN, SYN/ACK, ACK, FIN, and RST observations for both
directions. RST MUST delete the canonical flow immediately. FIN MUST retain
state until both directions complete FIN/ACK teardown, then delete after a
configurable bounded terminal grace period. A TCP flow that never completes
teardown MUST still expire through idle-TTL maintenance. UDP and
QUIC-over-UDP MUST have no TCP state and MUST expire only through idle-TTL
maintenance.

**Acceptance criteria**

- TCP state transitions round-trip through the ABI.
- One-sided FIN is retained.
- Completed bidirectional FIN/ACK is deleted after grace.
- Incomplete or abandoned TCP flows expire by idle TTL.
- RST deletes immediately.
- UDP/QUIC remain idle-TTL managed.

**Invariant impact:** Teardown is not premature and closed flows are removed.

### REQ-TC-005 — Packet safety and protocol scope

Only fully bounds-checkable TCP/UDP first fragments with valid headers are
eligible for rewrite and checksum recomputation. Malformed packets,
unsupported protocols, non-initial fragments, and non-linear/unreadable
headers MUST pass unchanged. Policy matching is exact; wildcard protocol
entries are not required.

**Acceptance criteria**

- Malformed, truncated, optioned, fragmented, and non-linear cases do not
  cause unsafe access or rewrite.
- Valid IPv4/IPv6 TCP/UDP headers and checksums are correct.
- Unsupported traffic is unchanged.

**Invariant impact:** Packet safety is preserved without applying TCP
assumptions to UDP/QUIC.

### REQ-TC-006 — Runtime limits and service integration

The control service MUST load and validate the new versioned BPF symbols/maps
and expose authenticated runtime configuration for policy admission capacity,
active-flow admission capacity, map scan batch/TTL, and TCP terminal FIN grace
period. ELF map `max_entries` values are fixed load-time maxima; runtime
capacities are bounded admission caps and MUST NOT imply in-place kernel map
resizing. Updates MUST be atomically validated and bounded. Existing active
flows retain their snapped target across policy changes.

**Acceptance criteria**

- ELF symbol and ABI validation is complete before readiness.
- Valid configuration updates publish one coherent revision.
- Runtime admission caps never exceed fixed ELF map maxima.
- Zero, overflow, contradictory, and oversized values are rejected.
- Concurrent data-plane, maintenance, and configuration operations observe
  coherent revisions.
- Shutdown and maintenance report cleanup failures.

**Invariant impact:** Control-plane/data-plane synchronization and resource
limits remain deterministic.

## Non-Goals

- Cross-family NAT or encapsulation.
- SNAT or source-address impersonation.
- Wildcard policy matching.
- Protocol-specific QUIC close tracking.
- Rewriting malformed or non-initial fragments.
- Replacing TC with another interception mechanism.
- Unrelated host-proxy redesign.
