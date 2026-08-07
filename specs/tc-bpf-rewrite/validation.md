<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# TC BPF Rewrite Validation

## Validation Strategy

Use ABI/property tests and the control-service backend test double on all
platforms. Run BPF verifier, checksum, TC attachment, and packet-path tests
only when the repository-supported Linux kernel, clang, libbpf, and Aya
capabilities are available. Packet-path tests SHOULD invoke the loaded
`SCHED_CLS` programs through the kernel `bpf_prog_test_run` API (or
`bpf_prog_test_run_opts`) with captured packet fixtures, then inspect output
bytes, return action, checksum validity, and expected policy/flow-map effects.
Fixtures MUST include ordered stateful sequences for policy miss, flow
creation, forward rewrite, reverse rewrite, FIN/ACK teardown, and RST. Where
the target kernel exposes TC context or metadata behavior that test-run cannot
model, a small attached-TC integration test MUST cover that boundary.
Environment-gated tests MUST fail clearly when required capabilities are
absent rather than report false readiness.

## Test Cases

| ID | Requirement | Scenario | Expected result |
|---|---|---|---|
| TC-TC-001 | REQ-TC-006 | Build/load required BPF artifact | Linux artifact builds; all required maps/programs and ABI versions are discovered; missing or mixed symbols fail attach. |
| TC-TC-002 | REQ-TC-006 | Non-Linux build | Unsupported adapter remains explicit; no false TC readiness. |
| TC-TC-003 | REQ-TC-002 | Set/list/delete policy | Authenticated idempotent CRUD round-trips exact TCP/UDP IPv4/IPv6 entries. |
| TC-TC-004 | REQ-TC-002 | Invalid policy | Zero/overflow port, unsupported protocol, malformed address, family mismatch, and capacity exhaustion are rejected atomically. |
| TC-TC-005 | REQ-TC-002 | Concurrent policy replacement | BPF lookup sees a complete old or new target, never partial bytes. |
| TC-TC-006 | REQ-TC-001 | Ingress IPv4 TCP/UDP rewrite | Destination-only rewrite and L3/L4 checksums are correct; source tuple is unchanged. |
| TC-TC-007 | REQ-TC-001 | Ingress IPv6 TCP/UDP rewrite | Header bounds are safe; destination-only rewrite and checksums are correct. |
| TC-TC-008 | REQ-TC-001 | Egress reverse rewrite | Target-to-client packets restore source to the original destination; client tuple remains unchanged. |
| TC-TC-009 | REQ-TC-001 | No-policy/family mismatch | Packet passes unchanged and miss telemetry increments. |
| TC-TC-010 | REQ-TC-005 | Malformed/fragment/unsupported packet | Packet passes unchanged; no out-of-bounds access or checksum mutation. |
| TC-TC-011 | REQ-TC-003 | Concurrent first packets | Both directions converge on one flow ID and no tuple is associated with another flow. |
| TC-TC-012 | REQ-TC-003 | Flow-map full/insertion failure | Eligible packet drops and bounded failure telemetry is visible. |
| TC-TC-013 | REQ-TC-003 | Policy update with active flow | Existing flow uses snapped target; a new flow uses the replacement target. |
| TC-TC-014 | REQ-TC-004 | TCP state progression | SYN, SYN/ACK, ACK, one-sided FIN, bidirectional FIN/ACK, and RST state encode/decode correctly. |
| TC-TC-015 | REQ-TC-004 | TCP teardown | RST deletes immediately; completed FIN/ACK deletes after grace; incomplete FIN remains. |
| TC-TC-016 | REQ-TC-004 | UDP/QUIC lifecycle | Last-used updates; no TCP flags; cleanup occurs only after idle TTL. |
| TC-TC-017 | REQ-TC-006 | Runtime limits | Policy/flow capacities and terminal grace update atomically; invalid or oversized values retain the prior revision. |
| TC-TC-018 | REQ-TC-006 | Maintenance partial cleanup | Idle/terminal deletion, index races, decode failures, and backend errors are counted and never reported as full success. |
| TC-TC-019 | REQ-TC-003 | Mapping RPC compatibility | Host-proxy lookup by ingress synthetic tuple returns the exact snapped original tuple; canonical list/get never mixes directions. |
| TC-TC-020 | REQ-TC-006 | Attach/detach/shutdown | Required links and maps are transactionally owned; rollback and shutdown report partial cleanup. |
| TC-TC-021 | REQ-TC-005/006 | Security/failure semantics | Unauthorized policy/config/attach is rejected; no direct-forward fallback; secrets and payloads are not logged. |
| TC-TC-022 | REQ-TC-001/003/005 | `bpf_prog_test_run` ingress/egress fixtures | The kernel test-run API executes both classifiers against valid and invalid IPv4/IPv6 TCP/UDP fixtures; output bytes, TC action, checksums, and policy/flow-map effects match the expected rewrite/pass/drop behavior. |
| TC-TC-023 | REQ-TC-003 | Multi-map partial insertion | Inject failure after canonical-state or one-index creation; rollback removes all attempt-owned entries and no `CREATING` flow can rewrite packets. |
| TC-TC-024 | REQ-TC-003 | Concurrent flow creators | Two creators for one tuple converge on one flow ID; the losing creator cannot delete the winner's indexes or state. |
| TC-TC-025 | REQ-TC-004 | Terminal deadline precedence | RST deletes immediately; idle TTL cannot delete a FIN-complete flow before terminal grace; late pre-deadline traffic updates activity without reopening state. |
| TC-TC-026 | REQ-TC-006 | Fixed maxima and runtime caps | Runtime admission caps never exceed discovered ELF map maxima; cap changes do not resize maps or require re-attach; invalid caps preserve the prior revision. |

## Impact Map

| Requirement | Design | Validation | Implementation surfaces |
|---|---|---|---|
| REQ-TC-001 | D-TC-001, D-TC-002, D-TC-006, D-TC-008 | TC-TC-001–TC-TC-010, TC-TC-022 | `crates/bpf`, Aya adapter, TC tests |
| REQ-TC-002 | D-TC-001, D-TC-004, D-TC-007 | TC-TC-003–TC-TC-005 | protobuf, policy ABI, service/backend |
| REQ-TC-003 | D-TC-002, D-TC-003, D-TC-007, D-TC-009 | TC-TC-011–TC-TC-013, TC-TC-019, TC-TC-022–TC-TC-024 | flow index/state ABI, mapping service |
| REQ-TC-004 | D-TC-003, D-TC-005, D-TC-007, D-TC-010 | TC-TC-014–TC-TC-018, TC-TC-025 | BPF lifecycle, maintenance worker |
| REQ-TC-005 | D-TC-002, D-TC-006 | TC-TC-006–TC-TC-010, TC-TC-021–TC-TC-022 | packet parser/checksum code |
| REQ-TC-006 | D-TC-007, D-TC-008, D-TC-010 | TC-TC-001, TC-TC-004, TC-TC-017–TC-TC-022, TC-TC-026 | config, attach lifecycle, status |

## Explicit No-Impact Decisions

- Host-proxy forwarding and source-binding behavior remain unchanged.
- QUIC remains UDP activity only.
- Existing TLS/authentication policy is reused for new policy/configuration
  RPCs.
- Cleanup remains bounded by the configured scan batch.
- Linux BPF/TC integration remains environment-gated; ABI and lifecycle unit
  tests run through the backend test double where kernel facilities are absent.
