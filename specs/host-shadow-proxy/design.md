<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Host Shadow Proxy Design

## 1. Scope and Traceability

This design implements REQ-009 through REQ-015 from `requirements.md`.

```text
USER-REQUEST -> REQ-* -> D-* -> TC-* -> implementation/test artifacts
```

The existing BPF ABI, control-service RPC schema, Linux TC lifecycle, and
control-service implementation remain unchanged. The new proxy consumes the
existing `GetMapping` RPC.

## 2. Component Architecture

### D-011 — Host-proxy crate and runtime

Add `crates/host-proxy` to the workspace with platform-neutral forwarding
logic and Windows transport/bootstrap code. The runtime starts one TCP
listener and one UDP socket on the configured shared port, plus a gRPC
mapping client.

Startup validates CLI values and TLS-PSK initialization before listeners are
considered ready. Tokio owns listener tasks and cancellation. Shutdown stops
accepts, closes the UDP association table, and allows active TCP tasks to
terminate.

### D-012 — Synthetic tuple extraction

For TCP, derive:

```text
source      = accepted.peer_addr()
destination = accepted.local_addr()
protocol    = TCP
ports       = observed source/destination ports
```

For UDP, derive the same tuple from `recv_from()`'s peer address and the
bound local address, with protocol UDP. Address family is preserved.

Each lookup sends an exact `GetMapping` request. Returned mappings are
validated for the same synthetic tuple, matching protocol and family, and a
non-unspecified original destination. A mapping is never cached across a
different synthetic key.

### D-013 — Windows TLS-PSK gRPC client

Implement a client transport adapter using OpenSSL/Tokio OpenSSL on Windows,
constrained to TLS 1.2 PSK and h2 ALPN, matching the control-service server
policy. Feed the authenticated stream into tonic's generated
`ControlClient`.

The adapter owns credential handling and maps handshake/configuration
failures to startup errors. The PSK is accepted from a protected file or
environment variable, not required to appear directly in a process-visible
argument. No plaintext, metadata-only, or unauthenticated fallback exists.

### D-014 — TCP session bridge

For each accepted connection, perform lookup, connect to
`original.destination`, and run two concurrent copy directions. EOF
half-closes the corresponding outbound direction; completion or fatal error
cancels the peer direction and closes both sockets.

Outbound source binding is not attempted because the approved behavior
requires connection to the original destination, not source impersonation.

### D-015 — UDP association table

Maintain an in-memory association keyed by the complete observed synthetic
UDP tuple. Each entry stores the client address, an outbound UDP socket
connected to the mapped original destination, last activity, and cancellation
state.

The receive loop forwards client datagrams. A per-association task relays
responses only to that entry's client. An idle reaper removes entries after
the configured timeout. A missing mapping drops the datagram. A changed
mapping creates or replaces only the affected association after exact-key
validation.

The selected resource policy does not impose a maximum association count;
allocation, socket, and send/receive errors remain observable.

### D-016 — Errors, logging, and limits

Use explicit typed errors for invalid CLI input, control
transport/authentication failure, mapping-not-found, malformed mapping,
connect/send/receive failure, and shutdown.

TCP lookup/connect failures close the client connection. UDP lookup/send
failures drop the datagram. Logs are bounded by the proxy's configured
logging policy; secrets and full payloads are excluded.

### D-017 — CLI and lifecycle

Expose CLI options for shared listen address/port, control endpoint, PSK
identity, PSK secret environment variable or protected file, UDP idle
timeout, and logging/runtime settings.

The listen address MUST be a specific IPv4 or IPv6 address rather than a
wildcard. This is required because UDP tuple lookup needs the actual local
destination address; Tokio's basic `recv_from` API does not expose the
destination address selected by the host for wildcard receives. The supported
runtime target is Windows.

## 3. Invariants

| ID | Invariant |
|---|---|
| INV-008 | Every lookup key is the exact observed synthetic 5-tuple for that flow. |
| INV-009 | A forwarding action uses only the original destination returned for its validated lookup key. |
| INV-010 | TCP peer shutdown and UDP association removal cannot leave an owned socket/task alive. |
| INV-011 | UDP responses are delivered only to the client address recorded for their association. |
| INV-012 | No forwarding path bypasses authenticated control lookup or falls back to direct destination inference. |
| INV-013 | A PSK secret is never written to logs, diagnostics, or successful responses. |

## 4. Impact Map

| Requirement | Design | Validation | Implementation surfaces |
|---|---|---|---|
| REQ-009 | D-011, D-017 | TC-037–TC-039 | workspace, host-proxy runtime/listeners |
| REQ-010 | D-012, D-016 | TC-040–TC-043, TC-058 | tuple conversion, mapping client |
| REQ-011 | D-014 | TC-044–TC-047, TC-059 | TCP session bridge |
| REQ-012 | D-015 | TC-048–TC-052, TC-058–TC-059 | UDP association table |
| REQ-013 | D-013, D-016 | TC-053–TC-054, TC-060 | TLS/gRPC client |
| REQ-014 | D-011, D-017 | TC-037–TC-039, TC-055 | CLI/bootstrap |
| REQ-015 | D-011, D-015, D-016 | TC-056–TC-057 | cancellation and resource cleanup |

## 5. Explicit No-Impact Decisions

- The BPF packet-rewriting logic is unchanged.
- The versioned mapping ABI is unchanged.
- The `GetMapping` protobuf RPC is reused without schema changes.
- Linux control-service behavior and existing tests are unchanged.
- The proxy does not bind original source addresses.
- QUIC receives UDP forwarding treatment and no TCP-state interpretation.
