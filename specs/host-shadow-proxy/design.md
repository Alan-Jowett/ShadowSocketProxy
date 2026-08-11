<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Host Shadow Proxy Design

## 1. Scope and Traceability

This design implements REQ-009 through REQ-015 from `requirements.md`.

```text
USER-REQUEST -> REQ-* -> D-* -> TC-* -> implementation/test artifacts
```

The flow-map ABI, Linux TC lifecycle, and `GetMapping` RPC remain compatible.
The control service now has a v3 packet-program/runtime configuration surface,
but the proxy continues to consume only the existing mapping contract.

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

TCP and the first datagram of an active UDP association send an exact
`GetMapping` request. Returned mappings are validated for the same synthetic
tuple, matching protocol and family, and a non-unspecified original
destination. A UDP mapping is never cached across a different synthetic key;
an existing association is reused until expiry, explicit invalidation, or the
controlled destination-specific retry path.

### D-013 — Windows TLS-PSK gRPC client

Implement a client transport adapter using OpenSSL/Tokio OpenSSL on Windows,
constrained to TLS 1.2 PSK and h2 ALPN, matching the control-service server
policy. Feed the authenticated stream into tonic's generated
`ControlClient`.

The adapter owns credential handling and maps handshake/configuration
failures to startup errors. The PSK is accepted from a protected file or
environment variable, not required to appear directly in a process-visible
argument. No plaintext, metadata-only, or unauthenticated fallback exists.

### D-014 — TCP session bridge and Windows conditional admission

On non-Windows, retain the existing Tokio accept, lookup, connect, and bridge
path. On Windows, bind the native listener with `SO_CONDITIONAL_ACCEPT` and
drive `WSAAccept` from a dedicated coordinator thread. The callback returns
`CF_DEFER` for a reserved attempt and the bridge is created only from the
matching `CF_ACCEPT` client socket plus preconnected outbound socket.

The bridge runs two concurrent copy directions. EOF half-closes the
corresponding outbound direction; completion or fatal error cancels the peer
direction and closes both sockets. Outbound source binding is not attempted
because the approved behavior requires connection to the original destination,
not source impersonation.

### D-015 — UDP association table

Maintain an in-memory association keyed by the complete observed synthetic
UDP tuple. Each entry stores the client address, an outbound UDP socket
connected to the mapped original destination, last activity, and cancellation
state.

The receive loop performs an authenticated mapping lookup only while creating
or replacing an association. A per-association task relays responses only to
that entry's client. An existing outbound association is reused for its exact
synthetic tuple without another lookup; expiry, host flow invalidation, or a
controlled destination-specific failure permits re-resolution. Both successful
outbound sends and successful replies update the association activity time.
An idle reaper removes entries after the configured timeout. A missing mapping
drops the datagram.

UDP forwarding failures are logged through a one-second rate limiter so a
persistent control-plane or network failure cannot flood the host logs.

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

At Ctrl-C, the runtime signals forwarding shutdown, joins TCP bridge,
maintenance, and UDP relay work, and only then issues the bounded detach RPC.
All control RPCs carry a tonic deadline and are locally bounded so shutdown
cannot wait indefinitely on a hung control channel.

### D-018 — Native listener and backlog configuration

`ProxyConfig.listen_backlog` and `--listen-backlog` default to 1024. Windows
first binds the native TCP socket, enables `SO_CONDITIONAL_ACCEPT`, and calls
native `listen` with that backlog before UDP binds the exact selected TCP
socket address. Port zero and an explicit IPv4/IPv6 family are preserved.

The native backlog is validated only in the Windows `i32` range and is never
used to allocate an application channel. Winsock re-invokes a condition
callback only for the deferred queue head, so the proxy has one fixed
conditional work slot and does not claim to process multiple deferred
connections concurrently. This is an explicit safe limitation, not a
conditional-backlog guarantee.

### D-019 — Prompt condition callback

The callback decodes only the supplied caller and callee socket-address bytes,
forming the exact TCP synthetic tuple. It fills one preallocated conditional
attempt slot, performs a bounded atomic reservation, a nonblocking unit-queue
`try_send`, and event signal, then returns `CF_DEFER`. The fixed slot and
unit queue avoid heap allocation in the callback. Its `try_lock` contention
is a resource failure and returns `CF_REJECT`, never blocking. It does no
Winsock call, RPC, socket operation, Tokio operation, or logging.

### D-020 — Coordinator and callback lifetime

The coordinator owns the native listener and repeatedly invokes nonblocking
`WSAAccept`. A manual-reset Windows event wakes it for worker completion and
shutdown; a bounded polling interval also services the queue head. The
callback receives an `Arc`-backed stable context pointer. The listener task
and coordinator retain that context until the coordinator joins, so no
callback can observe a dangling pointer. Fallible worker/coordinator startup,
native worker/runtime failures, thread panics, and both layers of native joins
propagate through `run_bound`.

### D-021 — Preconnect worker execution context

A distinct native preconnect worker thread owns a Tokio current-thread runtime.
It dequeues deferred attempts, runs `MappingClient::get_mapping`, validates
protocol, family, non-unspecified address, and port, and connects outbound.
The lookup/connect deadline is the remaining portion of five seconds measured
from the first `CF_DEFER`. This avoids `Handle::block_on` on a Tokio runtime
thread. Cancellation changes the attempt state and drops the pending async
operation.

### D-022 — Attempt identity, generations, and repeated defers

The fixed queue-head slot stores the exact caller/local TCP tuple and a
monotonic generation. A repeated callback for that deferred tuple returns
`CF_DEFER` using the existing state; another tuple is rejected until the slot
reaches a terminal state. Worker completion is applied only if its tuple and
generation still match the slot; late results drop their outbound socket.
Terminal removal releases admission exactly once.

### D-023 — Socket handoff ownership

Worker success stores an RAII-owned outbound socket before marking the request
ready. The callback atomically changes ready to claimed and returns
`CF_ACCEPT`; the coordinator removes the matching state and transfers both
raw sockets as one handoff. Conversion to Tokio streams occurs before a bridge
is spawned. Every failed claim, conversion, channel send, stale completion,
post-`CF_ACCEPT` `WSAAccept` failure, or shutdown path drops both
untransferred owners and releases the admission/handoff reservation; no
accepted socket is published without its matching outbound socket.

### D-024 — Conditional shutdown ordering

Shutdown takes the fixed-slot lock, then closes admission and removes the
attempt. This is the linearization point after which a ready callback cannot
claim `CF_ACCEPT`. It drops any prepared outbound socket, signals the
coordinator event, cancels worker operations, joins coordinator and worker
threads, aborts/joins TCP bridges, and clears UDP associations and maintenance
before returning from the proxy. The executable performs BPF detach only
after `run_bound` returns.

## 3. Invariants

| ID | Invariant |
|---|---|
| INV-008 | Every lookup key is the exact observed synthetic 5-tuple for that flow. |
| INV-009 | A forwarding action uses only the original destination returned for its validated lookup key. |
| INV-010 | TCP peer shutdown and UDP association removal cannot leave an owned socket/task alive. |
| INV-011 | UDP responses are delivered only to the client address recorded for their association. |
| INV-012 | No forwarding path bypasses authenticated control lookup or falls back to direct destination inference. |
| INV-013 | A PSK secret is never written to logs, diagnostics, or successful responses. |
| INV-014 | A Windows condition callback returns promptly without heap allocation, Winsock, blocking, RPC, re-entrant, or logging operations. |
| INV-015 | The one Windows queue-head `CF_DEFER` has one bounded admission reservation and queued request, released exactly once. |
| INV-016 | A Windows `CF_ACCEPT` is preceded by successful exact mapping validation and outbound TCP connection. |
| INV-017 | No TCP bridge reconnects an outbound socket prepared for conditional acceptance. |
| INV-018 | An attempt identity is its exact caller/local tuple plus a monotonic generation. |
| INV-019 | A stale generation result cannot publish a socket and closes any owned outbound socket. |
| INV-020 | A repeated deferred callback reuses the matching pending request state. |
| INV-021 | An accepted client socket cannot be published without its paired outbound socket. |
| INV-022 | Callback context memory remains valid until the coordinator/`WSAAccept` thread has stopped. |
| INV-023 | Conditional shutdown rejects pending work and joins native/forwarding owners before BPF detach. |
| INV-024 | UDP binds the actual TCP-selected address, port, and family. |
| INV-025 | After conditional shutdown linearizes, no ready attempt can claim `CF_ACCEPT`. |
| INV-026 | A failed/closed handoff and a post-`CF_ACCEPT` native failure release the exact attempt's prepared socket, admission, and handoff reservation. |

## 4. Impact Map

| Requirement | Design | Validation | Implementation surfaces |
|---|---|---|---|
| REQ-009 | D-011, D-017 | TC-037–TC-039 | workspace, host-proxy runtime/listeners |
| REQ-010 | D-012, D-016 | TC-040–TC-043, TC-058 | tuple conversion, mapping client |
| REQ-011 | D-014, D-019–D-023 | TC-044–TC-047, TC-059, TC-068–TC-078 | TCP conditional admission and bridge |
| REQ-012 | D-015 | TC-048–TC-052, TC-058–TC-059 | UDP association table |
| REQ-013 | D-013, D-016 | TC-053–TC-054, TC-060 | TLS/gRPC client |
| REQ-014 | D-011, D-017, D-018 | TC-037–TC-039, TC-055, TC-066–TC-067, TC-081–TC-083 | CLI/bootstrap and bind ordering |
| REQ-015 | D-011, D-015, D-016, D-024 | TC-056–TC-057, TC-076–TC-080 | cancellation and resource cleanup |

## 5. Explicit No-Impact Decisions

- The BPF packet-rewriting target selection may change independently of the
  proxy; the versioned flow-mapping ABI remains unchanged.
- The `GetMapping` protobuf RPC is reused without schema changes.
- Linux control-service target/listener configuration is outside the proxy.
- The proxy does not bind original source addresses.
- QUIC receives UDP forwarding treatment and no TCP-state interpretation.
