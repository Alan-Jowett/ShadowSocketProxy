<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Host Shadow Proxy Requirements

## Change Set

### CHG-009 — Add the Windows host shadow proxy

- **Before:** The repository has no host-side executable that accepts
  redirected TCP/UDP traffic and forwards it using the original flow
  destination.
- **After:** Add a `crates/host-proxy` Windows-capable Rust executable that
  listens on one configured address/port for both TCP and UDP, resolves each
  observed synthetic 5-tuple through the existing authenticated
  `Control.GetMapping` RPC, and forwards traffic to the returned original
  destination.
- **Traceability:** `USER-REQUEST: implement the "Host shadow proxy"... The
  shadow socket proxy will run on Windows.`

### CHG-010 — TCP forwarding lifecycle

- **Before:** Redirected TCP connections are not handled by a host proxy.
- **After:** For each accepted TCP connection, query the original tuple,
  connect outbound to the original destination, copy bytes bidirectionally,
  preserve half-close behavior, and close both peers when the forwarding
  session terminates or a fatal I/O error occurs.
- **Traceability:** `USER-REQUEST: For TCP make an outbound connection to that
  address and then copy traffic between the new connection and the accepted
  connection.`

### CHG-011 — UDP forwarding and response relay

- **Before:** Redirected UDP datagrams are not handled by a host proxy.
- **After:** For each received UDP datagram, query the original tuple, send it
  to the original destination, and relay response datagrams to the originating
  client. Maintain per-flow associations with an idle timeout; QUIC remains
  UDP treatment without TCP-state assumptions.
- **Traceability:** `USER-REQUEST: For UDP forward the packet to original
  address.` User clarification: `Forward requests and relay responses
  (Recommended)` and `Yes, bounded per-flow associations with idle timeout
  (Recommended)`.

### CHG-012 — Synthetic tuple construction and lookup failures

- **Before:** No host-side rule defines how redirected socket observations map
  to control-service lookup keys.
- **After:** Construct the synthetic tuple from the observed flow as client
  peer address/port to proxy local address/port, preserving address family and
  transport protocol. Use exact `GetMapping`; on lookup failure or `NOT_FOUND`,
  TCP closes and UDP drops the datagram, with bounded logging and no direct
  fallback.
- **Traceability:** User clarifications: `Yes, use the observed client/proxy
  5-tuple (Recommended)` and `Close/drop with bounded logging; never fall back
  (Recommended)`.

### CHG-013 — Windows control-plane transport

- **Before:** No Windows proxy client exists for the control service.
- **After:** The proxy reuses the existing protobuf contract and `GetMapping`
  RPC through a TCP gRPC client secured with TLS 1.2 PSK using a
  Windows-capable OpenSSL build with PSK support. Missing or unsupported
  TLS-PSK capability is a startup failure; credentials are never logged.
- **Traceability:** User clarifications: `Yes, reuse GetMapping and TLS-PSK
  (Recommended)` and `Use OpenSSL with TLS-PSK on Windows (Recommended)`.

### CHG-014 — Proxy configuration and platform scope

- **Before:** No configuration or platform contract exists for the host
  proxy.
- **After:** The executable accepts CLI configuration for the shared listen
  endpoint, control-service endpoint, PSK identity, PSK secret source, UDP
  idle timeout, and operational settings. It supports IPv4 and IPv6 and is
  intended to run on Windows; no configuration-file requirement is
  introduced. The PSK secret may be supplied through an environment variable
  or protected file to avoid process-list exposure.
- **Traceability:** User clarifications: `One shared address and port for both
  protocols (Recommended)`, `IPv4 and IPv6 (Recommended)`, `CLI arguments
  only`, `Allow --psk-secret-env or protected-file input (Recommended)`, and
  `Yes, add crates/host-proxy (Recommended)`.

### CHG-015 — Resource policy

- **Before:** No proxy concurrency policy exists.
- **After:** The proxy does not impose application-level TCP or UDP-flow caps;
  it relies on operating-system/resource errors. UDP associations still
  expire according to the configured idle timeout.
- **Traceability:** `Unbounded, relying on OS/resource errors`.

## Stable Requirements

### REQ-009 — Windows host proxy executable

The deliverable MUST add a workspace crate and executable for the Windows
host shadow proxy. It MUST bind one configured port for TCP and UDP and
support IPv4 and IPv6.

**Acceptance criteria**

- The crate builds for the documented Windows target.
- TCP and UDP listeners bind the configured port.
- Invalid or conflicting CLI configuration fails startup explicitly.
- The proxy does not silently fall back to direct forwarding or plaintext
  control traffic.

**Invariant impact:** Establishes the host data-plane owner without changing
BPF tuple-rewrite semantics.

### REQ-010 — Exact original-destination lookup

For every accepted TCP connection and received UDP datagram, the proxy MUST
construct the observed synthetic 5-tuple and call the authenticated
`GetMapping` RPC. The returned original tuple MUST be associated with the
same synthetic tuple and address family.

**Acceptance criteria**

- IPv4 and IPv6 TCP/UDP tuples round-trip into exact lookup requests.
- Missing mappings are distinguished from transport/backend failures.
- No original destination from a different flow is used.
- A response with mismatched protocol/family or an unspecified destination is
  rejected.
- Lookup failures produce explicit bounded logs and no direct-connect fallback.

**Invariant impact:** Preserves tuple identity across BPF, gRPC, and proxy
forwarding.

### REQ-011 — TCP forwarding

For TCP, after a successful mapping lookup, the proxy MUST connect to the
mapped original destination and copy bytes in both directions. It MUST
preserve half-close semantics and MUST close the peer when the session ends
due to EOF or fatal I/O failure.

**Acceptance criteria**

- Client-to-original and original-to-client payloads are forwarded without
  unintended transformation.
- Outbound connect failure closes the accepted side and is observable.
- EOF in one direction shuts down that direction while allowing the other
  direction to finish.
- Session completion closes both sockets and releases resources.

**Invariant impact:** Prevents connection leaks and prevents traffic from
being sent to an incorrect destination.

### REQ-012 — UDP forwarding and relay

For UDP, the proxy MUST send each mapped datagram to the original destination
and relay responses to the originating client using a per-flow association.
Associations MUST expire after the configured idle timeout.

**Acceptance criteria**

- UDP and QUIC-over-UDP payloads are forwarded with no TCP-state
  interpretation.
- Responses return only to the correct client flow.
- Missing mappings drop the datagram without a direct-send fallback.
- Idle associations are removed and no response is sent to an expired
  association.
- Send/receive failures are surfaced through bounded logs.

**Invariant impact:** Maintains client-flow ownership and prevents cross-flow
response delivery.

### REQ-013 — Authenticated Windows gRPC client

The proxy MUST use the existing `GetMapping` protobuf RPC over authenticated
TLS 1.2 PSK gRPC. It MUST fail startup when configured credentials or the
required PSK-capable transport cannot be initialized.

**Acceptance criteria**

- Correct identity/secret permits lookup.
- Incorrect credentials, plaintext, and unsupported PSK builds do not yield
  successful lookups.
- The PSK secret is not logged or returned in diagnostics.
- Control-service errors remain distinguishable from mapping-not-found.

**Invariant impact:** Prevents unauthorized mapping disclosure and accidental
insecure operation.

### REQ-014 — CLI configuration and platform support

The proxy MUST expose CLI configuration for listen endpoint, control
endpoint, PSK identity, PSK secret source, UDP idle timeout, and operational
settings. It MUST support Windows IPv4/IPv6 operation and document required
build/runtime dependencies.

**Acceptance criteria**

- Required values are validated before listeners report readiness.
- A shared port is documented for the configured IPv4 and/or IPv6 listener
  sockets.
- Explicit-family and wildcard/dual-stack binding failures are reported.
- Windows startup and shutdown behavior is deterministic.
- Linux-only control-service/BPF behavior remains unaffected.

**Invariant impact:** Keeps platform boundaries explicit and avoids
misleading cross-platform readiness.

### REQ-015 — Resource and shutdown behavior

The proxy MUST rely on OS/resource errors rather than introduce
application-level TCP or UDP-flow caps. It MUST cancel active tasks and close
listener/flow resources during shutdown.

**Acceptance criteria**

- Resource exhaustion is observable rather than converted into successful
  forwarding.
- TCP sessions and UDP associations terminate on shutdown.
- No task retains a socket after shutdown completes.

**Invariant impact:** Prevents unbounded lifetime leaks while preserving the
selected resource policy.

## Non-Goals

- Changing the BPF packet-rewriting program or mapping ABI.
- Adding a new control-service RPC.
- Binding the original source address for outbound TCP/UDP sockets.
- Direct forwarding when mapping lookup fails.
- Application-level TCP connection or UDP association caps.
- Implementing QUIC-specific state beyond UDP forwarding and idle activity.
