<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Host Shadow Proxy Validation

## 1. Validation Strategy

Validation covers REQ-009 through REQ-015 and INV-008 through INV-013.
Unit tests use mocked `GetMapping` responses and loopback TCP/UDP sockets.
Windows-specific OpenSSL/tonic integration tests are target- and
environment-gated and report missing PSK-capable prerequisites explicitly.

The proxy validation continues to use the existing `GetMapping` contract.
Control-service v3 target/listener validation is covered by the TC-BPF
validation specification and is not duplicated here.

## 2. Test Cases

| ID | Requirement | Scenario | Expected result |
|---|---|---|---|
| TC-037 | REQ-009/014 | Build `host-proxy` for Windows target | Build succeeds with documented features/dependencies |
| TC-038 | REQ-009 | Bind shared TCP/UDP IPv4 endpoint | Both listeners bind and use the configured port |
| TC-039 | REQ-009/014 | Bind IPv6 endpoint and construct IPv6 tuple | IPv6 flow data remains family-correct |
| TC-039A | REQ-014 | Configure an unspecified/wildcard listen address | Startup rejects the configuration before listeners are ready |
| TC-040 | REQ-010 | TCP observed tuple lookup | Exact peer-to-local tuple is sent to `GetMapping` |
| TC-041 | REQ-010 | UDP observed tuple lookup | Exact peer-to-local tuple is sent to `GetMapping` |
| TC-042 | REQ-010 | Missing mapping | TCP closes; UDP drops; no direct fallback |
| TC-043 | REQ-010 | Malformed or mismatched mapping response | Forwarding is rejected and no wrong destination is used |
| TC-044 | REQ-011 | Bidirectional TCP payload copy | Payloads arrive unchanged in both directions |
| TC-045 | REQ-011 | Client EOF | Corresponding direction half-closes; reverse direction can finish |
| TC-046 | REQ-011 | Original EOF or fatal I/O | Peer direction is cancelled and both sockets close |
| TC-047 | REQ-011 | Outbound connect failure | Accepted connection closes and failure is observable |
| TC-048 | REQ-012 | UDP request forwarding | Datagram reaches mapped original destination |
| TC-049 | REQ-012 | UDP response relay | Response returns only to the originating client |
| TC-050 | REQ-012 | Two simultaneous UDP flows | Responses do not cross flow boundaries |
| TC-051 | REQ-012 | UDP/QUIC payload | Payload forwards with UDP treatment and no TCP state |
| TC-052 | REQ-012/015 | UDP idle timeout | Association, socket, and task are removed after timeout |
| TC-053 | REQ-013 | Valid TLS-PSK gRPC lookup | Authenticated `GetMapping` succeeds |
| TC-054 | REQ-013 | Wrong PSK, plaintext, or unsupported PSK | Startup or lookup fails explicitly; no readiness |
| TC-055 | REQ-014 | Invalid CLI configuration | Startup fails before listener readiness |
| TC-056 | REQ-015 | Shutdown with active TCP/UDP work | Listeners stop and all owned tasks/sockets terminate |
| TC-057 | REQ-015 | OS send/connect/resource failure | Error is surfaced/logged; no success-shaped forwarding |
| TC-058 | REQ-010/012 | Mapping changes between UDP associations | Existing association is not reused for another synthetic tuple |
| TC-059 | REQ-011/012 | Concurrent TCP and UDP flows | Independent flows remain isolated and complete safely |
| TC-060 | REQ-013/015 | Secret-bearing config/log paths | PSK identity/secret is absent from logs and error text |
| TC-061 | REQ-010/012 | Multiple datagrams on one UDP association | The first datagram performs `GetMapping`; subsequent datagrams reuse the same destination and socket without another mapping RPC. |
| TC-062 | REQ-012/015 | Persistent UDP forwarding failure | Failure logging is rate-limited and does not emit one warning per datagram |
| TC-063 | REQ-012 | Continuous one-way UDP sends | Successful outbound sends refresh the idle lease; the association expires only after outbound and inbound activity stop. |
| TC-064 | REQ-015 | Ctrl-C with active forwarding | Shutdown joins TCP and UDP forwarding tasks before the bounded control detach request begins. |
| TC-065 | REQ-015 | Hung control operation | Maintenance and detach operations observe cancellation or their deadline and do not block shutdown indefinitely. |
| TC-066 | REQ-014 | Omit `--listen-backlog`; configure zero and out-of-range values | Default is 1024; invalid values fail configuration before listeners are ready. |
| TC-067 | REQ-014 | Windows native TCP listener setup | The configured backlog is passed to native `listen` and is documented as an application pending-attempt limit, not a conditional-backlog guarantee. |
| TC-068 | REQ-011 | Windows condition callback on a new TCP tuple | Callback performs bounded reservation/queue/event work and returns `CF_DEFER` without Winsock, RPC, blocking, re-entry, or logging. |
| TC-069 | REQ-011/015 | Pending conditional attempts exceed `listen_backlog` | Only the configured number reserve state; excess attempts receive `CF_REJECT`; each released attempt frees exactly one admission. |
| TC-070 | REQ-011 | Repeated callback for a deferred exact tuple | The same request identity is reused and returns `CF_DEFER`, without an additional reservation or lookup. |
| TC-071 | REQ-011 | Worker completion after the tuple is released and reused | A distinct higher generation owns the new request; stale success is ignored and closes its socket. |
| TC-072 | REQ-011 | Deferred mapping lookup begins late | Lookup plus connect are bounded by five seconds measured at first `CF_DEFER`, not worker start. |
| TC-073 | REQ-011 | Mapping missing, malformed, protocol/family-mismatched, or unspecified | Worker marks the request rejected; coordinator returns `CF_REJECT` and publishes no socket. |
| TC-074 | REQ-011 | Outbound TCP connect failure or resource error | Worker marks the request rejected; failure is observable and no accepted client socket is published. |
| TC-075 | REQ-011 | Valid mapping and outbound connection | Worker prepares one outbound socket; callback returns `CF_ACCEPT`; TCP bridge reuses that socket and does not connect a second time. |
| TC-076 | REQ-011/015 | Shutdown while lookup or connect is pending | Admission stops, the worker operation is cancelled, its socket is closed if produced, and worker/coordinator threads join. |
| TC-077 | REQ-011 | Accepted raw socket or Tokio conversion handoff failure | Both client and paired outbound owners close; no half-handoff reaches a bridge. |
| TC-078 | REQ-011 | Worker result races cancellation or a claimed request | State transition permits only one handoff; terminal/stale result sockets close. |
| TC-079 | REQ-015 | Shutdown with deferred and ready conditional requests | Pending requests are rejectable, prepared outbound sockets close, and forwarding tasks join before `run_bound` returns. |
| TC-080 | REQ-011/015 | Callback context teardown | Context remains allocated through coordinator/`WSAAccept` stop and is reclaimed only after thread join. |
| TC-081 | REQ-014 | TCP bind with port zero | UDP binds the actual selected TCP address and port rather than the requested zero port. |
| TC-082 | REQ-014 | Explicit IPv4 and IPv6 TCP listeners | UDP binds the matching selected family and mapping tuples retain that family. |
| TC-083 | REQ-011/014/015 | Non-Windows build and Windows test availability | Non-Windows TCP behavior remains unchanged and unit regressions pass; Windows runs a deterministic loopback `SO_CONDITIONAL_ACCEPT`/`WSAAccept` bridge test. |

## 3. Property and Invariant Checks

- Tuple conversion is bijective for supported IPv4/IPv6 observations.
- Every `GetMapping` request exactly matches the observed synthetic tuple.
- A mapping with mismatched family/protocol or unspecified destination is never
  used for forwarding.
- TCP half-close does not terminate an otherwise healthy reverse direction.
- Every UDP response is sent only to its recorded association client.
- Idle UDP associations eventually release their socket and task.
- No forwarding path succeeds without an authenticated mapping lookup.
- No secret value appears in logs, diagnostics, or RPC responses.
- `CF_ACCEPT` is impossible without a ready matching outbound socket, and a
  ready outbound socket is impossible without a successful exact validation
  and connect.
- Deferred-request generations are monotonic; a stale generation cannot
  transfer or leak its socket.
- Conditional admission count is never greater than `listen_backlog` and
  every request decrements it at most once.
- The callback context outlives every `WSAAccept` callback.

## 4. Failure Semantics

The implementation MUST distinguish:

- invalid CLI/configuration (`INVALID_ARGUMENT` or startup failure);
- unauthenticated or incorrect TLS-PSK (`UNAUTHENTICATED` or startup
  failure);
- missing mapping (`NOT_FOUND`, then TCP close or UDP drop);
- malformed/mismatched mapping (`FAILED_PRECONDITION` or explicit local
  validation error);
- backend/control transport failure (`UNAVAILABLE`/`INTERNAL`, then close or
  drop);
- outbound connect/send/receive failure (explicit log and resource cleanup);
- OS/resource exhaustion (explicit error; never a successful forwarding
  result);
- cancellation/shutdown (deterministic task and socket cleanup).

No test may accept direct forwarding or an empty successful response when the
mapping or forwarding operation failed.

## 5. Validation Commands

The implementation phase will use repository-supported commands:

```text
cargo fmt --check
cargo check -p shadow-socket-proxy-host
cargo test -p shadow-socket-proxy-host
cargo check --workspace
cargo test --workspace
cargo clippy -p shadow-socket-proxy-host --all-targets -- -D warnings
```

Windows-specific integration tests MUST be feature- or environment-gated and
MUST fail clearly when required OpenSSL PSK support or runtime prerequisites
are unavailable. Linux control-service checks remain green without
pretending to provide the Windows host proxy runtime.

TC-067 through TC-080 combine focused state-machine tests with the Windows
loopback conditional-accept bridge test. Live TLS-PSK control-plane validation
remains environment-gated on a PSK-capable OpenSSL installation.
