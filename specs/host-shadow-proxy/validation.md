<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Host Shadow Proxy Validation

## 1. Validation Strategy

Validation covers REQ-009 through REQ-015 and INV-008 through INV-013.
Unit tests use mocked `GetMapping` responses and loopback TCP/UDP sockets.
Windows-specific OpenSSL/tonic integration tests are target- and
environment-gated and report missing PSK-capable prerequisites explicitly.

Existing control-service validation remains unchanged because the new proxy
consumes the existing `GetMapping` contract without modifying it.

## 2. Test Cases

| ID | Requirement | Scenario | Expected result |
|---|---|---|---|
| TC-037 | REQ-009/014 | Build `host-proxy` for Windows target | Build succeeds with documented features/dependencies |
| TC-038 | REQ-009 | Bind shared TCP/UDP IPv4 endpoint | Both listeners bind and use the configured port |
| TC-039 | REQ-009/014 | Bind IPv6 endpoint and construct IPv6 tuple | IPv6 flow data remains family-correct |
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
```

Windows-specific integration tests MUST be feature- or environment-gated and
MUST fail clearly when required OpenSSL PSK support or runtime prerequisites
are unavailable. Linux control-service checks remain green without
pretending to provide the Windows host proxy runtime.
