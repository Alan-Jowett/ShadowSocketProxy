<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy

ShadowSocketProxy demonstrates a WSL networking model where outbound TCP/UDP flows are intercepted inside the Linux side and transparently proxied through a host‑side process. The container believes it is connecting normally; the host actually owns the external socket.

## Overview

Outbound packets are rewritten to target a host‑visible proxy socket. The proxy establishes the real external connection, forwards data bidirectionally, and preserves flow semantics. Inbound packets are rewritten back to the container’s original tuple so applications see a normal connection.





## Components

- **TC‑attached BPF program** — Intercepts inbound/outbound packets, rewrites L3/L4 tuples, and maintains a per‑flow redirection map in a BPF hash.
- **Container gRPC control service** — Loads the BPF program, exposes the redirection map to the host, and provides minimal control/inspection hooks.
- **Host shadow proxy** — Listens for redirected flows, performs the real outbound connect(), and bridges traffic between the container and the external endpoint.





## Why this exists

WSL’s NAT model breaks VPNs, packet inspection, and tools that rely on owning the real socket. ShadowSocketProxy gives the host full visibility and control over outbound flows while keeping the container unmodified.

## How it works (short version)

1. Container app calls `connect()`.
2. BPF rewrites the destination to the host proxy.
3. Host proxy receives the synthetic connection, looks up the original tuple via gRPC.
4. Host proxy establishes the real external connection.
5. Proxy shuttles bytes between both sides until teardown.

## Status

Prototype. Packet rewriting, flow mapping, and proxy bridging are functional. Future work includes QUIC support, better failure semantics, and selective flow interception.

## Container control service

The Linux-targeted Rust control service is in `crates/control-service`, with
the shared protobuf contract in `crates/proto` and the placeholder BPF program
in `crates/bpf`:

```text
cargo build --target x86_64-unknown-linux-gnu
cargo test
```

It provides the versioned mapping ABI, replaceable BPF/TC backend, maintenance
worker, protobuf/gRPC service, configuration snapshots, and bounded log pull.
On Linux, the production backend uses Aya for ELF loading, versioned
map/program discovery, TC ingress/egress links, transactional rollback, and
map operations. The TCP gRPC endpoint uses OpenSSL with TLS 1.2 PSK and h2
ALPN; invalid credentials or a build without PSK support fail startup rather
than falling back to plaintext, metadata-only auth, or mTLS. Linux builds
require an OpenSSL development installation whose build enables PSK.

## Windows host shadow proxy

The Windows host proxy is in `crates/host-proxy`. It listens for redirected
TCP and UDP flows, resolves each observed synthetic tuple through the
authenticated `GetMapping` RPC, connects TCP flows to the original destination,
and forwards UDP datagrams with response relaying.

Build the default workspace target with:

```text
cargo build -p shadow-socket-proxy-host
```

Windows deployments that provide a PSK-capable OpenSSL installation must build
the runnable proxy with:

```text
cargo build -p shadow-socket-proxy-host --features tls-psk
```

Configure the listener and control service with CLI options; provide the PSK through `--psk-secret`,
`SSP_TLS_PSK_SECRET`, or `--psk-secret-file`. The proxy requires a nonzero
`--udp-idle-timeout-secs` and never falls back to direct forwarding when a
mapping lookup fails. The listen address must be a specific local IPv4 or IPv6
address, not a wildcard address, so UDP lookups preserve the actual local
destination tuple.
