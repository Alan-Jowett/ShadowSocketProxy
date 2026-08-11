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

Prototype. Global TCP/UDP packet rewriting, flow mapping, and proxy bridging
are implemented. Kernel attachment and packet-path verification remain
Linux-environment gated.

## Container control service

The Linux-targeted Rust control service is in `crates/control-service`, with
the shared protobuf contract in `crates/proto` and the Linux TC BPF artifact
source in `crates/bpf`:

```text
cargo build --target x86_64-unknown-linux-gnu -p shadow-socket-proxy-control --features tls-psk
cargo test --workspace --no-default-features
```

It provides the versioned mapping ABI, replaceable BPF/TC backend,
protobuf/gRPC service, configuration snapshots, and bounded log pull.
Host-proxy owns the maintenance worker, expiry policy, retries, flow deletion,
and local UDP association behavior; for maintenance, control-service exposes
only typed flow-operation adapters.
On Linux, the production backend uses Aya for ELF loading, versioned
map/program discovery, TC ingress/egress links, transactional rollback, and
map operations. Runnable control-service builds must select exactly one
transport feature; neither is the default:

```text
cargo build --locked -p shadow-socket-proxy-control --features tls-psk
cargo build --locked -p shadow-socket-proxy-control --features tls-rustls
```

Feature-neutral library and test compilation remains supported, but each
runnable TLS-selected binary built without either feature exits nonzero with an
explicit `tls-psk`/`tls-rustls` feature-selection diagnostic.

`tls-psk` preserves the OpenSSL TLS 1.2 PSK and h2 ALPN behavior. `tls-rustls`
uses TCP gRPC over h2 with TLS 1.2/1.3, mutual self-signed PEM certificates,
and a normalized SHA-256 pin of the peer leaf certificate's exact DER bytes.
Rustls validates the pinned leaf's signature, validity, and key usage without
requiring a hostname. Missing, malformed, or ambiguous startup settings fail;
there is no plaintext or cross-mode fallback. Rustls builds do not require
OpenSSL.

Rustls runtime settings are startup-only and may be supplied by either CLI
flags or their environment variables (not both):

```text
--tls-cert-file <PEM>             SSP_TLS_CERT_FILE
--tls-key-file <PEM>              SSP_TLS_KEY_FILE
--tls-peer-cert-sha256 <HEX>      SSP_TLS_PEER_CERT_SHA256
```

The pin parser is case-insensitive and normalizes an optional `0x` prefix,
whitespace, `:` separators, and `-` separators.

## Windows host shadow proxy

The Windows host proxy is in `crates/host-proxy`. It listens for redirected
TCP and UDP flows, resolves each observed synthetic tuple through the
authenticated `GetMapping` RPC, connects TCP flows to the original destination,
and forwards UDP datagrams with response relaying. It also owns the maintenance
worker and lifecycle policy for stale flows.

Build the default workspace target with:

```text
cargo build -p shadow-socket-proxy-host
```

Windows deployments can choose either transport; neither feature is enabled by
default:

```text
cargo build -p shadow-socket-proxy-host --features tls-psk
cargo build -p shadow-socket-proxy-host --features tls-rustls
```

The PSK build requires a PSK-capable OpenSSL installation and accepts
`--psk-secret`, `SSP_TLS_PSK_SECRET`, or `--psk-secret-file`. The rustls build
uses the certificate flags above and does not require OpenSSL. The proxy
requires a nonzero
`--udp-idle-timeout-secs` and never falls back to direct forwarding when a
mapping lookup fails. The listen address must be a specific local IPv4 or IPv6
address, not a wildcard address, so UDP lookups preserve the actual local
destination tuple. `--listen-backlog` defaults to 1024 and is passed to native
`listen` on Windows. Winsock calls a conditional-accept callback only for the
deferred queue head, so the proxy processes one deferred attempt at a time;
the configured native backlog neither sizes internal queues nor promises
parallel conditional admission.

## Windows/WSL demo deployment

This is a prototype, not a hardened production service. The following procedure
runs the same control service, BPF program, and Windows host proxy that a demo
uses. It redirects all eligible new IPv4 TCP and UDP flows from the selected
WSL interface through the Windows proxy. The proxy creates the actual outbound
connections, so only use a disposable WSL distribution or a quiet demo
environment.

The host needs Windows, WSL 2, a WSL distribution with BPF/TC support, and
Rust 1.96.1 available in both Windows and WSL. The PSK example additionally
requires a PSK-capable OpenSSL installation. The examples use an Ubuntu
distribution named `Ubuntu`, a repository at `C:\dev\ShadowSocketProxy`, and
the default WSL interface
`eth0`.

### Build the components

Install the Linux build and runtime prerequisites as WSL root, then build as
the normal WSL user:

```powershell
wsl -d Ubuntu -u root -- sh -c `
  'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y `
   build-essential clang llvm linux-libc-dev libssl-dev pkg-config make `
   iproute2 python3 ca-certificates'

wsl -d Ubuntu -- bash -lc `
  'cd /mnt/c/dev/ShadowSocketProxy &&
   make -C crates/bpf clean all &&
   cargo build --locked --release -p shadow-socket-proxy-control --features tls-psk'
```

For the PSK mode, install the Windows OpenSSL development package and build the
host components:

```powershell
winget install --id ShiningLight.OpenSSL.Dev --version 4.0.1 --exact `
  --scope machine --accept-source-agreements --accept-package-agreements

$openssl = Get-ChildItem 'C:\Program Files' -Directory -Filter 'OpenSSL*' |
  ForEach-Object { Join-Path $_.FullName 'bin\openssl.exe' } |
  Where-Object { Test-Path $_ } |
  Select-Object -First 1
$opensslRoot = Split-Path (Split-Path $openssl -Parent) -Parent
$env:OPENSSL_DIR = $opensslRoot
$env:OPENSSL_LIB_DIR = Join-Path $opensslRoot 'lib\VC\x64\MD'

cargo build --locked --release -p shadow-socket-proxy-host --features tls-psk
```

For rustls mode, no OpenSSL installation is needed:

```powershell
cargo build --locked --release -p shadow-socket-proxy-host --features tls-rustls
```

Generate one self-signed certificate/key pair for each endpoint and pass each
process its own pair plus the SHA-256 pin of the peer certificate DER. The
same three `--tls-*` options can be supplied through `SSP_TLS_*` variables;
supplying a value through both forms is rejected.

### Start the demo

Open three PowerShell terminals in the repository. First, calculate the WSL
gateway address and create one PSK shared by the control service and proxy:

```powershell
$gateway = (wsl -d Ubuntu -- ip route show default).Split()[2]
$identity = 'ssp-demo'
$secret = [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
$secret | Set-Content -NoNewline .\ssp-demo.psk
```

In the first terminal, load the shared credentials and start the control
service as WSL root. WSL traffic leaves through physical egress, so
`SSP_TC_HOOK_LAYOUT=wsl` is required here. Do not set that variable for a
native Linux deployment, which uses the default ingress/egress layout.

```powershell
$identity = 'ssp-demo'
$secret = (Get-Content -Raw .\ssp-demo.psk).Trim()

wsl -d Ubuntu -u root -- env `
  RUST_LOG=info `
  SSP_LISTEN_ADDR=127.0.0.1:50051 `
  SSP_TC_HOOK_LAYOUT=wsl `
  SSP_TLS_PSK_IDENTITY=$identity `
  SSP_TLS_PSK_SECRET=$secret `
  /mnt/c/dev/ShadowSocketProxy/target/release/shadow-socket-proxy-control
```

In the second terminal, rediscover the gateway, identity, and OpenSSL path
before starting the Windows proxy. The `127.0.0.1` control endpoint uses WSL
localhost forwarding, while the proxy listens on the WSL gateway address that
BPF will use as its synthetic destination. The proxy authenticates to the
control service, attaches the supplied BPF ELF to the interface, and sets its
own listener as the global target before it accepts traffic.

```powershell
$gateway = (wsl -d Ubuntu -- ip route show default).Split()[2]
$identity = 'ssp-demo'
$openssl = Get-ChildItem 'C:\Program Files' -Directory -Filter 'OpenSSL*' |
  ForEach-Object { Join-Path $_.FullName 'bin\openssl.exe' } |
  Where-Object { Test-Path $_ } |
  Select-Object -First 1
$opensslRoot = Split-Path (Split-Path $openssl -Parent) -Parent
$env:PATH = "$opensslRoot\bin;$env:PATH"
$env:RUST_LOG = 'info'

.\target\release\shadow-socket-proxy-host.exe `
  --listen "${gateway}:15000" `
  --control-endpoint https://127.0.0.1:50051 `
  --psk-identity $identity `
  --psk-secret-file .\ssp-demo.psk `
  --bpf-elf /mnt/c/dev/ShadowSocketProxy/crates/bpf/shadow-socket-proxy.bpf.o `
  --interface eth0
```

The proxy prints `connected to control service` followed by `attached BPF
program and configured proxy target`. The control-service terminal prints
`BPF program attached`; `wsl -d Ubuntu -u root -- bpftool prog list` also shows
the loaded programs. Each accepted TCP connection and newly created UDP
association then prints an unconditional forwarding record with its client,
proxy, and original destination.

In the third terminal, optionally start a local marker server and demonstrate
the redirected WSL-to-Windows path:

```powershell
$gateway = (wsl -d Ubuntu -- ip route show default).Split()[2]
$marker = 'ssp-demo-marker'
$markerProcess = Start-Process pwsh -PassThru -ArgumentList @(
  '-NoProfile', '-File', '.\scripts\tcp-marker-server.ps1',
  '-BindAddress', $gateway, '-Port', '18080', '-Marker', $marker
)

wsl -d Ubuntu -- python3 -c `
  "import socket; s = socket.create_connection(('$gateway', 18080), 10); s.sendall(b'demo\n'); print(s.recv(1024).decode().strip()); s.close()"
```

After the marker validation succeeds, WSL applications can make normal
outbound connections; their eligible IPv4 TCP and UDP flows are redirected
through the Windows proxy. For example:

```powershell
wsl -d Ubuntu -- python3 -c `
  "import socket; s = socket.create_connection(('1.1.1.1', 443), 10); print(s.getpeername()); s.close()"
```

### Stop the demo

Press `Ctrl+C` in the proxy terminal; it detaches the BPF links it attached.
Then stop the control service and marker process, and remove the temporary PSK
file:

```powershell
Stop-Process -Id $markerProcess.Id
Remove-Item .\ssp-demo.psk
```

## Documentation

The generated site combines private-item Rustdoc with Doxygen for the
canonical BPF source. From a clean checkout with Rust 1.96.1 and Doxygen:

```text
python scripts/check-rustdoc.py
```

PowerShell:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --locked --workspace --no-deps --document-private-items
```

POSIX shell:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --document-private-items
```

Then, on either platform:

```text
python -c "import shutil; shutil.rmtree('docs/.generated', ignore_errors=True); shutil.rmtree('site', ignore_errors=True)"
doxygen docs/Doxyfile
python scripts/assemble-docs.py --site-dir site
```

The disposable `site/` directory contains `index.html`, `rustdoc/`, and
`bpf/`; it is not committed to the source branch.

## Windows/WSL end-to-end validation

The checked-in Windows/WSL driver exercises the deployed BPF, control service,
and host proxy with an ephemeral TLS-PSK. It requires Windows, an installed
WSL distribution, and the Windows OpenSSL/Rust prerequisites:

```powershell
cargo build --locked --release -p shadow-socket-proxy-e2e-runner --features tls-psk
.\scripts\run-windows-wsl-e2e.ps1 `
  -BpfArtifact .\artifacts\bpf\shadow-socket-proxy.bpf.o `
  -ControlArtifact .\artifacts\control\shadow-socket-proxy-control `
  -HostArtifact .\artifacts\host
```

For a rustls-only runner build, use:

```powershell
cargo build --locked --release -p shadow-socket-proxy-e2e-runner --features tls-rustls
```

The runner also supports the three certificate
flags/environment variables above. In rustls mode, the control service,
host proxy, and runner each require their own PEM identity and the pin for
the peer leaf; no PSK or hostname fallback is attempted.

The command fails when WSL, BPF/TC, authentication, process, marker,
mapping, counter, or cleanup prerequisites are unavailable; it never falls
back to direct forwarding.

Local runs retain the selected WSL distribution and its existing TC setup.
CI passes `-TerminateDistribution` because it uses a disposable hosted
distribution.
