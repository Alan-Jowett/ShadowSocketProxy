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
requires a nonzero `--udp-idle-timeout-secs` and never falls back to direct
forwarding when a mapping lookup fails.

The optional `wsk` feature adds the versioned user-mode broker/device ABI and
runtime selection for the kernel-owned forwarding path:

```text
cargo check -p shadow-socket-proxy-host --features wsk
```

On Windows, pass `--wsk` to run the authenticated inverted-call mapping
broker and host-owned maintenance while the installed driver owns TCP/UDP
listeners. WSK mode currently requires the driver's fixed port `15000`.

### Build and run WSK mode

Install the native Windows toolchain before building. In Visual Studio
Installer, add **Desktop development with C++**, the matching Windows 10/11
SDK, and the Windows Driver Kit (WDK). The WDK build scripts also consume the
pinned NuGet content packages, so install the exact versions used by this
repository from an available `nuget.exe`:

```powershell
$nugetRoot = "$env:USERPROFILE\.nuget\packages"
nuget.exe install Microsoft.Windows.WDK.x64 `
  -Version 10.0.28000.2526 -OutputDirectory $nugetRoot
nuget.exe install Microsoft.Windows.SDK.CPP `
  -Version 10.0.28000.2526 -OutputDirectory $nugetRoot
```

If `nuget.exe` is not on `PATH`, install the NuGet CLI first or download
`nuget.exe` from [nuget.org](https://www.nuget.org/downloads). The commands
must leave these directories available:

```text
%USERPROFILE%\.nuget\packages\microsoft.windows.wdk.x64\10.0.28000.2526\c
%USERPROFILE%\.nuget\packages\microsoft.windows.sdk.cpp\10.0.28000.2526\c
```

The WSK binding generator also requires LLVM's `libclang.dll`. Install LLVM
if it is not already present, then point bindgen at its `bin` directory:

```powershell
winget install --id LLVM.LLVM --exact `
  --accept-source-agreements --accept-package-agreements

$env:LIBCLANG_PATH = "$env:ProgramFiles\LLVM\bin"
$env:PATH = "$env:LIBCLANG_PATH;$env:PATH"
```

Verify that the configured directory contains `libclang.dll` before building.
If LLVM is installed elsewhere, set `LIBCLANG_PATH` to that directory instead.

Build the user-mode proxy and kernel driver from an elevated Windows
PowerShell prompt. The driver target must match the installed WDK
architecture:

```powershell
$env:WDKContentRoot = "$env:USERPROFILE\.nuget\packages\microsoft.windows.wdk.x64\10.0.28000.2526\c"

cargo build --locked --release -p shadow-socket-proxy-wsk-driver `
  --features kernel --target x86_64-pc-windows-msvc
cargo build --locked --release -p shadow-socket-proxy-host `
  --features "tls-psk,wsk"
```

The driver is a kernel-mode binary and must be signed before Windows will load
it. For development, use a test certificate and test-signing mode according to
the Windows driver-signing workflow; production deployments require a
Microsoft-approved signing path. After signing, install the driver as a
kernel service from an elevated prompt, replacing the path with the built
driver location:

```powershell
sc.exe create ShadowSocketProxyWsk type= kernel start= demand `
  binPath= "$PWD\target\x86_64-pc-windows-msvc\release\shadow_socket_proxy_wsk_driver.dll"
sc.exe start ShadowSocketProxyWsk
```

Start the host proxy with the same control-service options used by the
Tokio-owned path, plus `--wsk` and a listener port of `15000`:

```powershell
.\target\release\shadow-socket-proxy-host.exe `
  --wsk `
  --listen 127.0.0.1:15000 `
  --control-endpoint https://127.0.0.1:50051 `
  --psk-identity $identity `
  --psk-secret-file .\ssp-demo.psk
```

In WSK mode, the driver owns the TCP and UDP listeners and forwards established
payloads directly in kernel mode. The host process handles mapping lookups and
maintenance only; payload bytes do not traverse user mode once a flow is
established. Stop the proxy before unloading the driver:

```powershell
sc.exe stop ShadowSocketProxyWsk
sc.exe delete ShadowSocketProxyWsk
```

The driver currently admits at most 64 TCP flows or UDP associations, fails
closed when capacity is exhausted, expires mapping requests after 5 seconds,
and removes mapped flows after 60 seconds of inactivity. Live signed-driver,
multi-flow, cancellation-race, and ARM64 validation are not yet automated.

`crates/wsk-driver` provides fixed ABI structs, session nonces, request IDs,
generations, broker state validation, and a Windows `DeviceIoControl` transport.
Its `kernel` feature is a WDM cdylib boundary: it discovers the pinned
`Microsoft.Windows.WDK.x64` or `.ARM64` NuGet package, generates WSK bindings
from checked-in wrappers for `ws2.h`, `ws2def.h`, and `wsk.h`, exports
`DriverEntry`, installs device IOCTL dispatch, and registers a WSK provider.
The driver binds fixed loopback TCP and UDP listeners on port `15000`, uses an
inverted-call mapping wait per admitted flow, validates the broker's exact
synthetic/original tuple completion, applies mapping and idle-flow timeouts, and
forwards established TCP and UDP indications directly between WSK sockets using
provider-owned MDL buffers. Payload forwarding does not issue per-packet IOCTLs
or use a user-mode fallback. The kernel flow state uses a bounded shared table
of 64 TCP flows and UDP associations; admission fails closed when all slots are
occupied.
Missing WDK/SDK packages fail with an explicit build error.
The official WDK crates also require `WDKContentRoot`; for the pinned x64
NuGet package, set it to
`%USERPROFILE%\.nuget\packages\microsoft.windows.wdk.x64\10.0.28000.2526\c`
before invoking the Windows kernel build.

The target-gated kernel compile can be checked with:

```powershell
cargo check --locked --target x86_64-pc-windows-msvc `
  -p shadow-socket-proxy-wsk-driver --features kernel
```

Configure the listener and control service with CLI options; provide the PSK through `--psk-secret`,
`SSP_TLS_PSK_SECRET`, or `--psk-secret-file`. The listen address must be a specific local IPv4 or IPv6
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
process its own pair plus the SHA-256 pin of the peer certificate DER. A
rustls listener has one configured peer-leaf pin, so every client connecting
to that listener must use the same pinned client certificate; the E2E driver
therefore shares one client pair between the host proxy and runner. The same
three `--tls-*` options can be supplied through `SSP_TLS_*` variables;
supplying a value through both forms is rejected.

### Start the demo with TLS-PSK

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

### Start the demo with rustls certificate pinning

Build the control service and Windows binaries with the rustls feature:

```powershell
wsl -d Ubuntu -- bash -lc `
  'cd /mnt/c/dev/ShadowSocketProxy &&
   cargo build --locked --release -p shadow-socket-proxy-control --features tls-rustls'
cargo build --locked --release -p shadow-socket-proxy-host --features tls-rustls
cargo build --locked --release -p shadow-socket-proxy-e2e-runner --features tls-rustls
```

Use one self-signed PEM certificate/key pair for the control service and one
shared client PEM certificate/key pair for the host proxy and runner. Compute
the SHA-256 pins from each certificate's exact DER bytes. The control service
must be configured with the client certificate pin; the Windows clients must
be configured with the control certificate pin.

In the first PowerShell terminal, start the rustls control service:

```powershell
$clientPin = '<sha256-of-client-certificate-der>'

wsl -d Ubuntu -u root -- env `
  RUST_LOG=info `
  SSP_LISTEN_ADDR=127.0.0.1:50051 `
  SSP_TC_HOOK_LAYOUT=wsl `
  SSP_TLS_CERT_FILE=/mnt/c/dev/ShadowSocketProxy/certs/control-cert.pem `
  SSP_TLS_KEY_FILE=/mnt/c/dev/ShadowSocketProxy/certs/control-key.pem `
  SSP_TLS_PEER_CERT_SHA256=$clientPin `
  /mnt/c/dev/ShadowSocketProxy/target/release/shadow-socket-proxy-control
```

In the second PowerShell terminal, start the rustls Windows host proxy:

```powershell
$gateway = (wsl -d Ubuntu -- ip route show default).Split()[2]
$controlPin = '<sha256-of-control-certificate-der>'

.\target\release\shadow-socket-proxy-host.exe `
  --listen "${gateway}:15000" `
  --control-endpoint https://127.0.0.1:50051 `
  --tls-cert-file .\certs\client-cert.pem `
  --tls-key-file .\certs\client-key.pem `
  --tls-peer-cert-sha256 $controlPin `
  --bpf-elf /mnt/c/dev/ShadowSocketProxy/crates/bpf/shadow-socket-proxy.bpf.o `
  --interface eth0
```

Do not provide PSK flags or `SSP_TLS_PSK_*` variables in rustls mode. The
host proxy and E2E runner must use the same client certificate because the
control service accepts one configured peer certificate pin.

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

The checked-in Windows/WSL driver defaults to the deployed BPF, control service,
and host proxy with an ephemeral TLS-PSK. That default requires Windows, an
installed WSL distribution, and the Windows OpenSSL/Rust prerequisites:

```powershell
cargo build --locked --release -p shadow-socket-proxy-e2e-runner --features tls-psk
.\scripts\run-windows-wsl-e2e.ps1 `
  -Transport psk `
  -BpfArtifact .\artifacts\bpf\shadow-socket-proxy.bpf.o `
  -ControlArtifact .\artifacts\control\shadow-socket-proxy-control `
  -HostArtifact .\artifacts\host
```

For rustls-only end-to-end validation, build all three artifacts with rustls:

```powershell
wsl -d Ubuntu -- bash -lc `
  'cd /mnt/c/dev/ShadowSocketProxy &&
   cargo build --locked --release -p shadow-socket-proxy-control --features tls-rustls'
cargo build --locked --release -p shadow-socket-proxy-host --features tls-rustls
cargo build --locked --release -p shadow-socket-proxy-e2e-runner --features tls-rustls
```

Provide a PEM certificate/key pair for the control service and one shared PEM
client pair for the host proxy and runner. Set the control-service pin to the
client certificate's DER SHA-256 and the client pin to the control certificate's
DER SHA-256, then select the rustls branch of the driver:

```powershell
.\scripts\run-windows-wsl-e2e.ps1 `
  -Transport rustls `
  -BpfArtifact .\crates\bpf\shadow-socket-proxy.bpf.o `
  -ControlArtifact .\target\release\shadow-socket-proxy-control `
  -HostArtifact .\target\release `
  -TlsControlCertificateFile .\certs\control-cert.pem `
  -TlsControlKeyFile .\certs\control-key.pem `
  -TlsControlPeerCertSha256 <shared-client-certificate-pin> `
  -TlsClientCertificateFile .\certs\client-cert.pem `
  -TlsClientKeyFile .\certs\client-key.pem `
  -TlsClientPeerCertSha256 <control-certificate-pin>
```

The driver passes the control identity through `SSP_TLS_*` variables and the
Windows identities through CLI flags. The rustls branch does not install or use
OpenSSL; no PSK or hostname fallback is attempted.

The command fails when WSL, BPF/TC, authentication, process, marker,
mapping, counter, or cleanup prerequisites are unavailable; it never falls
back to direct forwarding.

Local runs retain the selected WSL distribution and its existing TC setup.
CI passes `-TerminateDistribution` because it uses a disposable hosted
distribution.
