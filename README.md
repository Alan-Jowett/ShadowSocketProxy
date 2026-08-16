<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy

ShadowSocketProxy redirects selected TCP and UDP traffic from Linux/WSL
through a Windows data plane. The Linux control service owns the TC/BPF
redirection maps; the Windows side resolves each synthetic flow and forwards
traffic to its original destination.

Two data planes are available:

- **User mode** (default): the Windows host proxy owns forwarding.
- **Kernel mode** (`kernel-relay`): the WSK driver owns forwarding. This path
  is experimental and requires a disposable, kernel-debuggable Windows VM.

TLS is required for the control channel. Choose exactly one:

- **TLS-PSK** (`tls-psk`): OpenSSL PSK transport.
- **rustls** (`tls-rustls`): mutual TLS with certificate pinning.

## Quick start

Run all commands from the repository root in PowerShell.

| Goal | Command |
| --- | --- |
| User mode + TLS-PSK | `cargo xtask build --release --features wsl tls-psk` |
| User mode + rustls | `cargo xtask build --release --features wsl tls-rustls` |
| Kernel mode + TLS-PSK | `cargo xtask build --release --features wsl tls-psk kernel-relay test-signing` |
| Kernel mode + rustls | `cargo xtask build --release --features wsl tls-rustls kernel-relay test-signing` |

The first build provisions missing dependencies, builds the selected Linux
and Windows components, and publishes them under:

```text
target\ssp-build\release\
```

The build is deterministic for the selected feature set. `tls-psk` and
`tls-rustls` are mutually exclusive. `test-signing` is valid only with
`kernel-relay`.

## Prerequisites

### Windows

Install or enable:

- Windows 10/11 x64.
- Git.
- Rust/Cargo with the `x86_64-pc-windows-msvc` target.
- Visual Studio C++ build tools, including the MSVC x64 toolset and Windows
  SDK.
- PowerShell and `winget`.
- WSL 2 with an Ubuntu distribution.

The orchestrator automatically restores the pinned WDK/SDK NuGet packages,
installs the required WSL packages, and provisions Windows LLVM/OpenSSL when
needed.

For kernel builds, the orchestrator uses LLVM **18.1.8** for WDK binding
generation. A different installed LLVM version is not a compatible substitute.

### Optional environment overrides

Use these only when automatic discovery does not match the machine:

```powershell
$env:SSP_WSL_DISTRO = 'Ubuntu'
$env:SSP_VCVARS64_BAT = 'C:\Path\To\vcvars64.bat'
$env:SSP_LLVM_PACKAGE_VERSION = '18.1.8'
$env:SSP_OPENSSL_PACKAGE_VERSION = '4.0.1'
$env:SSP_SIGNTOOL = 'C:\Path\To\signtool.exe'
```

The WDK/SDK package roots can also be supplied explicitly:

```powershell
$env:SSP_WSK_NUGET_ROOT = "$env:USERPROFILE\.nuget\packages"
$env:SSP_WSK_WDK_ROOT = "$env:USERPROFILE\.nuget\packages\microsoft.windows.wdk.x64\10.0.28000.2526\c"
$env:SSP_WSK_SDK_ROOT = "$env:USERPROFILE\.nuget\packages\microsoft.windows.sdk.cpp\10.0.28000.2526\c"
```

## Unified build

The supported entry point is the workspace Cargo alias:

```powershell
cargo xtask build --release --features <features>
```

Use `--release` for deployable artifacts. Omit it for a faster debug build.
The orchestrator:

1. Validates the feature combination.
2. Provisions WSL, LLVM, OpenSSL, WDK, and SDK dependencies as needed.
3. Builds the BPF object and Linux control service when `wsl` is selected.
4. Builds the Windows host proxy for every build.
5. Builds the native WSK driver only when `kernel-relay` is selected.
6. Signs and verifies the driver when `test-signing` is selected.
7. Publishes artifacts and an atomic `manifest.json`.

### Build matrix

```powershell
# User-mode forwarding, TLS-PSK
cargo xtask build --release --features wsl tls-psk

# User-mode forwarding, rustls
cargo xtask build --release --features wsl tls-rustls

# Kernel forwarding, TLS-PSK, test certificate
cargo xtask build --release --features wsl tls-psk kernel-relay test-signing

# Kernel forwarding, rustls, test certificate
cargo xtask build --release --features wsl tls-rustls kernel-relay test-signing
```

### Published artifacts

User-mode builds publish:

```text
shadow-socket-proxy.bpf.o
ssp-bpf-fixture-runner
shadow-socket-proxy-control
shadow-socket-proxy-host.exe
manifest.json
```

Kernel-mode builds publish those artifacts plus:

```text
shadow_socket_proxy_kernel_relay.dll
```

The manifest records selected features, target triples, hashes, resolved
toolchain versions, signing state, and the test certificate thumbprint when
applicable.

## User-mode deployment on Windows + WSL

The following is a disposable demo deployment. It redirects eligible new
IPv4 TCP and UDP flows from the selected WSL interface. Do not use it as a
production service configuration.

### 1. Build

Choose one:

```powershell
cargo xtask build --release --features wsl tls-psk
cargo xtask build --release --features wsl tls-rustls
```

Set the artifact directory:

```powershell
$out = (Resolve-Path .\target\ssp-build\release).Path
$gateway = (wsl -d Ubuntu -- ip route show default).Split()[2]
```

### 2. Start the control service

For TLS-PSK, create a temporary 32-byte secret:

```powershell
$identity = 'ssp-demo'
$secret = [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
$secret | Set-Content -NoNewline .\ssp-demo.psk

wsl -d Ubuntu -u root -- env `
  RUST_LOG=info `
  SSP_LISTEN_ADDR=127.0.0.1:50051 `
  SSP_TC_HOOK_LAYOUT=wsl `
  SSP_TLS_PSK_IDENTITY=$identity `
  SSP_TLS_PSK_SECRET=$secret `
  /mnt/c/dev/ShadowSocketProxy/target/ssp-build/release/shadow-socket-proxy-control
```

For rustls, provide a control certificate, private key, and SHA-256 pin of
the client certificate's DER bytes:

```powershell
$clientPin = '<sha256-of-client-certificate-der>'

wsl -d Ubuntu -u root -- env `
  RUST_LOG=info `
  SSP_LISTEN_ADDR=127.0.0.1:50051 `
  SSP_TC_HOOK_LAYOUT=wsl `
  SSP_TLS_CERT_FILE=/mnt/c/dev/ShadowSocketProxy/certs/control-cert.pem `
  SSP_TLS_KEY_FILE=/mnt/c/dev/ShadowSocketProxy/certs/control-key.pem `
  SSP_TLS_PEER_CERT_SHA256=$clientPin `
  /mnt/c/dev/ShadowSocketProxy/target/ssp-build/release/shadow-socket-proxy-control
```

Do not set `SSP_TC_HOOK_LAYOUT=wsl` for a native Linux deployment. It is
required here because WSL traffic leaves through the physical egress path.

### 3. Start the Windows host proxy

For TLS-PSK:

```powershell
.\target\ssp-build\release\shadow-socket-proxy-host.exe `
  --listen "${gateway}:15000" `
  --control-endpoint https://127.0.0.1:50051 `
  --psk-identity $identity `
  --psk-secret-file .\ssp-demo.psk `
  --bpf-elf /mnt/c/dev/ShadowSocketProxy/target/ssp-build/release/shadow-socket-proxy.bpf.o `
  --interface eth0
```

For rustls:

```powershell
$controlPin = '<sha256-of-control-certificate-der>'

.\target\ssp-build\release\shadow-socket-proxy-host.exe `
  --listen "${gateway}:15000" `
  --control-endpoint https://127.0.0.1:50051 `
  --tls-cert-file .\certs\client-cert.pem `
  --tls-key-file .\certs\client-key.pem `
  --tls-peer-cert-sha256 $controlPin `
  --bpf-elf /mnt/c/dev/ShadowSocketProxy/target/ssp-build/release/shadow-socket-proxy.bpf.o `
  --interface eth0
```

The proxy attaches the BPF program, configures its listener as the synthetic
destination, and then accepts redirected traffic. A successful startup
reports both control-service connectivity and BPF attachment.

### 4. Stop the demo

Press `Ctrl+C` in the host proxy and control-service terminals. Then remove
temporary credentials:

```powershell
Remove-Item .\ssp-demo.psk -ErrorAction SilentlyContinue
```

## Kernel-mode build and VM deployment

Kernel mode is **experimental**. The build currently produces and signs the
native WSK driver artifact; it does not provide a turnkey installer or
production service configuration.

### 1. Build for a disposable VM

```powershell
cargo xtask build --release --features wsl tls-psk kernel-relay test-signing
```

The test certificate is stored outside the repository under the current
user's local application data. `test-signing` signs the driver; it does not
silently enable Windows test-signing mode or reboot the machine.

Before loading the driver:

- Take a VM snapshot.
- Enable Windows test-signing mode explicitly in the VM.
- Enable kernel debugging and crash dumps.
- Configure WinDbg on the target.
- Use Driver Verifier for pool, I/O, deadlock, and unload checks.

Do not load the kernel artifact on a production or primary workstation.

### 2. Validate the artifact

Inspect the published manifest:

```powershell
Get-Content .\target\ssp-build\release\manifest.json
```

Confirm that:

- `features` includes `kernel-relay`.
- `signing` is `test-signed`.
- The driver hash matches the published artifact.
- The recorded LLVM version is `18.1.8`.

The driver exposes the secured device interface
`\\.\ShadowSocketProxyKernelRelay` for the host-agent/IOCTL transport. A
compatible user-mode mapping agent is still required for the opaque control
requests; building the driver alone does not start a complete kernel-mode
forwarding service.

### 3. Runtime validation order

On the VM, validate in this order:

1. Driver load and unload with no traffic.
2. Malformed and unauthorized IOCTLs.
3. One TCP flow in each direction.
4. TCP half-close and repeated aborts.
5. UDP and QUIC-as-UDP associations.
6. Missing mappings and control-agent disconnects.
7. Concurrent flows, cancellation, unload, and late callbacks.
8. Resource exhaustion and low-memory behavior.

Stop immediately and collect a kernel dump if Driver Verifier reports a
failure. Successful compilation and signature verification do not establish
that the driver is safe for production use.

## Direct Cargo commands

After provisioning, package-level commands remain available:

```powershell
# Host proxy
cargo build --locked --release -p shadow-socket-proxy-host --features tls-psk
cargo build --locked --release -p shadow-socket-proxy-host --features tls-rustls

# Linux control service
wsl -d Ubuntu -- bash -lc `
  'cd /mnt/c/dev/ShadowSocketProxy &&
   cargo build --locked --release -p shadow-socket-proxy-control --features tls-psk'

# Kernel relay host-independent tests
cargo test -p shadow-socket-proxy-kernel-relay
```

Native WDK builds require the pinned WDK/SDK roots and an MSVC developer
environment. Prefer `cargo xtask build` because it supplies those variables
in the same process that invokes Cargo.

## Validation

Run the focused tests after code changes:

```powershell
cargo fmt --all -- --check
cargo test -p shadow-socket-proxy-xtask
cargo test -p shadow-socket-proxy-kernel-relay
```

The BPF fixture runner is Linux-only:

```sh
make -C crates/bpf clean all
./crates/bpf/ssp-bpf-fixture-runner \
  ./crates/bpf/shadow-socket-proxy.bpf.o \
  --fixture target-miss \
  --fixture flow-create \
  --fixture forward-rewrite \
  --fixture reverse-rewrite \
  --fixture control-bypass \
  --fixture fin-ack-teardown \
  --fixture rst
```

Live WSK, Driver Verifier, low-memory, unload, and end-to-end Linux/Windows
tests require the appropriate disposable target environment. They are not
replaced by host-independent unit tests.

## Troubleshooting

### Visual Studio environment not found

Install the Visual Studio C++ workload, or point directly to the developer
environment script:

```powershell
$env:SSP_VCVARS64_BAT = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
```

### LLVM version or WDK layout errors

The native binding build requires LLVM 18.1.8:

```powershell
$env:SSP_LLVM_PACKAGE_VERSION = '18.1.8'
cargo xtask build --release --features wsl tls-psk kernel-relay test-signing
```

### OpenSSL errors in TLS-PSK mode

Use rustls to avoid Windows OpenSSL provisioning:

```powershell
cargo xtask build --release --features wsl tls-rustls
```

Or set `OPENSSL_DIR`, `OPENSSL_INCLUDE_DIR`, and `OPENSSL_LIB_DIR` to a valid
PSK-capable OpenSSL development installation.

### Signature verification errors

Use the same Windows user for certificate creation, signing, and verification.
Pull the latest branch so the build imports the test certificate into the
current user's `Root` and `TrustedPublisher` stores before verification.

## License

ShadowSocketProxy is licensed under the MIT License. See `LICENSE`.
