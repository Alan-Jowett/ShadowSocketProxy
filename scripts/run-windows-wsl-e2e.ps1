param(
    [Parameter(Mandatory = $true)]
    [string] $BpfArtifact,
    [Parameter(Mandatory = $true)]
    [string] $ControlArtifact,
    [Parameter(Mandatory = $true)]
    [string] $HostArtifact,
    [ValidateSet("psk", "rustls")]
    [string] $Transport = "psk",
    [string] $TlsControlCertificateFile,
    [string] $TlsControlKeyFile,
    [string] $TlsControlPeerCertSha256,
    [string] $TlsClientCertificateFile,
    [string] $TlsClientKeyFile,
    [string] $TlsClientPeerCertSha256,
    [string] $Distribution,
    [string] $Interface,
    [switch] $TerminateDistribution,
    [string] $WorkDirectory = (Join-Path $env:TEMP "shadow-socket-proxy-e2e")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-WslRoot([string] $Distribution, [string[]] $Command) {
    & wsl.exe -d $Distribution -u root -- @Command
    if ($LASTEXITCODE -ne 0) {
        throw "WSL root command failed: wsl.exe -d $Distribution -u root -- $($Command -join ' ')"
    }
}

function Invoke-Wsl([string[]] $Arguments) {
    $result = & wsl.exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed: wsl.exe $($Arguments -join ' ')"
    }
    return (($result | Out-String).Trim() -replace "`0", "")
}

function Wait-TcpPort([string] $Address, [int] $Port) {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ((Test-NetConnection -ComputerName $Address -Port $Port -InformationLevel Quiet) -eq $true) {
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "TCP port $Address`:$Port did not become ready"
}

function Wait-WslTcpListener([string] $Distribution, [int] $Port) {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $listeners = Invoke-Wsl @("-d", $Distribution, "--", "ss", "-ltn")
        if ($listeners -match "(?m):$Port\s") {
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "WSL TCP listener on port $Port did not become ready"
}

function ConvertTo-WslPath([string] $WindowsPath) {
    $full = (Resolve-Path $WindowsPath).Path
    if ($full -notmatch "^([A-Za-z]):\\(.*)$") {
        throw "Only drive-qualified paths can be deployed into WSL: $full"
    }
    return "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2] -replace '\\', '/')"
}

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe is required"
}

if (-not $Distribution) {
    $status = Invoke-Wsl @("--status")
    $defaultLine = $status -split "`r?`n" | Where-Object { $_ -match "Default Distribution:" } | Select-Object -First 1
    if ($defaultLine) {
        $Distribution = ($defaultLine -split ":", 2)[1].Trim()
    }
    if (-not $Distribution) {
        throw "No default WSL distribution is installed"
    }
}

$wslRoot = Invoke-Wsl @("-d", $Distribution, "--", "pwd")
$addresses = Invoke-Wsl @("-d", $Distribution, "--", "ip", "-4", "-o", "addr", "show", "scope", "global")
$wslIp = [regex]::Match($addresses, "(?<!127\.0\.0\.1)(\d+\.\d+\.\d+\.\d+)/\d+").Groups[1].Value
$route = (Invoke-Wsl @("-d", $Distribution, "--", "ip", "route", "show", "default")) -split "\s+"
$hostGateway = if ($route.Length -ge 3) { $route[2] } else { "" }
$defaultInterface = if ($route.Length -ge 5) { $route[4] } else { "" }
if (-not $Interface) {
    $Interface = $defaultInterface
}
if (-not $wslIp -or -not $hostGateway -or -not $Interface) {
    throw "Unable to discover WSL address, host gateway, or default interface"
}
Write-Output "Using WSL distribution '$Distribution', address $wslIp, gateway $hostGateway, interface $Interface"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$bpf = (Resolve-Path $BpfArtifact).Path
$control = (Resolve-Path $ControlArtifact).Path
$hostProxy = (Resolve-Path $HostArtifact).Path
$bpfWsl = ConvertTo-WslPath $bpf
$controlWsl = ConvertTo-WslPath $control
$runner = Join-Path $PSScriptRoot "..\target\release\shadow-socket-proxy-e2e-runner.exe"
$proxy = Join-Path $hostProxy "shadow-socket-proxy-host.exe"
$server = Join-Path $PSScriptRoot "tcp-marker-server.ps1"
$marker = "ssp-e2e-$([guid]::NewGuid().ToString('N'))"
$identity = "ssp-e2e-$([guid]::NewGuid().ToString('N'))"
$secret = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$controlPort = 50051
$proxyPort = 15000
$serverPort = 18080
# WSL localhost forwarding avoids Hyper-V firewall policy between the Windows
# host and the WSL virtual NIC for the TLS control-plane connection.
$endpoint = "https://127.0.0.1:$controlPort"
$target = "${hostGateway}:$serverPort"
$proxyAddress = "${hostGateway}:$proxyPort"
$serverProcess = $null
$controlProcess = $null
$proxyProcess = $null
$qdiscCreated = $false
$controlStdout = Join-Path $WorkDirectory "control.stdout.log"
$controlStderr = Join-Path $WorkDirectory "control.stderr.log"
$proxyStdout = Join-Path $WorkDirectory "host-proxy.stdout.log"
$proxyStderr = Join-Path $WorkDirectory "host-proxy.stderr.log"
$rustlsEnvironmentBackup = @{}

if ($Transport -eq "rustls") {
    $rustlsInputs = @(
        $TlsControlCertificateFile,
        $TlsControlKeyFile,
        $TlsControlPeerCertSha256,
        $TlsClientCertificateFile,
        $TlsClientKeyFile,
        $TlsClientPeerCertSha256
    )
    $missingRustlsInputs = @(
        $rustlsInputs | Where-Object { [string]::IsNullOrWhiteSpace($_) }
    )
    if ($missingRustlsInputs.Count -ne 0) {
        throw "rustls transport requires control/client certificate, key, and peer-pin inputs"
    }
    $tlsControlCertificate = (Resolve-Path $TlsControlCertificateFile).Path
    $tlsControlKey = (Resolve-Path $TlsControlKeyFile).Path
    $tlsClientCertificate = (Resolve-Path $TlsClientCertificateFile).Path
    $tlsClientKey = (Resolve-Path $TlsClientKeyFile).Path
    $tlsControlCertificateWsl = ConvertTo-WslPath $tlsControlCertificate
    $tlsControlKeyWsl = ConvertTo-WslPath $tlsControlKey
}

try {
    if ($Transport -eq "rustls") {
        foreach ($name in @(
            "SSP_TLS_CERT_FILE",
            "SSP_TLS_KEY_FILE",
            "SSP_TLS_PEER_CERT_SHA256",
            "SSP_TLS_PSK_IDENTITY",
            "SSP_TLS_PSK_SECRET"
        )) {
            $rustlsEnvironmentBackup[$name] = [Environment]::GetEnvironmentVariable($name)
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
    }
    $wslPackages = if ($Transport -eq "psk") {
        "iproute iproute-tc python3 openssl-libs ca-certificates"
    }
    else {
        "iproute iproute-tc python3 ca-certificates"
    }
    $wslAptPackages = if ($Transport -eq "psk") {
        "iproute2 python3 libssl3 ca-certificates"
    }
    else {
        "iproute2 python3 ca-certificates"
    }
    Invoke-WslRoot $Distribution @("sh", "-c",
        "if command -v dnf >/dev/null; then dnf install -y $wslPackages; elif command -v apt-get >/dev/null; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $wslAptPackages; else echo 'unsupported WSL package manager' >&2; exit 1; fi")
    Invoke-WslRoot $Distribution @("chmod", "+x", $bpfWsl, $controlWsl)
    Invoke-WslRoot $Distribution @("sh", "-c",
        "command -v tc >/dev/null || { echo 'tc is required but unavailable' >&2; exit 1; }")
    $qdiscListing = Invoke-Wsl @(
        "-d", $Distribution, "-u", "root", "--", "tc", "qdisc", "show", "dev", $Interface
    )
    if ($qdiscListing -notmatch "(?m)^qdisc clsact ") {
        Invoke-WslRoot $Distribution @("tc", "qdisc", "add", "dev", $Interface, "clsact")
        $qdiscCreated = $true
    }

    $controlArguments = @(
        "-d", $Distribution, "-u", "root", "--", "env",
        "SSP_LISTEN_ADDR=127.0.0.1:$controlPort",
        "SSP_TC_HOOK_LAYOUT=wsl"
    )
    if ($Transport -eq "psk") {
        $controlArguments += @(
            "SSP_TLS_PSK_IDENTITY=$identity",
            "SSP_TLS_PSK_SECRET=$secret"
        )
    }
    else {
        $controlArguments += @(
            "SSP_TLS_CERT_FILE=`"$tlsControlCertificateWsl`"",
            "SSP_TLS_KEY_FILE=`"$tlsControlKeyWsl`"",
            "SSP_TLS_PEER_CERT_SHA256=$TlsControlPeerCertSha256"
        )
    }
    $controlArguments += "`"$controlWsl`""
    $controlProcess = Start-Process wsl.exe -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $controlStdout -RedirectStandardError $controlStderr `
        -ArgumentList $controlArguments
    Wait-WslTcpListener $Distribution $controlPort
    if ($controlProcess.HasExited) {
        Get-Content $controlStderr -ErrorAction SilentlyContinue
        throw "control service exited before the host proxy started"
    }

    $serverProcess = Start-Process pwsh -PassThru -WindowStyle Hidden -ArgumentList @(
        "-NoProfile", "-File", "`"$server`"", "-BindAddress", $hostGateway,
        "-Port", $serverPort, "-Marker", $marker
    )
    Wait-TcpPort $hostGateway $serverPort
    $env:PATH = "$hostProxy;$env:PATH"
    $proxyArguments = @(
        "--listen", $proxyAddress,
        "--control-endpoint", $endpoint
    )
    if ($Transport -eq "psk") {
        $proxyArguments += @(
            "--psk-identity", $identity,
            "--psk-secret", $secret
        )
    }
    else {
        $proxyArguments += @(
            "--tls-cert-file", "`"$tlsClientCertificate`"",
            "--tls-key-file", "`"$tlsClientKey`"",
            "--tls-peer-cert-sha256", $TlsClientPeerCertSha256
        )
    }
    $proxyArguments += @(
        "--bpf-elf", "`"$bpfWsl`"",
        "--interface", $Interface
    )
    $proxyProcess = Start-Process $proxy -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $proxyStdout -RedirectStandardError $proxyStderr `
        -ArgumentList $proxyArguments
    Start-Sleep -Milliseconds 500
    if ($proxyProcess.HasExited) {
        Get-Content $proxyStderr -ErrorAction SilentlyContinue
        throw "host proxy exited before readiness checks"
    }
    try {
        Wait-TcpPort $hostGateway $proxyPort
    }
    catch {
        Get-Content $proxyStderr -ErrorAction SilentlyContinue
        throw
    }
    $runnerArguments = @("--control-endpoint", $endpoint)
    if ($Transport -eq "psk") {
        $runnerArguments += @("--psk-identity", $identity, "--psk-secret", $secret)
    }
    else {
        $runnerArguments += @(
            "--tls-cert-file", $tlsClientCertificate,
            "--tls-key-file", $tlsClientKey,
            "--tls-peer-cert-sha256", $TlsClientPeerCertSha256
        )
    }
    $runnerArguments += @(
        "--target", $target,
        "--proxy", $proxyAddress,
        "--wsl-distribution", $Distribution,
        "--marker", $marker
    )
    & $runner @runnerArguments
    $runnerExitCode = $LASTEXITCODE
    if ($runnerExitCode -ne 0) {
        Get-Content (Join-Path $WorkDirectory "control.stderr.log") -ErrorAction SilentlyContinue
        Get-Content $proxyStderr -ErrorAction SilentlyContinue
        throw "E2E runner failed with exit code $runnerExitCode"
    }
}
finally {
    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    foreach ($process in @($proxyProcess, $serverProcess, $controlProcess)) {
        try {
            if ($null -ne $process -and -not $process.HasExited) {
                Stop-Process -Id $process.Id -Force
            }
        }
        catch {
            $cleanupErrors.Add("process cleanup failed: $_")
        }
    }
    if ($qdiscCreated) {
        try {
            Invoke-WslRoot $Distribution @("tc", "qdisc", "del", "dev", $Interface, "clsact")
        }
        catch {
            $cleanupErrors.Add("qdisc cleanup failed: $_")
        }
    }
    if ($TerminateDistribution) {
        try {
            & wsl.exe --terminate $Distribution
            if ($LASTEXITCODE -ne 0) {
                throw "WSL distribution termination failed"
            }
        }
        catch {
            $cleanupErrors.Add("WSL termination failed: $_")
        }
    }
    foreach ($entry in $rustlsEnvironmentBackup.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item "Env:$($entry.Key)" $entry.Value
        }
    }
    if ($cleanupErrors.Count -ne 0) {
        throw "WSL cleanup failed: $($cleanupErrors -join '; ')"
    }
}
