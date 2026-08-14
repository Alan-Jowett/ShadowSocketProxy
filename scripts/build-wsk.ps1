#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SignDriver,
    [switch]$EnableTestSigning
)

$ErrorActionPreference = 'Stop'

$wdkVersion = '10.0.28000.2526'
$driverTarget = 'x86_64-pc-windows-msvc'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$nugetRoot = Join-Path $env:USERPROFILE '.nuget\packages'
$wdkRoot = Join-Path $nugetRoot "microsoft.windows.wdk.x64\$wdkVersion\c"
$sdkRoot = Join-Path $nugetRoot "microsoft.windows.sdk.cpp\$wdkVersion\c"
$llvmRoot = if ($env:LLVM_HOME) { $env:LLVM_HOME } else { Join-Path $env:ProgramFiles 'LLVM' }
$libclangPath = Join-Path $llvmRoot 'bin'
$opensslRoot = $env:OPENSSL_DIR
if (-not $opensslRoot) {
    $opensslRoot = Get-ChildItem $env:ProgramFiles -Directory -Filter 'OpenSSL*' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $candidate = Join-Path $_.FullName 'bin\openssl.exe'
            if (Test-Path -LiteralPath $candidate) {
                $_.FullName
            }
        } |
        Select-Object -First 1
}
if (-not $opensslRoot) {
    throw 'OpenSSL was not found. Install the Windows OpenSSL development package or set OPENSSL_DIR.'
}
$opensslLib = if ($env:OPENSSL_LIB_DIR) {
    $env:OPENSSL_LIB_DIR
} else {
    Join-Path $opensslRoot 'lib\VC\x64\MD'
}

function Invoke-Native {
    param(
        [Parameter(Mandatory)]
        [string]$Command,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

foreach ($requiredPath in @(
        $wdkRoot,
        $sdkRoot,
    (Join-Path $libclangPath 'libclang.dll'),
    (Join-Path $opensslRoot 'include\openssl\ssl.h'),
    (Join-Path $opensslLib 'libcrypto.lib'),
    (Join-Path $opensslLib 'libssl.lib')
    )) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required WSK build dependency was not found: $requiredPath"
    }
}

$env:SSP_WSK_NUGET_ROOT = $nugetRoot
$env:SSP_WSK_WDK_ROOT = $wdkRoot
$env:SSP_WSK_SDK_ROOT = $sdkRoot
$env:WDKContentRoot = $wdkRoot
$env:LLVM_HOME = $llvmRoot
$env:LIBCLANG_PATH = $libclangPath
$env:OPENSSL_DIR = $opensslRoot
$env:OPENSSL_LIB_DIR = $opensslLib
$env:OPENSSL_INCLUDE_DIR = Join-Path $opensslRoot 'include'
$env:PATH = "$libclangPath;$opensslRoot\bin;$env:PATH"

Push-Location $repoRoot
try {
    if ($Clean) {
        Invoke-Native 'cargo' @('clean', '--target', $driverTarget)
    }

    $originalRustFlags = $env:RUSTFLAGS
    $driverRustFlags = @(
        $originalRustFlags,
        '-C panic=abort',
        '-C target-feature=+crt-static'
    ) | Where-Object { $_ } | Join-String -Separator ' '
    try {
        $env:RUSTFLAGS = $driverRustFlags
        Invoke-Native 'cargo' @(
            'build',
            '--locked',
            '--release',
            '-p',
            'shadow-socket-proxy-wsk-driver',
            '--features',
            'kernel',
            '--target',
            $driverTarget
        )
    }
    finally {
        $env:RUSTFLAGS = $originalRustFlags
    }

    Invoke-Native 'cargo' @(
        'build',
        '--locked',
        '--release',
        '-p',
        'shadow-socket-proxy-host',
        '--features',
        'tls-psk,wsk'
    )

    $driverDllPath = Join-Path $repoRoot "target\$driverTarget\release\shadow_socket_proxy_wsk_driver.dll"
    $driverPath = Join-Path $repoRoot "target\$driverTarget\release\shadow_socket_proxy_wsk_driver.sys"
    if (Test-Path -LiteralPath $driverPath) {
        Remove-Item -LiteralPath $driverPath -Force
    }
    Move-Item -LiteralPath $driverDllPath -Destination $driverPath
    $hostPath = Join-Path $repoRoot 'target\release\shadow-socket-proxy-host.exe'

    if ($SignDriver -or $EnableTestSigning) {
        $signArguments = @('-DriverPath', $driverPath)
        if ($EnableTestSigning) {
            $signArguments += '-EnableTestSigning'
        }
        & (Join-Path $repoRoot 'scripts\sign-wsk-driver.ps1') @signArguments
        if (-not $?) {
            throw 'sign-wsk-driver.ps1 failed'
        }
    }

    Write-Host ''
    Write-Host "Driver: $driverPath"
    Write-Host "Host:   $hostPath"
}
finally {
    Pop-Location
}
