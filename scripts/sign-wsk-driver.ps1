#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [string]$DriverPath = (Join-Path (Get-Location) 'target\x86_64-pc-windows-msvc\release\shadow_socket_proxy_wsk_driver.sys'),
    [string]$Subject = 'CN=ShadowSocketProxy WSK Test Driver',
    [switch]$EnableTestSigning
)

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell prompt.'
}

if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) {
    throw "Driver binary was not found: $DriverPath"
}

$signTool = Get-ChildItem `
    -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
    -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if ($null -eq $signTool) {
    throw 'signtool.exe was not found. Install the Windows SDK signing tools.'
}

$certificate = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if ($null -eq $certificate) {
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -CertStoreLocation Cert:\LocalMachine\My
}

foreach ($store in @(
        'Cert:\LocalMachine\Root',
        'Cert:\LocalMachine\TrustedPublisher'
    )) {
    if (-not (Get-ChildItem $store | Where-Object Thumbprint -eq $certificate.Thumbprint)) {
        Copy-Item -Path $certificate.PSPath -Destination $store
    }
}

& $signTool.FullName sign /v /fd SHA256 /sm /sha1 $certificate.Thumbprint $DriverPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool sign failed with exit code $LASTEXITCODE"
}

& $signTool.FullName verify /kp /v $DriverPath
if ($LASTEXITCODE -ne 0) {
    throw "kernel-mode signtool verification failed with exit code $LASTEXITCODE"
}

if ($EnableTestSigning) {
    & bcdedit.exe /set testsigning on
    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit failed with exit code $LASTEXITCODE"
    }
    Write-Host 'Test signing was enabled. Reboot Windows before starting the driver.'
}

Write-Host "Signed driver: $DriverPath"
Write-Host "Certificate: $($certificate.Thumbprint)"
