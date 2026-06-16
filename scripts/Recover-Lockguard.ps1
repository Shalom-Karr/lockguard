#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Recover-Lockguard.ps1 — pure-PS recovery client. Opens a 10-minute
    permissive window on the lockguard kernel driver so the admin can run
    Uninstall-Lockguard.ps1 (or any other repair task).

.DESCRIPTION
    Implements the same PBKDF2 + HMAC-SHA256 challenge-response that the
    Go lockguard-cli.exe uses, via .NET crypto primitives + a
    DeviceIoControl P/Invoke. No external dependencies; this script is
    self-contained and re-typable from the README if all you have is the
    password.

    On wrong password, fails locally without sending any IOCTL — the
    driver never sees a bad attempt that didn't already pre-verify.

.EXAMPLE
    .\Recover-Lockguard.ps1
    Recovery password: ************
    Unlocked — 10:00 remaining.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ---------- Win32 P/Invoke ----------
if (-not ([System.Management.Automation.PSTypeName]'Lockguard.Native').Type) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Lockguard {
    public static class Native {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFileW(
            string filename, uint access, uint share, IntPtr sa,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            SafeFileHandle device, uint ctlCode,
            byte[] inBuf, uint inLen,
            byte[] outBuf, uint outLen,
            out uint returned, IntPtr overlapped);

        public const uint GENERIC_READ_WRITE = 0xC0000000;
        public const uint FILE_SHARE_READ_WRITE = 0x3;
        public const uint OPEN_EXISTING = 3;

        public static uint CtlCode(uint dev, uint func, uint method, uint access) {
            return (dev << 16) | (access << 14) | (func << 2) | method;
        }
    }
}
'@
}

$CTL_GET_NONCE = [Lockguard.Native]::CtlCode(0x22, 0x801, 0, 0)
$CTL_UNLOCK    = [Lockguard.Native]::CtlCode(0x22, 0x802, 0, 0)

# ---------- Read verifier ----------
$reg = 'HKLM:\SYSTEM\Lockguard\Recovery'
if (-not (Test-Path $reg)) {
    Write-Error 'No recovery verifier at HKLM\SYSTEM\Lockguard\Recovery. Is Lockguard installed?'
    exit 1
}

$salt       = (Get-ItemProperty -Path $reg -Name InstallSalt).InstallSalt
$iterations = (Get-ItemProperty -Path $reg -Name Iterations ).Iterations
$verifier   = (Get-ItemProperty -Path $reg -Name Verifier   ).Verifier

# ---------- Prompt password + derive key ----------
$pwSS = Read-Host 'Recovery password' -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwSS)
$pw   = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$deriv = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $pw, $salt, [int]$iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$derived = $deriv.GetBytes(32)
$deriv.Dispose()
$pw = $null

# Verify locally first — wrong password fails without touching the driver.
$label = [System.Text.Encoding]::ASCII.GetBytes('LOCKGUARD-VERIFIER-V1')
$hmac  = New-Object System.Security.Cryptography.HMACSHA256(,$derived)
$computed = $hmac.ComputeHash($label)
$hmac.Dispose()

$ok = $true
for ($i = 0; $i -lt 32; $i++) {
    if ($computed[$i] -ne $verifier[$i]) { $ok = $false }
}
if (-not $ok) {
    [Array]::Clear($derived, 0, 32)
    Write-Error 'Wrong password.'
    exit 1
}

# ---------- Open driver, get nonce, send response ----------
$h = [Lockguard.Native]::CreateFileW(
        '\\.\Lockguard',
        [Lockguard.Native]::GENERIC_READ_WRITE,
        [Lockguard.Native]::FILE_SHARE_READ_WRITE,
        [IntPtr]::Zero,
        [Lockguard.Native]::OPEN_EXISTING,
        0, [IntPtr]::Zero)
if ($h.IsInvalid) {
    [Array]::Clear($derived, 0, 32)
    Write-Error "Cannot open \\.\Lockguard (is the kernel driver loaded?). LastError: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    exit 1
}

try {
    $nonce = New-Object byte[] 32
    $ret = 0
    if (-not [Lockguard.Native]::DeviceIoControl($h, $CTL_GET_NONCE, $null, 0,
              $nonce, 32, [ref]$ret, [IntPtr]::Zero)) {
        Write-Error "IOCTL_GET_NONCE failed. LastError: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        exit 1
    }

    $respMac = New-Object System.Security.Cryptography.HMACSHA256(,$derived)
    $response = $respMac.ComputeHash($nonce)
    $respMac.Dispose()

    $payload = New-Object byte[] 64
    [Array]::Copy($response, 0, $payload, 0,  32)
    [Array]::Copy($derived , 0, $payload, 32, 32)

    if (-not [Lockguard.Native]::DeviceIoControl($h, $CTL_UNLOCK, $payload, 64,
              $null, 0, [ref]$ret, [IntPtr]::Zero)) {
        Write-Error "IOCTL_UNLOCK failed. LastError: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        exit 1
    }

    Write-Host 'Unlocked — 10:00 remaining.' -ForegroundColor Green
    Write-Host 'Run Uninstall-Lockguard.ps1 within this window to fully remove.'
} finally {
    [Array]::Clear($derived, 0, 32)
    $h.Dispose()
}
