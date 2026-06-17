#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Set-LockguardPassword.ps1 — change the Lockguard recovery / uninstall
    password from PowerShell. Functionally identical to
    `lockguard-cli.exe --set-password`.

.DESCRIPTION
    1. Prompts for the CURRENT password.
    2. Verifies locally against the HKLM verifier.
    3. Sends the PBKDF2 + HMAC challenge-response to the kernel driver,
       opening the 10-minute permissive window.
    4. Prompts for the NEW password (with strength validation).
    5. Generates new salt, computes new verifier, writes both to
       HKLM\SYSTEM\Lockguard\Recovery — the driver's registry callback
       allows the write because we're in the permissive window.

    On wrong current password the script exits before touching the driver.
    Inside the permissive window the script also leaves enough time for a
    follow-up Uninstall-Lockguard.ps1 run — useful if you're rotating the
    password as part of a teardown.

.EXAMPLE
    .\Set-LockguardPassword.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ---------- Win32 P/Invoke ----------
if (-not ([System.Management.Automation.PSTypeName]'Lockguard.NativeSP').Type) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Lockguard {
    public static class NativeSP {
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

        public const uint GENERIC_READ_WRITE     = 0xC0000000;
        public const uint FILE_SHARE_READ_WRITE  = 0x3;
        public const uint OPEN_EXISTING          = 3;

        public static uint CtlCode(uint dev, uint func, uint method, uint access) {
            return (dev << 16) | (access << 14) | (func << 2) | method;
        }
    }
}
'@
}

$CTL_GET_NONCE = [Lockguard.NativeSP]::CtlCode(0x22, 0x801, 0, 0)
$CTL_UNLOCK    = [Lockguard.NativeSP]::CtlCode(0x22, 0x802, 0, 0)

# ---------- Helpers ----------
function Read-SecurePlain([string]$prompt) {
    $ss   = Read-Host $prompt -AsSecureString
    $ptr  = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($ss)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
    }
}

function Read-StrongNewPassword {
    while ($true) {
        $a = Read-SecurePlain 'New password (12+ chars, mixed case + digit)'
        $b = Read-SecurePlain 'Confirm new password'
        if ($a -ne $b)                 { Write-Warning 'Mismatch. Retry.';        continue }
        if ($a.Length -lt 12)          { Write-Warning 'Too short (<12).';        continue }
        if ($a -notmatch '[A-Z]')      { Write-Warning 'Need an uppercase letter.'; continue }
        if ($a -notmatch '[a-z]')      { Write-Warning 'Need a lowercase letter.'; continue }
        if ($a -notmatch '[0-9]')      { Write-Warning 'Need a digit.';           continue }
        return $a
    }
}

# ---------- Read current verifier ----------
$reg = 'HKLM:\SYSTEM\Lockguard\Recovery'
if (-not (Test-Path $reg)) {
    Write-Error 'No recovery verifier at HKLM\SYSTEM\Lockguard\Recovery. Is Lockguard installed?'
    exit 1
}
$salt       = (Get-ItemProperty -Path $reg -Name InstallSalt).InstallSalt
$iterations = (Get-ItemProperty -Path $reg -Name Iterations ).Iterations
$verifier   = (Get-ItemProperty -Path $reg -Name Verifier   ).Verifier

# ---------- Verify CURRENT password ----------
$curPw = Read-SecurePlain 'Current password'
$deriv = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $curPw, $salt, [int]$iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$curDerived = $deriv.GetBytes(32)
$deriv.Dispose()
$curPw = $null

$label  = [System.Text.Encoding]::ASCII.GetBytes('LOCKGUARD-VERIFIER-V1')
$hmac   = New-Object System.Security.Cryptography.HMACSHA256(,$curDerived)
$check  = $hmac.ComputeHash($label)
$hmac.Dispose()

$match = $true
for ($i = 0; $i -lt 32; $i++) { if ($check[$i] -ne $verifier[$i]) { $match = $false } }
if (-not $match) {
    [Array]::Clear($curDerived, 0, 32)
    Write-Error 'Wrong current password.'
    exit 1
}

# ---------- Open permissive window ----------
$h = [Lockguard.NativeSP]::CreateFileW(
        '\\.\Lockguard',
        [Lockguard.NativeSP]::GENERIC_READ_WRITE,
        [Lockguard.NativeSP]::FILE_SHARE_READ_WRITE,
        [IntPtr]::Zero,
        [Lockguard.NativeSP]::OPEN_EXISTING,
        0, [IntPtr]::Zero)
if ($h.IsInvalid) {
    [Array]::Clear($curDerived, 0, 32)
    Write-Error 'Cannot open \\.\Lockguard (is the kernel driver loaded?).'
    exit 1
}

try {
    $nonce = New-Object byte[] 32
    $ret = 0
    if (-not [Lockguard.NativeSP]::DeviceIoControl($h, $CTL_GET_NONCE, $null, 0,
              $nonce, 32, [ref]$ret, [IntPtr]::Zero)) {
        Write-Error "IOCTL_GET_NONCE failed. LastError: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        exit 1
    }
    $respMac  = New-Object System.Security.Cryptography.HMACSHA256(,$curDerived)
    $response = $respMac.ComputeHash($nonce)
    $respMac.Dispose()

    $payload = New-Object byte[] 64
    [Array]::Copy($response,   0, $payload, 0,  32)
    [Array]::Copy($curDerived, 0, $payload, 32, 32)

    if (-not [Lockguard.NativeSP]::DeviceIoControl($h, $CTL_UNLOCK, $payload, 64,
              $null, 0, [ref]$ret, [IntPtr]::Zero)) {
        Write-Error "IOCTL_UNLOCK failed. LastError: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        exit 1
    }
    Write-Host 'Current password verified. Permissive window open.' -ForegroundColor Green
} finally {
    [Array]::Clear($curDerived, 0, 32)
    $h.Dispose()
}

# ---------- Prompt new password + write ----------
$newPw = Read-StrongNewPassword

$newSalt = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($newSalt)

$newIter   = 1000000
$newDeriv  = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                $newPw, $newSalt, $newIter,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$newKey    = $newDeriv.GetBytes(32)
$newDeriv.Dispose()
$newPw = $null

$newMac    = New-Object System.Security.Cryptography.HMACSHA256(,$newKey)
$newVerif  = $newMac.ComputeHash($label)
$newMac.Dispose()
[Array]::Clear($newKey, 0, 32)

try {
    Set-ItemProperty -Path $reg -Name 'InstallSalt' -Value $newSalt    -Type Binary -Force
    Set-ItemProperty -Path $reg -Name 'Iterations'  -Value $newIter    -Type DWord  -Force
    Set-ItemProperty -Path $reg -Name 'Verifier'    -Value $newVerif   -Type Binary -Force
} catch {
    Write-Error "Failed to write new verifier: $($_.Exception.Message)"
    Write-Error 'Permissive window may have expired (10 min limit), or driver registry callback denied the write.'
    exit 1
}

Write-Host ''
Write-Host 'Password changed.' -ForegroundColor Green
Write-Host 'The new password is required for any future --recover, --set-password,'
Write-Host 'or Uninstall-Lockguard.ps1 run. Store it safely; there is no key file.'
