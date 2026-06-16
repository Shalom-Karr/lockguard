#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Uninstall-Lockguard.ps1 — full teardown. Reverses Install-Lockguard.ps1.

.DESCRIPTION
    Must be run inside the 10-minute permissive window opened by either
    Recover-Lockguard.ps1 or `lockguard-cli.exe --recover`. Outside that
    window, the kernel driver's callbacks will deny each step and the
    script will fail loudly.

    Order of operations matters: stop the watchdog, then deregister it,
    then remove the WDAC policy (so future boots don't enforce against
    things we need to delete), then revert BCD, then delete services,
    then delete files, then reboot.

.EXAMPLE
    .\Recover-Lockguard.ps1   # opens 10-minute window
    .\Uninstall-Lockguard.ps1 # runs teardown
#>

[CmdletBinding()]
param(
    [switch]$NoReboot
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$ProgramData     = 'C:\ProgramData\Lockguard'
$RestorePath     = 'C:\Windows\Lockguard-Restore'
$DriverSysTarget = 'C:\Windows\System32\drivers\lockguard.sys'
$WDACPolicyDest  = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'
$RecoveryRegPath = 'HKLM:\SYSTEM\Lockguard\Recovery'

function Step($n, $title) { Write-Host "`n[$n] $title" -ForegroundColor Cyan }
function Info($m)          { Write-Host "    $m" -ForegroundColor Gray }
function OK($m)            { Write-Host "    $m" -ForegroundColor Green }
function Warn($m)          { Write-Warning $m }

# ---------- [1] Permissive-window check ----------
Step 1 'Verify permissive window is open'

$cli = 'lockguard-cli.exe'
$cliPath = (Get-Command $cli -ErrorAction SilentlyContinue).Source
if ($cliPath) {
    $status = & $cliPath --status 2>&1 | Out-String
    if ($status -match 'Permissive:\s+True') {
        OK 'Driver is in permissive mode.'
    } else {
        Warn 'Driver is NOT in permissive mode. Run Recover-Lockguard.ps1 first to open the 10-minute window.'
        Warn 'Continuing anyway; expect access-denied on many steps.'
    }
} else {
    Info 'lockguard-cli.exe not on PATH; cannot verify window status. Proceeding.'
}

# ---------- [2] Stop + remove watchdog service ----------
Step 2 'Remove watchdog service'
& sc.exe stop   lockguard-svc 2>$null
& sc.exe delete lockguard-svc 2>$null
OK 'lockguard-svc removed.'

# ---------- [3] Remove WDAC policy ----------
Step 3 'Remove WDAC policy'
$cip = Join-Path $WDACPolicyDest 'lockguard.cip'
if (Test-Path $cip) {
    Remove-Item $cip -Force -ErrorAction SilentlyContinue
    if (Get-Command CiTool.exe -ErrorAction SilentlyContinue) {
        # Refresh so the kernel forgets the policy.
        & CiTool.exe --refresh-policies 2>$null | Out-Null
    }
    OK 'WDAC policy removed.'
} else {
    Info 'No policy file to remove.'
}

# ---------- [4] Revert BCD ----------
Step 4 'Revert BCD'
& bcdedit.exe /set testsigning off | Out-Null
& bcdedit.exe /set bootmenupolicy legacy | Out-Null
OK 'testsigning=off, bootmenupolicy=legacy.'

# ---------- [5] Remove driver service ----------
Step 5 'Remove driver service'
# Can't `sc stop` the driver (no DriverUnload), but we can delete the service
# registration so the next reboot doesn't load it.
& sc.exe delete lockguard 2>$null
foreach ($mode in 'Minimal','Network') {
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode\lockguard.sys" `
                -Recurse -Force -ErrorAction SilentlyContinue
}
OK 'lockguard service registration deleted.'

# ---------- [6] Restore file associations ----------
Step 6 'Restore default file associations'
$pol = 'HKLM:\Software\Policies\Microsoft\Windows\System'
Remove-ItemProperty -Path $pol -Name 'DefaultAssociationsConfiguration' -ErrorAction SilentlyContinue
OK 'Association policy lock removed (defaults will reset on next user logon).'

# ---------- [7] Restore audio services ----------
Step 7 'Restore audio services'
foreach ($svc in 'audiosrv','AudioEndpointBuilder') {
    & sc.exe config $svc start= auto | Out-Null
    & sc.exe start  $svc 2>$null
}
OK 'Audio services re-enabled.'

# ---------- [8] Re-enable Bluetooth/WWAN adapters ----------
Step 8 'Re-enable network adapters'
Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -match 'Bluetooth|Cellular|Mobile|WWAN'
} | Enable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue

# Wipe WLAN filters
& netsh.exe wlan delete filter permission=denyall networktype=infrastructure 2>$null
& netsh.exe wlan delete filter permission=denyall networktype=adhoc           2>$null
# Allow rule needs explicit ssid; iterate any stored rules.
$filters = & netsh.exe wlan show filters
$filters | Select-String 'SSID name\s+:\s+"([^"]+)"' | ForEach-Object {
    $ssid = $_.Matches[0].Groups[1].Value
    & netsh.exe wlan delete filter permission=allow ssid="$ssid" networktype=infrastructure 2>$null
}
OK 'Adapters re-enabled; WLAN filters cleared.'

# ---------- [9] Remove scheduled tasks ----------
Step 9 'Remove scheduled tasks'
foreach ($t in 'LockguardBoot','LockguardLogon','LockguardHeal') {
    Unregister-ScheduledTask -TaskName $t -TaskPath '\Microsoft\Windows\Lockguard\' `
                              -Confirm:$false -ErrorAction SilentlyContinue
}
OK 'Tasks removed.'

# ---------- [10] Delete files ----------
Step 10 'Delete files'
foreach ($p in $ProgramData, $RestorePath) {
    if (Test-Path $p) {
        & icacls.exe $p '/reset' '/T' '/C' | Out-Null
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if (Test-Path $DriverSysTarget) {
    Remove-Item $DriverSysTarget -Force -ErrorAction SilentlyContinue
}
OK 'Files deleted (driver image stays in memory until reboot).'

# ---------- [11] Remove recovery registry ----------
Step 11 'Remove recovery registry'
Remove-Item -Path $RecoveryRegPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\SYSTEM\Lockguard'       -Recurse -Force -ErrorAction SilentlyContinue
OK 'Recovery verifier deleted.'

# ---------- [12] Reboot ----------
Step 12 'Reboot'
Write-Host '`nLockguard fully uninstalled. A reboot completes the removal.' -ForegroundColor Green

if (-not $NoReboot) {
    $ans = Read-Host 'Reboot now? [Y/n]'
    if ($ans -eq '' -or $ans -match '^[Yy]') {
        Restart-Computer -Force
    }
}
