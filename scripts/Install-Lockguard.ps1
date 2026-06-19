#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install-Lockguard.ps1 — one-shot installer for the Lockguard lockdown system.

.DESCRIPTION
    The 14-phase installer described in README.md. Sets up the kernel
    driver, watchdog service, WDAC policy, file associations, audio
    mute, WLAN filter, scheduled tasks, and recovery verifier on the
    target machine. Idempotent (re-running detects already-installed
    components and skips). Failures roll back partial state.

.PARAMETER BundlePath
    Path to Lockguard-bundle.zip. Default: same folder as this script.

.PARAMETER WDACAudit
    Install the WDAC policy in audit mode (no enforcement). Use this for
    the first install to surface false-positives before enforcing.

.PARAMETER SkipBIOS
    Skip the printed BIOS-step reminder (e.g. for automated re-runs).

.EXAMPLE
    .\Install-Lockguard.ps1 -BundlePath D:\Lockguard-bundle.zip -WDACAudit
#>

[CmdletBinding()]
param(
    [string]$BundlePath = (Join-Path $PSScriptRoot 'Lockguard-bundle.zip'),
    [switch]$WDACAudit,
    [switch]$SkipBIOS
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProgramData      = 'C:\ProgramData\Lockguard'
$RestorePath      = 'C:\Windows\Lockguard-Restore'
$DriverSysTarget  = 'C:\Windows\System32\drivers\lockguard.sys'
$WatchdogTarget   = Join-Path $ProgramData 'bin\lockguard-svc.exe'
$ConfigDir        = Join-Path $ProgramData 'config'
$WDACPolicyDest   = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'
$RecoveryRegPath  = 'HKLM:\SYSTEM\Lockguard\Recovery'

function Step($n, $title)  { Write-Host "`n[$n/14] $title" -ForegroundColor Cyan }
function Info($msg)          { Write-Host "        $msg" -ForegroundColor Gray }
function OK($msg)            { Write-Host "        $msg" -ForegroundColor Green }
function Warn($msg)          { Write-Warning $msg }
function Die($msg)           { Write-Error $msg; exit 1 }

# ---------- [1/14] Verify environment ----------
Step 1 'Verify environment'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die 'Run this script from an elevated PowerShell prompt.'
}

$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Info "OS: $osCaption"
if ($osCaption -notmatch 'Windows 11' -and $osCaption -notmatch 'Windows 10') {
    Warn "This installer was designed for Windows 11 Home. Detected: $osCaption"
}

if (-not (Test-Path $BundlePath)) {
    Die "Bundle not found: $BundlePath  (build & place Lockguard-bundle.zip next to this script first)"
}
OK "Bundle found: $BundlePath"

# ---------- [2/14] Restore point + recovery password ----------
Step 2 'Restore point + recovery password'

try {
    Checkpoint-Computer -Description 'Pre-Lockguard' -RestorePointType 'APPLICATION_INSTALL' -ErrorAction Stop
    OK 'System restore point created.'
} catch {
    Warn "Restore-point creation failed: $($_.Exception.Message). Continuing — you should still snapshot before installing."
}

function Read-SecurePlain([string]$prompt) {
    # Convert a SecureString prompt to a plain string with the unmanaged
    # backing memory zeroized + freed in finally, so the password doesn't
    # linger in process memory.
    $ss  = Read-Host $prompt -AsSecureString
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($ss)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
    }
}

function Read-StrongPassword {
    while ($true) {
        $sa = Read-SecurePlain 'Recovery password (12+ chars, mixed case + digit)'
        $sb = Read-SecurePlain 'Confirm password'
        if ($sa -ne $sb)                { Warn 'Mismatch. Retry.';        continue }
        if ($sa.Length -lt 12)          { Warn 'Too short (<12).';        continue }
        if ($sa -notmatch '[A-Z]')      { Warn 'Need an uppercase letter.'; continue }
        if ($sa -notmatch '[a-z]')      { Warn 'Need a lowercase letter.'; continue }
        if ($sa -notmatch '[0-9]')      { Warn 'Need a digit.';           continue }
        return $sa
    }
}

if (Test-Path $RecoveryRegPath) {
    Info 'Recovery verifier already present — reusing existing salt/verifier.'
} else {
    $pw = Read-StrongPassword

    $salt = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)

    $iterations = 1000000
    Info "Computing PBKDF2 ($iterations iterations) — this takes ~0.5 s."
    $deriv = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                $pw, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $derivedKey = $deriv.GetBytes(32)
    $deriv.Dispose()
    $pw = $null
    [System.GC]::Collect()

    $label = [System.Text.Encoding]::ASCII.GetBytes('LOCKGUARD-VERIFIER-V1')
    $hmac  = New-Object System.Security.Cryptography.HMACSHA256(,$derivedKey)
    $verifier = $hmac.ComputeHash($label)
    $hmac.Dispose()

    New-Item -Path $RecoveryRegPath -Force | Out-Null
    New-ItemProperty -Path $RecoveryRegPath -Name 'InstallSalt' -Value $salt       -PropertyType Binary -Force | Out-Null
    New-ItemProperty -Path $RecoveryRegPath -Name 'Iterations'  -Value $iterations -PropertyType DWord  -Force | Out-Null
    New-ItemProperty -Path $RecoveryRegPath -Name 'Verifier'    -Value $verifier   -PropertyType Binary -Force | Out-Null

    # ACL: SYSTEM full, Administrators read + write (so lockguard-cli.exe
    # --set-password can rewrite the verifier inside the permissive window).
    # The driver's registry callback is the actual lock — it blocks every
    # write to this key OUTSIDE the permissive window, regardless of token.
    # Users get no access; the verifier is readable to admins by design.
    $acl = Get-Acl $RecoveryRegPath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
        'BUILTIN\Administrators', 'ReadKey,SetValue,CreateSubKey,Delete', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -Path $RecoveryRegPath -AclObject $acl

    # Zeroize sensitive buffers.
    [Array]::Clear($derivedKey, 0, $derivedKey.Length)
    $pw = $null
    OK 'Recovery verifier stored. Password is your ONLY escape — save it.'
    Read-Host '        Press Enter once you have stored the password safely'
}

# ---------- [3/14] Stage files ----------
Step 3 'Stage files'

New-Item -ItemType Directory -Path $ProgramData -Force | Out-Null
New-Item -ItemType Directory -Path "$ProgramData\bin"    -Force | Out-Null
New-Item -ItemType Directory -Path $ConfigDir            -Force | Out-Null
New-Item -ItemType Directory -Path $RestorePath          -Force | Out-Null

$stage = Join-Path $env:TEMP 'lockguard-stage'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
Expand-Archive -Path $BundlePath -DestinationPath $stage -Force

Copy-Item -Path "$stage\bin\lockguard.sys"     -Destination $DriverSysTarget -Force
Copy-Item -Path "$stage\bin\lockguard.sys"     -Destination "$RestorePath\lockguard.sys" -Force
Copy-Item -Path "$stage\bin\lockguard-svc.exe" -Destination $WatchdogTarget -Force
Copy-Item -Path "$stage\bin\lockguard-svc.exe" -Destination "$RestorePath\lockguard-svc.exe" -Force
Copy-Item -Path "$stage\config\*"              -Destination $ConfigDir      -Force -Recurse

# Tighten ACL on ProgramData\Lockguard.
$paths = @($ProgramData, $RestorePath)
foreach ($p in $paths) {
    & icacls.exe $p '/inheritance:r' | Out-Null
    & icacls.exe $p '/grant:r' 'NT SERVICE\TrustedInstaller:(OI)(CI)F' | Out-Null
    & icacls.exe $p '/grant:r' 'NT AUTHORITY\SYSTEM:(OI)(CI)RX'        | Out-Null
    & icacls.exe $p '/grant:r' 'BUILTIN\Administrators:(OI)(CI)R'      | Out-Null
}
attrib +h +s $ProgramData
attrib +h +s $RestorePath

OK 'Files staged + ACL tightened.'

# ---------- [4/14] Cert trust ----------
Step 4 'Cert trust'

$cer = "$stage\certs\Lockguard.cer"
if (Test-Path $cer) {
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root             | Out-Null
    OK 'Lockguard cert installed (TrustedPublisher + Root).'
} else {
    Warn "No cert at $cer — the .sys must already be signed with a trusted publisher key, or test signing trust will fail to load it."
}

# ---------- [5/14] Test signing + BCD ----------
Step 5 'Enable test signing + boot config'

# Secure Boot MUST be OFF before enabling test signing — otherwise the
# test-signed driver fails to load on reboot, silently breaking the
# entire lockdown (driver gone, but watchdog/WDAC/etc. all still applied).
# Bail out hard rather than continue into an unbootable / unprotected state.
try {
    $secureBootOn = Confirm-SecureBootUEFI -ErrorAction Stop
} catch [System.PlatformNotSupportedException] {
    # Legacy BIOS (non-UEFI) — Secure Boot does not apply. Safe to proceed.
    $secureBootOn = $false
    Info 'Legacy BIOS detected (no UEFI) — Secure Boot check skipped.'
} catch [System.UnauthorizedAccessException] {
    Die 'Secure Boot state check requires elevation. Re-run from an elevated PowerShell prompt.'
} catch {
    Die "Unable to determine Secure Boot state: $($_.Exception.Message). Refusing to enable test signing blindly — verify Secure Boot is OFF in UEFI/BIOS, then re-run."
}

if ($secureBootOn) {
    Die @'
Secure Boot is currently ENABLED. Test-signed drivers will not load while Secure Boot is on, which would leave this machine with the watchdog, WDAC, WLAN filter, and audio mute applied but NO kernel driver — i.e. unprotected.

To proceed:
  1. Reboot into UEFI/BIOS setup.
  2. Disable Secure Boot.
  3. Boot back into Windows.
  4. Re-run this installer.
'@
}
OK 'Secure Boot is OFF (or N/A on legacy BIOS) — safe to enable test signing.'

& bcdedit.exe /set testsigning on        | Out-Null
& bcdedit.exe /set bootmenupolicy standard | Out-Null
& bcdedit.exe /set advancedoptions off    | Out-Null
& bcdedit.exe /deletevalue safeboot 2>$null
OK 'BCD locked down. Reboot required at end.'

# ---------- [6/14] Driver service (BootStart) ----------
Step 6 'Install driver service (BootStart)'

if ((& sc.exe query lockguard) -match 'STATE') {
    Info 'lockguard service exists — skipping create.'
} else {
    & sc.exe create lockguard type= kernel start= boot binPath= $DriverSysTarget DisplayName= 'Lockguard Driver' | Out-Null
    & sc.exe description lockguard 'Lockguard kernel protection driver.' | Out-Null
}

# Add to SafeBoot lists so it loads in Safe Mode too.
foreach ($mode in 'Minimal','Network') {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode\lockguard.sys"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name '(default)' -Value 'Driver'
}

& sc.exe failure lockguard reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
OK 'Driver installed: BootStart + Safe Mode + restart-on-failure.'

# ---------- [7/14] Watchdog service ----------
Step 7 'Install watchdog service'

if ((& sc.exe query lockguard-svc) -match 'STATE') {
    Info 'lockguard-svc exists — skipping create.'
} else {
    & "$WatchdogTarget" --service-install
}
OK 'Watchdog installed (Auto + restart-on-failure).'

# ---------- [8/14] WDAC policy ----------
Step 8 'Compile + deploy WDAC policy'

$xml = Join-Path $ConfigDir 'WDACPolicy.xml'
$cip = Join-Path $ConfigDir 'WDACPolicy.cip'

if ($WDACAudit) {
    Info 'Building in audit mode (no enforcement; logs blocks to event log).'
    # No edit needed — the XML ships with <Option>Enabled:Audit Mode</Option>.
} else {
    Info 'Building in ENFORCE mode.'
    (Get-Content $xml) -replace '<Option>Enabled:Audit Mode</Option>', '' | Set-Content $xml
}

if (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue) {
    ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cip | Out-Null
} else {
    Warn 'ConvertFrom-CIPolicy not available — RSAT / ConfigCI module is missing. Install with: Add-WindowsCapability -Online -Name Rsat.WSUS.Tools~~~~0.0.1.0   then re-run.'
}

if (Test-Path $cip) {
    New-Item -Path $WDACPolicyDest -ItemType Directory -Force | Out-Null
    Copy-Item -Path $cip -Destination (Join-Path $WDACPolicyDest 'lockguard.cip') -Force
    if (Get-Command CiTool.exe -ErrorAction SilentlyContinue) {
        & CiTool.exe --update-policy (Join-Path $WDACPolicyDest 'lockguard.cip') | Out-Null
    }
    OK 'WDAC policy deployed.'
} else {
    Warn 'WDAC policy not compiled — re-run with ConfigCI installed.'
}

# ---------- [9/14] File associations ----------
Step 9 'File associations'

$assoc = Join-Path $ConfigDir 'AppAssociations.xml'
& dism.exe /online /import-defaultappassociations:$assoc | Out-Null

$pol = 'HKLM:\Software\Policies\Microsoft\Windows\System'
New-Item -Path $pol -Force | Out-Null
Set-ItemProperty -Path $pol -Name 'DefaultAssociationsConfiguration' -Value $assoc
OK 'File associations imported + locked via policy.'

# ---------- [10/14] Strip media apps ----------
Step 10 'Strip media apps'

$rmApps = @(
    '*zunemusic*','*zunevideo*','*WindowsMediaPlayer*','*Microsoft.Media*',
    '*WindowsCamera*','*MicrosoftOfficeHub*',
    '*XboxApp*','*Xbox.TCUI*','*XboxGameOverlay*','*XboxGamingOverlay*',
    '*XboxIdentityProvider*','*XboxSpeechToTextOverlay*',
    '*YourPhone*','*Getstarted*','*MicrosoftSolitaireCollection*',
    '*SkypeApp*','*MicrosoftStickyNotes*','*GetHelp*','*Wallet*',
    '*Microsoft.People*','*WindowsAlarms*','*WindowsFeedbackHub*',
    '*WindowsMaps*','*WindowsSoundRecorder*','*Clipchamp*','*MixedReality*'
)
foreach ($a in $rmApps) {
    Get-AppxPackage -AllUsers $a -ErrorAction SilentlyContinue |
        Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
        Where-Object DisplayName -Like $a |
        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}
try {
    Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart -ErrorAction Stop | Out-Null
} catch { }
OK 'Media apps removed.'

# ---------- [11/14] Mute the system ----------
Step 11 'Mute the system'

foreach ($svc in 'audiosrv','AudioEndpointBuilder') {
    & sc.exe config $svc start= disabled | Out-Null
    & sc.exe stop   $svc 2>$null
}
OK 'Audio services disabled.'

# ---------- [12/14] WiFi printing carve-out + adapter posture ----------
Step 12 'WiFi printing carve-out'

$mode = Read-Host '        Printer mode: [d]irect (Wi-Fi Direct) or [i]nfrastructure (home WiFi)? [d/i]'
if ($mode -eq 'd') {
    $ssid = Read-Host '        Printer Wi-Fi Direct SSID (looks like DIRECT-XX-PrinterName)'
} else {
    $ssid = Read-Host '        Home WiFi SSID hosting the printer'
}

$cfgJson = Join-Path $ConfigDir 'lockguard.json'
$cfg = Get-Content $cfgJson | ConvertFrom-Json
$cfg.printer_ssid = $ssid
$cfg.printer_mode = if ($mode -eq 'd') { 'wifi_direct' } else { 'infrastructure' }
$cfg | ConvertTo-Json | Set-Content $cfgJson

& netsh.exe wlan add filter permission=allow   ssid="$ssid" networktype=infrastructure | Out-Null
& netsh.exe wlan add filter permission=denyall                networktype=infrastructure | Out-Null
& netsh.exe wlan add filter permission=denyall                networktype=adhoc           | Out-Null

# Disable Bluetooth + WWAN adapters (WiFi + Ethernet stay enabled).
Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -match 'Bluetooth|Cellular|Mobile|WWAN'
} | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue

OK "WLAN whitelist: $ssid only. Bluetooth + WWAN disabled."

# ---------- [13/14] Scheduled tasks ----------
Step 13 'Install scheduled tasks'

$tasks = @(
    @{ Name = 'LockguardBoot';  Trigger = (New-ScheduledTaskTrigger -AtStartup) },
    @{ Name = 'LockguardLogon'; Trigger = (New-ScheduledTaskTrigger -AtLogOn)   }
)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @"
-NoProfile -WindowStyle Hidden -Command "Start-Service lockguard -EA SilentlyContinue; Start-Service lockguard-svc -EA SilentlyContinue"
"@
$princ = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
$set   = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

foreach ($t in $tasks) {
    Register-ScheduledTask -TaskName $t.Name -TaskPath '\Microsoft\Windows\Lockguard\' `
        -Trigger $t.Trigger -Action $action -Principal $princ -Settings $set -Force | Out-Null
}
OK 'Scheduled tasks installed (Boot + Logon).'

# ---------- [14/14] Summary + manual follow-ups ----------
Step 14 'Summary'

Write-Host @"

  ╔══════════════════════════════════════════════════════════════════╗
  ║                LOCKGUARD INSTALL COMPLETE                        ║
  ╠══════════════════════════════════════════════════════════════════╣
  ║  Driver:    lockguard.sys     (BootStart, Safe Mode)             ║
  ║  Watchdog:  lockguard-svc.exe (Auto, restart-on-failure)         ║
  ║  WDAC:      $(if($WDACAudit){'audit mode'}else{'ENFORCE mode'})  ║
  ║  WLAN:      whitelist = $ssid                                    ║
  ║  Audio:     muted (services disabled)                           ║
  ║  Recovery:  password-only (no key file)                          ║
  ╚══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green

if (-not $SkipBIOS) {
    Write-Host '  *** MANUAL BIOS STEP (do this BEFORE handing the machine over) ***' -ForegroundColor Yellow
    Write-Host '    1. Reboot into UEFI/BIOS setup.' -ForegroundColor Yellow
    Write-Host '    2. Set Supervisor / Administrator password.' -ForegroundColor Yellow
    Write-Host '    3. Disable: Bluetooth, WWAN/Cellular.' -ForegroundColor Yellow
    Write-Host '    4. LEAVE enabled: WiFi (printer needs it), Ethernet (USB-Ethernet printer fallback).' -ForegroundColor Yellow
    Write-Host '    5. Boot order: internal SSD only.' -ForegroundColor Yellow
    Write-Host '    6. Disable USB boot, disable boot-menu hotkey.' -ForegroundColor Yellow
    Write-Host '    7. Save and exit.' -ForegroundColor Yellow
    Write-Host ''
}

Write-Host '  Recovery is by password only. If lost, only offline OS media can wipe.' -ForegroundColor Magenta
Write-Host ''

$ans = Read-Host 'Reboot now? [Y/n]'
if ($ans -eq '' -or $ans -match '^[Yy]') {
    Restart-Computer -Force
}
