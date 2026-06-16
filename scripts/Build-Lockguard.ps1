#Requires -Version 5.1

<#
.SYNOPSIS
    Build-Lockguard.ps1 — build, sign, and bundle all Lockguard artifacts.

.DESCRIPTION
    Runs on YOUR dev box (Visual Studio 2022 + WDK + Go 1.22+ installed).
    Produces a self-contained Lockguard-bundle.zip that Install-Lockguard.ps1
    expects sitting next to it on the target machine.

    Steps:
      1. Ensure self-signed code-signing cert exists in CurrentUser\My;
         generate if missing.
      2. Build the kernel driver (msbuild lockguard.vcxproj /p:Configuration=Release).
      3. Build watchdog (go build).
      4. Build CLI (go build).
      5. Sign all three .sys / .exe with signtool /t timestamp /v.
      6. Export Lockguard.cer for cert trust on the target.
      7. Zip everything into bundle/Lockguard-bundle.zip.

.EXAMPLE
    .\Build-Lockguard.ps1
#>

[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$CertSubject   = 'CN=Lockguard',
    [string]$TimestampUrl  = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root          = Split-Path -Parent $PSScriptRoot
$DriverDir     = Join-Path $Root 'driver'
$WatchdogDir   = Join-Path $Root 'watchdog'
$CliDir        = Join-Path $Root 'cli'
$ConfigDir     = Join-Path $Root 'config'
$CertsDir      = Join-Path $Root 'certs'
$BundleDir     = Join-Path $Root 'bundle'

function Step($n, $title) { Write-Host "`n[$n] $title" -ForegroundColor Cyan }
function Info($m)          { Write-Host "    $m" -ForegroundColor Gray }
function OK($m)            { Write-Host "    $m" -ForegroundColor Green }

# ---------- [1] Cert ----------
Step 1 'Code-signing cert'

$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $CertSubject } | Select-Object -First 1
if (-not $cert) {
    Info 'Generating self-signed cert (CurrentUser\My)…'
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
        -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears(5) `
        -CertStoreLocation Cert:\CurrentUser\My
}
OK "Cert thumbprint: $($cert.Thumbprint)"

# Export .cer for trust import on target.
New-Item -ItemType Directory -Path $CertsDir -Force | Out-Null
$cerOut = Join-Path $CertsDir 'Lockguard.cer'
Export-Certificate -Cert $cert -FilePath $cerOut -Force | Out-Null
OK "Exported: $cerOut"

# ---------- [2] Driver ----------
Step 2 'Build kernel driver'

$msbuild = (Get-Command msbuild.exe -ErrorAction SilentlyContinue).Source
if (-not $msbuild) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vs = & $vswhere -latest -requires Microsoft.Component.MSBuild -property installationPath
        $msbuild = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
    }
}
if (-not (Test-Path $msbuild)) { throw 'msbuild not found — install Visual Studio 2022 with C++ workload + WDK.' }

& $msbuild (Join-Path $DriverDir 'lockguard.vcxproj') `
    "/p:Configuration=$Configuration" '/p:Platform=x64' '/m' '/v:minimal'

$sys = Join-Path $Root "bin\x64\$Configuration\lockguard.sys"
if (-not (Test-Path $sys)) { throw "Driver build produced no .sys at $sys" }
OK "lockguard.sys built: $sys"

# ---------- [3] Watchdog ----------
Step 3 'Build watchdog (Go)'

Push-Location $WatchdogDir
try {
    & go.exe build -trimpath -ldflags='-s -w -H windowsgui' -o lockguard-svc.exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build watchdog failed' }
} finally { Pop-Location }
$svc = Join-Path $WatchdogDir 'lockguard-svc.exe'
OK "lockguard-svc.exe built: $svc"

# ---------- [4] CLI ----------
Step 4 'Build CLI (Go)'

Push-Location $CliDir
try {
    & go.exe build -trimpath -ldflags='-s -w' -o lockguard-cli.exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build cli failed' }
} finally { Pop-Location }
$cli = Join-Path $CliDir 'lockguard-cli.exe'
OK "lockguard-cli.exe built: $cli"

# ---------- [5] Sign ----------
Step 5 'Sign artifacts'

$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
if (-not $signtool) {
    # Fall back to the WDK's signtool.
    $wdkRoot = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Directory |
               Sort-Object Name -Descending | Select-Object -First 1
    if ($wdkRoot) { $signtool = Join-Path $wdkRoot.FullName 'x64\signtool.exe' }
}
if (-not (Test-Path $signtool)) { throw 'signtool.exe not found.' }

foreach ($p in $sys, $svc, $cli) {
    & $signtool sign /v /fd SHA256 /sha1 $cert.Thumbprint /t $TimestampUrl $p
    if ($LASTEXITCODE -ne 0) { throw "signtool failed on $p" }
}
OK 'All three artifacts signed.'

# ---------- [6] Bundle ----------
Step 6 'Package bundle'

$stage = Join-Path $env:TEMP 'lockguard-bundle-stage'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage           | Out-Null
New-Item -ItemType Directory -Path "$stage\bin"     | Out-Null
New-Item -ItemType Directory -Path "$stage\config"  | Out-Null
New-Item -ItemType Directory -Path "$stage\certs"   | Out-Null

Copy-Item $sys      "$stage\bin\"
Copy-Item $svc      "$stage\bin\"
Copy-Item $cli      "$stage\bin\"
Copy-Item "$ConfigDir\*" "$stage\config\" -Recurse
Copy-Item $cerOut   "$stage\certs\"

New-Item -ItemType Directory -Path $BundleDir -Force | Out-Null
$bundleZip = Join-Path $BundleDir 'Lockguard-bundle.zip'
if (Test-Path $bundleZip) { Remove-Item $bundleZip -Force }
Compress-Archive -Path "$stage\*" -DestinationPath $bundleZip
OK "Bundle: $bundleZip"

Remove-Item $stage -Recurse -Force

Write-Host @"

  ╔══════════════════════════════════════════════════════════════════╗
  ║              BUILD COMPLETE — READY TO DEPLOY                    ║
  ╠══════════════════════════════════════════════════════════════════╣
  ║  Bundle:  $bundleZip                                             ║
  ║  Cert:    $cerOut                                                ║
  ║                                                                  ║
  ║  Next: copy bundle + Install-Lockguard.ps1 to target USB.        ║
  ║  Then on target as admin:                                        ║
  ║      .\Install-Lockguard.ps1 -BundlePath .\Lockguard-bundle.zip  ║
  ╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green
