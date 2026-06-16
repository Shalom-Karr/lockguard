# Lockdown Plan — Word-only PC for a tech-savvy admin friend

## Project root

All work for this project lives in **`C:\Users\nates\Downloads\Claude\Filter Kernel\`**. Everything is built relative to that root. **This `README.md` is the project's living spec** — every later step references it, and revisions to the plan happen here from now on (the plan file under `~\.claude\plans\` was a one-time bootstrap copy).

Layout the project will grow into:

```
Filter Kernel\
  README.md                          # this plan — source of truth
  driver\                            # lockguard.sys C source, VS project, signed .sys output
    lockguard.c, lockguard.h, lockguard.inf, lockguard.vcxproj
    bin\x64\Release\lockguard.sys
  watchdog\                          # lockguard-svc.exe Go source
    go.mod, main.go, service_windows.go, enforce_windows.go, ...
    lockguard-svc.exe
  cli\                               # lockguard-cli.exe Go recovery tool
    go.mod, main.go, ioctl_windows.go
    lockguard-cli.exe
  config\
    WDACPolicy.xml, AppAssociations.xml, lockguard.json
  scripts\
    Install-Lockguard.ps1
    Recover-Lockguard.ps1            # password-gated; runs from any admin PS prompt
    Uninstall-Lockguard.ps1          # uses the unlock window opened by Recover
  certs\                             # self-signed Lockguard code-signing cert + .pfx (gitignored)
  bundle\                            # zip artifact the installer extracts from
  (no key file — recovery is password-based; remember it)
```

## Context

A friend has asked to have his own Windows 11 Home laptop turned into a focus machine: only Microsoft Word, Explorer, and Edge (PDFs only) can run; no music, video, browsing, or unrestricted internet; USB drives may be plugged in but only `.pdf .doc .docx .txt` are usable; USB and WiFi printing must keep working. He must remain a local admin and is technically skilled — he will actively try to break out. There is no budget for an EV code-signing cert; the kernel driver will be test-signed.

The aim is **defense in depth on hostile ground**: every layer can be broken by a determined admin given enough time, but breaking out should take hours of focused work, multiple coordinated steps, and physical access — not a single PowerShell command.

## Honest threat-model limits (read first)

Windows 11 Home + admin user + test-signed driver = three structural weaknesses that cannot be eliminated, only mitigated:

1. **Test signing requires Secure Boot OFF.** An admin can boot a Linux USB and modify the disk directly. Without BitLocker (Home only has Device Encryption on some hardware, with the recovery key tied to a Microsoft Account), there's no encryption defense.
2. **Admin can run `bcdedit /set testsigning off` and reboot.** Driver stops loading. We mitigate by having a kernel registry callback that blocks BCD writes, but `bootice` / direct BCD-hive edits from another OS bypass this.
3. **Home edition lacks AppLocker GUI, WDAC enforcement with UEFI-lock, and Group Policy editor.** We compensate with raw-registry SRP, kernel-side process-creation blocking, and `CiTool`-deployed WDAC in audit-then-enforce mode — but enforcement on Home is best-effort, not guaranteed.

**Upgrades that materially change the picture** (offered, not assumed):
- Make him a Standard user → eliminates 80% of attack surface.
- Upgrade to Pro → unlocks BitLocker (kills offline disk attacks) and real WDAC.
- Buy an EV cert (~$300/yr) → keeps Secure Boot ON.
- Enable Device Encryption if hardware supports it (Settings → Privacy & Security → Device Encryption) → partial offline-attack defense even on Home.

The plan below assumes none of these and does what is achievable as-is.

## Architecture — five layers

| # | Layer | Function | Weak against |
|---|---|---|---|
| 1 | BIOS / UEFI | Boot path lock, hardware kill | Physical CMOS reset |
| 2 | `lockguard.sys` kernel driver | WFP LAN-only filter (WiFi printing OK, internet dead) + self-protection | `bcdedit testsigning off` from another OS |
| 3 | `lockguard-svc.exe` user-mode watchdog | Respawns driver + re-enforces policy | Kill watchdog + driver in same instant |
| 4 | Policy (WDAC + SRP + file assoc + service disables) | Whitelists Word/Edge/Explorer, mutes audio, kills media apps | Admin can edit registry — countered by layer 2 |
| 5 | Scheduled tasks + boot-start config | Multiple respawn vectors | All taken offline simultaneously |

The two-process buddy system (driver ⇄ watchdog) plus 3 scheduled tasks is the core of the tamper-resistance: an attacker has to kill 5+ things in the same instant before any one of them re-instates the others.

## Components to build

All live under `C:\ProgramData\Lockguard\`. **What actually protects these files from being deleted by the admin friend:**

1. **`lockguard.sys` minifilter** (the actual lock) — registers with FltMgr and returns `STATUS_ACCESS_DENIED` on `IRP_MJ_SET_INFORMATION/FileDispositionInformation` (delete), `FileRenameInformation` (rename-bypass), `IRP_MJ_CREATE` with `FILE_DELETE_ON_CLOSE`, and writes/truncates under `C:\ProgramData\Lockguard\*`, `C:\Windows\System32\drivers\lockguard.sys`, and `\EFI\Microsoft\Boot\BCD`. Path-based, not token-based — denies admin, SYSTEM, and TrustedInstaller-token holders alike.
2. **Loaded-image lock** — while the driver is loaded, Windows holds the `.sys` file open without `FILE_SHARE_DELETE`. Can't delete a running driver's image even with the minifilter off.
3. **`SERVICE_BOOT_START` ordering** — driver loads before user-mode SCM and any login. No window where files exist but the filter is not yet enforcing.
4. **Safe Mode coverage** — driver name added to `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\{Minimal,Network}`. `FltMgr.sys` is core Windows and loads in Safe Mode regardless.
5. **Redundant copies for self-heal** — installer drops encrypted copies of `lockguard.sys`, `lockguard-svc.exe`, and the config files to a second path (`C:\Windows\Lockguard-Restore\`, also minifilter-protected). On any boot, the watchdog verifies SHA256 of the primary set against the restore set and re-stages if anything is missing or mutated.
6. **NTFS ACLs (just first-line)** — TrustedInstaller-only write. Admin can `takeown` + `icacls` to bypass; this only buys seconds and produces a 4670 audit event the watchdog reacts to. ACLs are not the lock.

**What defeats this stack:** booting another OS (Linux USB) bypasses the minifilter entirely — the disk is just bytes. That's the structural hole from test-signing + Secure-Boot-off + no-BitLocker called out at the top of this plan. Not solvable without one of those upgrades.

Component files:

| File | Type | Purpose |
|---|---|---|
| `bin\lockguard.sys` | Kernel driver, C, ~750 lines | WFP LAN-only filter (allow RFC1918, deny public IPs); registry callbacks protect own service key, BCD, and WLAN filter keys; minifilter protects own files; process-notify routine blocks `regedit.exe`, `procexp.exe`, `pchunter.exe`, etc. |
| `bin\lockguard-svc.exe` | Go service, single static binary | Watchdog: monitors driver, re-installs if missing; re-applies registry/file-assoc/service/WLAN-filter settings every 30 s; logs to private event log. Built on kiosk-exit-guard's `service_windows.go` patterns. |
| `bin\lockguard-cli.exe` | Go console, signed | Recovery tool — prompts for password, runs the PBKDF2+HMAC challenge-response described below, sends `DeviceIoControl` IOCTL to unlock the system. Distributed with YOU; deployable from a USB or saved off-machine. |
| `scripts\Recover-Lockguard.ps1` | PowerShell script | Pure-PS alternative recovery client. Implements the same IOCTL protocol via `Rfc2898DeriveBytes` + `HMACSHA256` + `DeviceIoControl` P/Invoke. No compile required, runs from any admin PS prompt. |
| `config\WDACPolicy.xml` | XML | WDAC policy: allow `winword.exe`, `explorer.exe`, `msedge.exe`, Windows essentials, deny the rest. Deployed compiled to `.cip` |
| `config\AppAssociations.xml` | XML | Default file associations (PDF→Edge, DOC/DOCX→Word, TXT→Notepad, all media→Notepad) |
| `config\lockguard.json` | JSON | Service settings; the watchdog reads this and re-enforces if mutated |
| `Install-Lockguard.ps1` | PowerShell | The one-shot installer, described in detail below |

## Build prerequisites (on YOUR dev box, not the target)

- Visual Studio 2022 Community + WDK (matching SDK version) — for the kernel driver
- Go 1.22+ — for watchdog and CLI; same toolchain as kiosk-exit-guard
- `goversioninfo` (`go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest`) — for `.syso` resource embedding
- A self-signed code-signing cert (`New-SelfSignedCertificate -Type CodeSigning -Subject "CN=Lockguard"`)
- The `Microsoft Configurable Code Integrity Policy` schema (ships with WDK)

## Reuse from kiosk-exit-guard

Vendor or copy these patterns from `C:\Users\nates\Downloads\Claude\kiosk-exit-guard\` directly. They are battle-tested in production:

- **Service install / SCM dispatcher** (`service_windows.go`) — adapt `--service-install` / `--service-remove` / `--service-run` flow for `lockguard-svc`.
- **Single-instance enforcement** — `acquireAdminOnlyNamedMutex` with SDDL `D:(A;;0x1F0001;;;BA)(A;;0x1F0001;;;SY)`.
- **LocalSystem → user-session spawning** via `CreateProcessAsUserW` + `pickActiveUserSession()` (only matters if Lockguard needs a UI prompt in the user session — likely not, but the pattern is useful for the recovery channel).
- **HKLM secret storage with DACL reset** — used for the recovery-key HMAC seed.
- **IFEO Debugger-redirect block install** — exactly how Lockguard blocks `regedit.exe`, `taskmgr.exe`, `bcdedit.exe`, `procexp*.exe`, etc. from launching as the friend user.
- **HKCU policy applier** — `DisableTaskMgr`, `NoRun`, `NoTrayContextMenu`, `DisableRegistryTools`.
- **Atomic file replace via `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`** — for the watchdog's self-restore from backup.
- **AtLogon scheduled task install** — `Register-ScheduledTask` wrapper for `LockguardLogon`.
- **`--reset` recovery flag pattern** — model for `lockguard-cli.exe --recover`.

Lift either by copying files into `Filter Kernel\watchdog\internal\` and rewriting the parts that differ (no WebView2 UI, no GitHub auto-update — Lockguard is offline-only), or by importing `github.com/Shalom-Karr/kiosk-exit-guard` as a Go module and using exported helpers if the API surface allows. Default: copy + adapt, since Lockguard's needs diverge enough.

The dev workflow produces three signed artifacts (`lockguard.sys`, `lockguard-svc.exe`, `lockguard-cli.exe`) and three config files, bundled into a zip the installer extracts.

## The kernel driver — what it does

`lockguard.sys` combines a LAN-only WFP filter (so WiFi printing keeps working) with multiple self-protection callbacks:

### Network filtering (the new LAN-only logic — not block-all)

At `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`, filters with explicit IP-range conditions:

| Filter | Action | Condition |
|---|---|---|
| Allow LAN outbound | `FWP_ACTION_PERMIT` | `IP_REMOTE_ADDRESS` in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` |
| Allow LAN inbound | `FWP_ACTION_PERMIT` | same ranges on receive |
| Allow mDNS / SSDP printer discovery | `FWP_ACTION_PERMIT` | UDP dst `224.0.0.251:5353`, `239.255.255.250:1900` |
| Block all DNS to non-LAN | `FWP_ACTION_BLOCK` | dst port 53, remote addr NOT in RFC1918 |
| Default deny outbound | `FWP_ACTION_BLOCK` | (no condition) |
| Default deny inbound | `FWP_ACTION_BLOCK` | (no condition) |

Filter weights are explicit so allow beats deny for printer traffic. Net result: printer on the LAN (Wi-Fi Direct or infrastructure mode) is reachable; the public internet is unreachable even if the friend connects to a WiFi with internet uplink.

### Self-protection layer

1. **No DriverUnload routine.** `DriverObject->DriverUnload = NULL`. Service Control Manager cannot unload the driver after it starts — only a reboot can.
2. **`CmRegisterCallbackEx`** intercepting writes to:
   - `HKLM\SYSTEM\CurrentControlSet\Services\Lockguard*` (own service keys)
   - `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-...}` (network adapter properties — block disable of printer adapters, block enable of others)
   - `HKLM\SYSTEM\CurrentControlSet\Services\Wlansvc\Parameters\Interfaces\*` (WLAN profile + filter list — block tampering with SSID whitelist)
   - `\Registry\Machine\BCD00000000` (BCD — block testsigning/safeboot edits)
   - `HKLM\SYSTEM\Lockguard\Recovery` (recovery verifier — block any post-install write, reads remain open)
   - Returns `STATUS_ACCESS_DENIED` on delete/setvalue. Allows reads.
3. **`PsSetCreateProcessNotifyRoutineEx`** blocking specific images by path/hash:
   - `regedit.exe`, `procmon.exe`, `procexp*.exe`, `pchunter*.exe`, `dbgview.exe`, `kdbgctrl.exe`, `taskmgr.exe`, `services.msc`-launching `mmc.exe`
   - This is belt to WDAC's suspenders.
4. **Minifilter (`FltRegisterFilter`)** denying delete/rename/write on `C:\ProgramData\Lockguard\bin\*` and `C:\ProgramData\Lockguard\config\*`.
5. **`ObRegisterCallbacks`** stripping `PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME` from handles to `lockguard-svc.exe` and `services.exe`. Even admin / SYSTEM cannot terminate the watchdog.
6. **IOCTL recovery channel — password-based, multi-client.** Two IOCTLs:
   - `IOCTL_GET_NONCE` — returns a 32-byte random nonce, single-use, 60 s validity.
   - `IOCTL_UNLOCK` — accepts `(response[32], derived_key[32])`. Driver:
     1. Reads `install_salt`, `iterations`, `verifier` from `HKLM\SYSTEM\Lockguard\Recovery` (set at install time)
     2. Computes `expected_verifier = HMAC-SHA256("LOCKGUARD-VERIFIER-V1", derived_key)`
     3. Constant-time compare to stored `verifier` — must match
     4. Verify `response == HMAC-SHA256(nonce, derived_key)`
     5. On success, disable all protective callbacks for 600 s, log `Lockguard.Recovery.Granted` with caller PID/image.
   The CLI / PowerShell script does the PBKDF2 derivation in user-mode (avoids blocking the driver) and pre-checks the password by computing its own `expected_verifier` before any IOCTL is sent. **Any program implementing the protocol can unlock** — Go CLI, PS script, or a future Python client.

**Driver is set as `SERVICE_BOOT_START` (Start=0)** so it loads before user-mode SCM is up. Even Safe Mode loads it (added to `SafeBoot\Minimal` and `SafeBoot\Network`).

## The watchdog — what it re-enforces

`lockguard-svc.exe` runs as LocalSystem, `SERVICE_AUTO_START`, restart-on-failure. Every 30 s:

1. Check `lockguard.sys` is loaded → if not, `sc start lockguard`.
2. Check WDAC policy file exists in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\` → if not, redeploy from `config\WDACPolicy.cip` + `CiTool --refresh`.
3. Check Audio + AudioEndpointBuilder services are Disabled → if not, re-disable + stop.
4. Check default file associations match `AppAssociations.xml` → if drifted, re-import via DISM.
5. Check NTFS ACLs on `C:\ProgramData\Lockguard\` deny Users write → reapply if changed.
6. Check BCD: `testsigning=on`, `bootmenupolicy=standard`, `safeboot` absent → re-set.
7. Check `netsh wlan show filters` matches the install-time whitelist → if drifted, re-add allow rule for printer SSID + deny-all.
8. Check IFEO blocks (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*`) for the blacklist (`regedit.exe`, `taskmgr.exe`, `bcdedit.exe`, etc.) → re-apply if removed.
9. Heartbeat to driver via IOCTL. If driver stops hearing heartbeats for 90 s, driver logs a tamper event (visible to you via recovery tool).
10. Self-heal: SHA-256 check primary `lockguard.sys` + `lockguard-svc.exe` against the redundant copies in `C:\Windows\Lockguard-Restore\` → if missing or mutated, atomic-replace via `MoveFileEx`.

The watchdog protects the driver. The driver protects the watchdog (object callbacks on its process handle). Mutually protective.

## Scheduled tasks (3 belts to the watchdog's suspenders)

Installed by the PS1 script:

1. **`LockguardBoot`** — At startup, runs as SYSTEM, `Start-Service lockguard; Start-Service lockguard-svc`.
2. **`LockguardLogon`** — At any user logon, same action.
3. **`LockguardHeal`** — On event ID 7036 (service state change) from source "Service Control Manager", action: re-start both services. Catches `sc stop` attempts.

All three are stored in `\Microsoft\Windows\Lockguard\` and ACL'd so only TrustedInstaller can modify.

## `Install-Lockguard.ps1` — the one-shot installer

The deliverable you specifically asked for. Run as admin. Phases (script will print numbered progress):

```
[1/14] Verify environment
        - Elevation check
        - Windows 11 Home detected
        - PowerShell 5.1+ available
        - Internet present? warn if yes (recommend offline install)
        - Refuse to run if D:\Lockguard-bundle.zip not found next to script

[2/14] Restore point + recovery password
        - Checkpoint-Computer -Description "Pre-Lockguard"
        - Prompt YOU for recovery password twice (Read-Host -AsSecureString)
        - Enforce minimum: 12 chars, mixed classes (script rejects weak inputs)
        - Generate 32-byte install_salt
        - Compute derived_key = PBKDF2-SHA256(password, install_salt, 1,000,000 iter)
        - Compute verifier = HMAC-SHA256("LOCKGUARD-VERIFIER-V1", derived_key)
        - Write {install_salt, iterations, verifier} to HKLM\SYSTEM\Lockguard\Recovery
        - ACL the subkey: SYSTEM + Administrators READ only; driver registry callback
          installed in [6/14] then blocks ALL writes (including SYSTEM)
        - Zeroize password + derived_key from script memory
        - PROMPT YOU to confirm you have the password memorized / stored safely

[3/14] Stage files
        - Expand bundle to C:\ProgramData\Lockguard\
        - Set NTFS ACL: TrustedInstaller full, SYSTEM read+execute, Users none
        - Hide folder

[4/14] Cert trust
        - Import Lockguard.cer to LocalMachine\TrustedPublisher
        - Import Lockguard.cer to LocalMachine\Root

[5/14] Enable test signing + boot config
        - bcdedit /set testsigning on
        - bcdedit /set bootmenupolicy standard
        - bcdedit /set advancedoptions off
        - bcdedit /deletevalue safeboot   (if present)
        - WARN: reboot required at end

[6/14] Install driver service (BootStart)
        - sc create lockguard type=kernel start=boot binPath=...lockguard.sys
        - Add to SafeBoot\Minimal and SafeBoot\Network registry hives
        - sc failure lockguard reset=0 actions=restart/5000/restart/5000/restart/5000

[7/14] Install watchdog service (Auto, restart-on-failure)
        - sc create lockguard-svc type=own start=auto binPath=...lockguard-svc.exe
        - sc failure lockguard-svc reset=0 actions=restart/5000/restart/5000/restart/5000
        - sc sidtype lockguard-svc unrestricted

[8/14] Compile + deploy WDAC policy
        - ConvertFrom-CIPolicy WDACPolicy.xml -> WDACPolicy.cip
        - Copy to C:\Windows\System32\CodeIntegrity\CiPolicies\Active\
        - CiTool --update-policy WDACPolicy.cip
        - Policy options enabled: UMCI, Audit (first boot only — flip to Enforce on second run)

[9/14] File associations
        - dism /online /import-defaultappassociations:AppAssociations.xml
        - Lock via registry: HKLM\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration

[10/14] Strip media apps
        - Uninstall list: ZuneMusic, ZuneVideo, WindowsMediaPlayer, MediaPlayer,
          Xbox*, YourPhone, Clipchamp, MixedReality, SkypeApp, Solitaire,
          Getstarted, Wallet, People, WindowsMaps, SoundRecorder, etc.
        - Remove-AppxPackage -AllUsers + Remove-AppxProvisionedPackage
        - Disable-WindowsOptionalFeature WindowsMediaPlayer

[11/14] Mute the system
        - sc config audiosrv start=disabled; sc stop audiosrv
        - sc config AudioEndpointBuilder start=disabled; sc stop AudioEndpointBuilder
        - The watchdog re-enforces these

[12/14] WiFi printing carve-out + adapter posture
        - Detect printer mode:
            * If user picks Wi-Fi Direct: prompt for printer Wi-Fi Direct SSID + key,
              connect once, save profile as the ONLY allowed network.
            * Else (infrastructure): prompt for home Wi-Fi SSID hosting the printer.
        - netsh wlan add filter permission=allow ssid="<chosen>" networktype=infrastructure
        - netsh wlan add filter permission=denyall networktype=infrastructure
        - netsh wlan add filter permission=denyall networktype=adhoc
        - Disable Bluetooth + WWAN at OS level (BIOS step also disables them firmware-side):
            Get-NetAdapter -Name "*Bluetooth*","*Cellular*","*WWAN*" | Disable-NetAdapter -Confirm:$false
        - LEAVE WiFi adapter ENABLED — printer needs it.
        - LEAVE Ethernet adapter ENABLED (in case user later switches to USB-Ethernet printer).
        - WFP LAN-only filter (loaded in [6/14]) is what actually restricts traffic.
        - Driver registry callbacks block tampering with WLAN filter list.

[13/14] Install scheduled tasks
        - Register-ScheduledTask LockguardBoot, LockguardLogon, LockguardHeal
        - All run as SYSTEM, hidden, highest priority

[14/14] Print summary + manual follow-ups
        - Summary table of what installed
        - BIG WARNING with the manual BIOS steps:
            * Set Supervisor password
            * Disable Bluetooth + WWAN at firmware level
            * LEAVE WiFi enabled (printer needs it)
            * LEAVE Ethernet enabled (optional USB-Ethernet printer fallback)
            * Set boot order: internal SSD only
            * Disable USB boot, disable boot menu hotkey
            * Save and exit
        - Print reminder: "Recovery password — make sure it's stored safely.
          No key file exists; the password is the only escape."
        - Prompt: "Reboot now? [Y/n]"
```

Script is idempotent (re-running detects already-installed components and skips). Failures roll back partial state.

## Verification (after install + reboot)

```powershell
# Driver loaded
sc query lockguard            # STATE: 4 RUNNING, START_TYPE: BOOT_START

# Watchdog loaded
sc query lockguard-svc        # STATE: 4 RUNNING

# Network filtered (LAN works, internet dead)
ping <printer-LAN-IP>         # works (e.g. 192.168.1.50)
ping 8.8.8.8                  # blocked — public IP, denied by WFP
nslookup google.com           # times out — DNS to non-LAN resolvers blocked
Test-NetConnection 192.168.1.50 -Port 9100  # printer raw-print port reachable
Test-NetConnection 8.8.8.8                  # all fields fail

# WDAC active
CiTool --list-policies        # Lockguard policy present, IsEnforced: True

# Try to break out (all should fail)
sc stop lockguard             # access denied (registry callback)
sc delete lockguard           # access denied
Remove-Item C:\ProgramData\Lockguard\bin\lockguard.sys  # access denied (minifilter)
bcdedit /set testsigning off  # access denied (registry callback on BCD)
Stop-Process -Name lockguard-svc -Force  # access denied (Ob callback)
regedit                       # blocked by process-notify routine
Get-NetAdapter -Name Bluetooth* | Enable-NetAdapter  # adapter re-disables within seconds (WiFi stays on by design)
netsh wlan add filter permission=allow ssid="EvilNet" networktype=infrastructure  # registry callback denies write
netsh wlan delete filter permission=denyall                                        # registry callback denies write

# Functional whitelist
Start-Process winword.exe     # opens
Start-Process explorer.exe    # opens
Start-Process msedge.exe      # opens, can view local PDF, web pages fail (DNS blocked, public IPs denied)
Start-Process calc.exe        # blocked by WDAC
Start-Process notepad.exe     # opens (we left it for file assoc fallback)

# USB
# Insert USB with: report.pdf, song.mp3, malware.exe, podcast.mp4
# Double-click report.pdf  -> opens in Edge
# Double-click song.mp3    -> opens in Notepad (binary gibberish)
# Double-click malware.exe -> WDAC block dialog
# Double-click podcast.mp4 -> Notepad gibberish

# Print (both paths)
# USB printer: Ctrl+P in Word -> printer listed -> test page prints
# WiFi printer (LAN): Ctrl+P in Word -> printer discoverable via mDNS -> test page prints
#   curl http://192.168.1.50/   # LAN HTTP to printer admin page works
#   curl http://example.com/    # blocked
```

## Recovery path (for YOU) — password-based, no key file

If you ever need to remove the lockdown or fix something:

1. Boot the machine, log in as admin.
2. Open PowerShell as admin. Either:
   - **PowerShell-only path:** `& \\path\to\Recover-Lockguard.ps1` (script can live anywhere — USB, network share, or you paste it in). It prompts for the recovery password, derives the key, runs the challenge-response IOCTL, returns "Unlocked — 10:00 remaining."
   - **Compiled CLI path:** `lockguard-cli.exe --recover` — same protocol, prompts password, same outcome.
3. Within the 10-minute permissive window: run `Uninstall-Lockguard.ps1` (also password-gated; first attempt re-uses the open window, no second prompt needed). It reverses the install — deletes services, restores BCD, re-enables adapters, removes WDAC policy, restores file associations, removes scheduled tasks, deletes registry keys.
4. Reboot — clean machine.

**No USB or key file required.** All you need is the password. The recovery client (PS or Go) can be re-typed, re-downloaded, or pasted in from anywhere — the script is short and the source of truth for it lives in the project README.

**If you lose the password**, the only recovery is booting external media (Linux USB, Windows install media) to delete the `lockguard` service registration and the `.sys` file offline. This works because Secure Boot is off and there's no full-disk encryption — the same hole that costs us against the friend buys back the parent's escape hatch. Document the password well; it is the single point of failure.

## Order of operations (suggested timeline)

Total active time ~2–3 hours, plus one overnight WDAC audit-mode soak.

1. **Day 0 — Dev box prep (1–2 hrs):** Build driver + watchdog + CLI in VS / Go, sign with self-signed cert, package the bundle zip.
2. **Day 1 — Target machine first pass (~1 hr):**
   - Restore point.
   - Run installer with WDAC in **audit mode** (script flag `-WDACAudit`).
   - Use the machine as the friend would for a few hours — install audit shows what WDAC would have blocked. Adjust whitelist for any missed Windows-essential paths.
3. **Day 1 evening:** Re-run installer with WDAC in **enforce mode**. Reboot.
4. **BIOS step (~15 min):** Enter UEFI setup, set Supervisor password, disable Bluetooth + WWAN, LEAVE WiFi + Ethernet enabled (printer needs WiFi), lock boot order to internal SSD, disable USB boot + boot menu. Save.
5. **Verification (~30 min):** Run the verification block above as the admin friend user. Every break-out attempt should fail; every allowed action should succeed; printer test page should print.
6. **Hand-off:** Memorize the recovery password. Done — no key file to lose.

## Files that will be created during execution (summary)

Deployed to disk:
- `C:\ProgramData\Lockguard\bin\{lockguard.sys, lockguard-svc.exe}`
- `C:\ProgramData\Lockguard\config\{WDACPolicy.xml, WDACPolicy.cip, AppAssociations.xml, lockguard.json}`
- `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{policy-guid}.cip`
- Services: `lockguard`, `lockguard-svc`
- Scheduled tasks: `\Microsoft\Windows\Lockguard\{LockguardBoot, LockguardLogon, LockguardHeal}`
- Registry: service keys, BCD edits, file-assoc lock policy, SafeBoot entries

Kept by YOU only (no longer requires a USB — just the password in your head):
- `lockguard-cli.exe` (recovery client, compiled)
- `Recover-Lockguard.ps1` (recovery client, script — re-typable from README if lost)
- `Uninstall-Lockguard.ps1` (full teardown, uses the unlock window opened above)
- The recovery **password** itself, memorized or stored in your password manager

## Open decisions before execution

These change small details of the build, not the architecture. I'd default the way marked unless you say otherwise:

1. **Watchdog & CLI language**: **Go** (decided — single static binary, kiosk-exit-guard reuse, faster to ship). Driver stays C.
2. **Recovery**: **Password-based** (decided — PBKDF2(1M)+HMAC challenge-response, ships as both Go CLI and PS script; no key file). Minimum 12 chars enforced at install.
3. **First install in WDAC audit mode for one day before enforce mode** (default — catches whitelist gaps without locking you out) vs straight to enforce (faster, riskier).
4. **PBKDF2 iterations**: default 1,000,000 (≈500 ms on a modern laptop, slows brute force by 6 orders of magnitude). Bump to 5,000,000 if you want extra margin and don't mind a ~2.5 s recovery prompt.
5. **Wi-Fi printing mode**: **Wi-Fi Direct (P2P)** if printer supports it (cleanest — no router uplink at all), else **infrastructure-mode + LAN-only WFP + SSID whitelist** (works on any printer). Installer auto-detects via `netsh wlan show drivers` and prefers Wi-Fi Direct.
