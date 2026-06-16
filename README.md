# lockguard

Kernel-mode lockdown for a Word-only Windows 11 Home focus PC. Allows WiFi printing, blocks the public internet at the WFP layer, resists a tech-savvy admin user. Driver in C; watchdog and recovery CLI in Go.

---

> ## ⚠ NOT OPEN SOURCE — VIEWING ONLY
>
> This repository is **not** open source. You may read the source on GitHub.com. You may **not** clone, build, install, run, deploy, fork-to-use, vendor, modify, or distribute any part of it without **explicit prior written permission from Shalom Karr**. This applies to **personal, private, internal, educational, research, and commercial** use alike. See [`LICENSE`](LICENSE) for the full terms.

---

## What this is

A four-component lockdown stack for turning a Windows 11 Home laptop into a Word-only focus machine that survives an admin-level user actively trying to break out:

| Component | Language | Role |
|---|---|---|
| `lockguard.sys` | C (WDK) | Kernel driver: LAN-only WFP filter, self-protecting registry / file / process / object callbacks, password-based IOCTL recovery channel |
| `lockguard-svc.exe` | Go | LocalSystem watchdog: 30-second enforcement loop, heartbeat to driver, self-heal from backup, IFEO + WLAN + audio re-enforcement |
| `lockguard-cli.exe` | Go | Recovery client: PBKDF2 + HMAC challenge-response over the documented IOCTL protocol; opens a 10-minute permissive window |
| PowerShell scripts | PS 5.1 | `Install-Lockguard.ps1` (14-phase installer), `Recover-Lockguard.ps1` (pure-PS recovery), `Uninstall-Lockguard.ps1` (full teardown), `Build-Lockguard.ps1` (build + sign + bundle) |

Whitelisted apps: **Word**, **Explorer**, **Edge** (PDFs only). All other Win32 binaries blocked by WDAC. Audio service disabled system-wide. File associations for media / scripts / archives mapped to Notepad so double-clicks produce gibberish instead of playback. WiFi printing works via a LAN-only WFP filter (RFC1918 + mDNS/SSDP permitted, public IPs and non-LAN DNS blocked).

## Architecture (5 layers)

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  L1  BIOS / UEFI                                                │
  │      Supervisor pw, boot order locked, USB-boot off, BT/WWAN off│
  ├─────────────────────────────────────────────────────────────────┤
  │  L2  lockguard.sys  (BootStart kernel driver — no DriverUnload) │
  │      • WFP LAN-only filter                                      │
  │      • CmRegisterCallbackEx  (BCD / WLAN / Recovery / Services) │
  │      • PsSetCreateProcessNotifyRoutineEx  (regedit, debuggers)  │
  │      • FltMgr minifilter  (path-protected, even vs SYSTEM)      │
  │      • ObRegisterCallbacks (strip TERMINATE from watchdog)      │
  │      • IOCTL recovery channel (PBKDF2 + HMAC-SHA256)            │
  ├─────────────────────────────────────────────────────────────────┤
  │  L3  lockguard-svc.exe  (LocalSystem, Auto, restart-on-failure) │
  │      30-second loop: driver / WDAC / audio / BCD / WLAN /       │
  │      file-assoc / IFEO / ACL / SHA-256 self-heal                │
  ├─────────────────────────────────────────────────────────────────┤
  │  L4  Policy: WDAC + file-association lock + service disables    │
  │      Whitelist Word/Edge/Explorer; deny PS/cmd/reg/sc/netsh/etc │
  ├─────────────────────────────────────────────────────────────────┤
  │  L5  Scheduled tasks: AtBoot + AtLogon + on event 7036          │
  │      Multiple respawn vectors for L3                            │
  └─────────────────────────────────────────────────────────────────┘
```

Driver ⇄ watchdog mutual protection: each component is hardened against tampering by the other's mechanism. Killing one without the other is denied. Both have multiple respawn paths.

## Source tree

```
lockguard/
  README.md                      this file
  Plan.md                        full design spec (the source of truth)
  LICENSE                        proprietary — no use without written permission

  driver/                        kernel driver (C, WDK)
    lockguard.h     lockguard.c
    wfp.c           regcb.c
    procnotify.c    minifilter.c
    obcallback.c    lockguard.inf
    lockguard.vcxproj

  watchdog/                      LocalSystem service (Go)
    go.mod          main.go
    service_windows.go
    enforce_windows.go
    ioctl_windows.go
    config_windows.go

  cli/                           recovery CLI (Go)
    go.mod          main.go

  config/                        deployed configs
    WDACPolicy.xml
    AppAssociations.xml
    lockguard.json

  scripts/                       PowerShell
    Install-Lockguard.ps1
    Recover-Lockguard.ps1
    Uninstall-Lockguard.ps1
    Build-Lockguard.ps1
```

## Honest threat-model limits (read this before considering deployment)

The target combination (Windows 11 Home + admin user + self-signed test signing + no BitLocker) has three structural weaknesses that cannot be eliminated, only mitigated:

1. **Test signing requires Secure Boot OFF.** An admin can boot a Linux USB and modify the disk directly. Without full-disk encryption there is no offline-attack defense.
2. **Admin can disable test signing with `bcdedit /set testsigning off` from another OS.** The kernel registry callback denies it from inside the running Windows, but the offline BCD edit bypasses that.
3. **Home edition lacks AppLocker GUI, WDAC enforcement with UEFI-lock, and Group Policy editor.** WDAC enforcement on Home is best-effort.

Upgrades that materially change the picture:
- Demote the friend to **Standard user** → eliminates ~80% of attack surface.
- Upgrade to **Pro** → unlocks BitLocker + real WDAC.
- Buy an **EV cert** (~$300/yr) → keeps Secure Boot ON.

The system aims to make breaking out require **hours of expert effort, multiple coordinated steps, and physical access**, not a single PowerShell command. Anything stronger requires one of the upgrades above.

See `Plan.md` for the complete threat model, layer-by-layer attack analysis, and known vulnerabilities.

## Build & deploy (overview)

On the dev machine (Visual Studio 2022 + WDK + Go 1.22+):

```powershell
.\scripts\Build-Lockguard.ps1
# → builds & signs lockguard.sys, lockguard-svc.exe, lockguard-cli.exe
# → exports certs\Lockguard.cer for trust import on target
# → packages bundle\Lockguard-bundle.zip
```

On the target machine (elevated PowerShell, USB with the bundle next to the installer):

```powershell
# First pass: WDAC in audit mode so we can find missed whitelist paths
.\Install-Lockguard.ps1 -BundlePath .\Lockguard-bundle.zip -WDACAudit
# Use the machine for a few hours; review WDAC audit events.

# Second pass: switch WDAC to enforce
.\Install-Lockguard.ps1 -BundlePath .\Lockguard-bundle.zip
# Reboot. BIOS step (set supervisor pw, lock boot order, disable BT/WWAN).
```

## Recovery (password-based, no key file)

```powershell
# Either:
.\Recover-Lockguard.ps1            # pure PowerShell, prompts for password
# or:
lockguard-cli.exe --recover        # compiled Go client, same protocol

# Within the 10-minute permissive window:
.\Uninstall-Lockguard.ps1          # full teardown
```

The password is stored only as a PBKDF2-derived HMAC verifier (1,000,000 iterations, SHA-256) in HKLM. The driver re-derives independently inside the IOCTL handler. Losing the password means recovery requires booting external media.

## Status

Pre-release research project. **The code is structurally complete but has known issues** (see `Plan.md` "vulnerabilities" section and inline `// TODO` markers). The published vulnerability audit names ~5 critical issues that need to be fixed before any real deployment. Do not deploy this on a friend's machine yet.

## License summary

[**Proprietary. All rights reserved.**](LICENSE) Reading the source on GitHub is the only permitted use. Any other use — clone, build, run, fork-to-use, modify, distribute, deploy — requires explicit prior written permission from Shalom Karr. This applies equally to personal, private, internal, educational, research, and commercial contexts.

For permission requests, open a GitHub issue or contact Shalom Karr directly.
