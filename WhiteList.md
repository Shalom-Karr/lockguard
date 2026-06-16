# Whitelist Browsing — Plan

Add an optional **hostname-level browsing whitelist** to Lockguard so the friend can reach a small set of allowed sites (e.g. `wikipedia.org`, `docs.microsoft.com`, the home printer's web admin page) while the rest of the public internet remains dead. Per-page granularity is explicitly **not** in scope — that requires TLS MITM and a locally trusted CA, which is heavy infrastructure with worse failure modes than it solves for this use case.

This document is a feature plan branched from `Plan.md`. Implementation will land on `feat/browse-whitelist` and merge to `main` only after the audit notes in `Plan.md` "vulnerabilities" section are first resolved on `main`.

## Context

The base Lockguard build at `main` runs a LAN-only WFP filter — RFC1918 destinations are reachable (so WiFi printing works), every public IP is denied. That is the right default. This document describes the layered escape valve: a curated allow-list of public hostnames that get a kernel-level pass.

Why hostname, not URL?

- The hostname is in cleartext at three independent layers before encryption begins (DNS query, TLS SNI, HTTP `Host` header). We can read it without breaking TLS.
- The URL path lives inside the encrypted stream. Reading it requires a local trust anchor + TLS interception, which breaks certificate pinning in many apps and forces the friend's browser to trust a CA that any other process could also abuse. Too much blast radius for marginal value.

A friend with hostname `youtube.com` allowed will be able to browse all of YouTube. That's an acceptable trade-off for this product. If page-level filtering is ever wanted, it's a separate later effort (MITM proxy + CA install + cert pinning escape hatches).

## What is visible at each layer

When a browser connects to `https://example.com/some/path`:

| Layer | Visible to Lockguard? | Field | Notes |
|---|---|---|---|
| DNS query (UDP/TCP 53) | yes, cleartext | `example.com` | Unless browser uses DoH/DoT — see leaks |
| TCP SYN to destination IP | yes, always | `93.184.216.34:443` | Connection metadata |
| TLS ClientHello → SNI extension | yes, cleartext | `example.com` | First TLS packet, extension type 0 |
| TLS application data | no, encrypted | `GET /some/path` | Inside AES tunnel |
| HTTP `Host:` header (plain HTTP) | yes, cleartext | `example.com` | Only on port 80 / `http://` |
| HTTP path + query (plain HTTP) | yes, cleartext | `/some/path` | Only on port 80 / `http://` |
| HTTP/3 (QUIC) over UDP/443 | partial | SNI in QUIC Initial | Parseable but more work |

So **hostname-level filtering does not require breaking TLS**. We use what's already in the clear.

## Architecture — three defense-in-depth layers

```
  ┌────────────────────────────────────────────────────────────────┐
  │  L1  Local DNS sinkhole                                        │
  │      lockguard-svc binds 127.0.0.1:53; resolves only           │
  │      whitelisted names; all other queries return NXDOMAIN.     │
  │      WFP-deny all outbound port 53 to anything but loopback.   │
  ├────────────────────────────────────────────────────────────────┤
  │  L2  WFP stream callout (kernel)                               │
  │      Buffers first ~512 bytes of every outbound TCP flow.      │
  │      If TLS ClientHello: parse SNI, allow iff in whitelist.    │
  │      If plain HTTP: parse Host header, same.                   │
  │      Catches direct-IP attempts that bypass L1.                │
  ├────────────────────────────────────────────────────────────────┤
  │  L3  Edge / Chrome browser policies                            │
  │      DoH disabled, ECH disabled, extension allow-list locked.  │
  │      Makes L1 and L2 actually authoritative.                   │
  └────────────────────────────────────────────────────────────────┘
```

Each layer is independently meaningful. L1 catches >95% of normal browser traffic at the cheapest place. L2 is the strongest layer because it runs after DNS, before the wire, and isn't bypassable from user mode. L3 closes the browser-level bypass paths (DoH especially) so L1/L2 can't be routed around.

## Why no TLS MITM

Forcing the friend's browser to trust a Lockguard-issued root CA so we can decrypt his traffic:

- Breaks certificate pinning in Office, Edge Sync, Windows Update, many app installers
- Creates a CA in the trust store that the friend (an admin) could pull and use to MITM external services
- Requires running a local TLS-terminating proxy process — another tamper target
- Solves only page-path filtering, which we don't need

Hostname filtering via SNI/DNS gives us 90% of the value at 10% of the complexity. We do not disable or terminate TLS anywhere.

## Components to add

| File | Type | Purpose |
|---|---|---|
| `driver/sni.c` | C, WDK | WFP stream callout. Registers at `FWPM_LAYER_STREAM_V4` / `_V6`. Per-flow context buffers first chunks until TLS `ClientHello` or HTTP request line is identifiable, then matches against the in-kernel whitelist set. |
| `driver/sni_parse.c` | C | TLS ClientHello SNI extractor + HTTP Host header extractor. ~300 lines. Pure parsing, no allocations on the hot path. |
| `driver/whitelist.c` | C | In-kernel whitelist set: hash table of allowed hostnames, refreshed by the watchdog via `IOCTL_SET_WHITELIST`. Suffix-match support so `*.wikipedia.org` works as one rule. |
| `dns/` (Go subpackage under `watchdog/`) | Go | DNS server bound to `127.0.0.1:53` (and `[::1]:53`). Forwards whitelisted names to a configured upstream (`9.9.9.9`, `1.1.1.1`); returns NXDOMAIN for everything else. Watchdog goroutine; no separate binary. |
| `config/browse-whitelist.json` | JSON | The list. Format: `{ "hosts": ["wikipedia.org", "*.wikipedia.org", "docs.microsoft.com"], "upstream_dns": "9.9.9.9" }`. Lives at `C:\ProgramData\Lockguard\config\browse-whitelist.json` — **protected by the same minifilter as every other Lockguard file** (added to the protected-paths list in `driver/minifilter.c`). Writes are denied to all callers — admin, SYSTEM, TrustedInstaller — except inside the permissive window opened by the recovery password. |
| `cli/admin.go` | Go | The **admin dashboard**. `lockguard-cli.exe --admin` launches a console TUI that first prompts for the recovery password (same PBKDF2 + HMAC protocol used by `--recover`), opens the permissive window via `IOCTL_UNLOCK`, then offers menu options: edit whitelist, view driver status, view tamper log, change recovery password, exit. On exit, the dashboard signals the driver to close the permissive window early. Every edit it makes is a normal file write — the minifilter sees the permissive flag and allows it; outside the dashboard, the same write would be denied. |
| `scripts/Update-BrowseWhitelist.ps1` | PS | Optional PowerShell front-end for the same operation, for when the Go CLI isn't on hand. Same password prompt, same IOCTL unlock, then writes the JSON file directly. Functionally equivalent to the dashboard's "edit whitelist" path. |

New IOCTLs on the driver (added to `lockguard.h`):

```c
#define LG_IOCTL_SET_WHITELIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define LG_IOCTL_GET_WHITELIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

`LG_IOCTL_SET_WHITELIST` requires the same PBKDF2-derived key as the recovery channel, signed over the new whitelist's SHA-256. This means changing the allowed sites needs the recovery password — Lockguard's tamper-resistance properties extend to the browse list.

## WFP callout sketch

A callout (not a simple action filter) is required because filters can only act on metadata; callouts can read packet bytes. Sketch of the classify routine:

```c
VOID NTAPI LgSniClassify(
    _In_ const FWPS_INCOMING_VALUES0* in,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* meta,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* out)
{
    LG_FLOW_CTX* fc = (LG_FLOW_CTX*)(ULONG_PTR)flowContext;
    if (!fc) return;

    FWPS_STREAM_CALLOUT_IO_PACKET0* pkt = layerData;
    if (!(pkt->streamData->flags & FWPS_STREAM_FLAG_SEND)) return;

    // Buffer up to 512 bytes per flow.
    LgAppendFlowBuf(fc, pkt->streamData);

    if (fc->parsed) return;
    if (fc->bytesSeen < 5) return;

    char host[256];
    if (LgIsTls(fc->buf, fc->bytesSeen) &&
        LgExtractTlsSni(fc->buf, fc->bytesSeen, host, sizeof host)) {
        fc->parsed = TRUE;
        if (!LgWhitelistMatches(host)) {
            out->actionType = FWP_ACTION_BLOCK;
            out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            LgRecordTamperEvent(L"sni denied");
            return;
        }
    } else if (LgIsHttp(fc->buf, fc->bytesSeen) &&
               LgExtractHttpHost(fc->buf, fc->bytesSeen, host, sizeof host)) {
        fc->parsed = TRUE;
        if (!LgWhitelistMatches(host)) {
            out->actionType = FWP_ACTION_BLOCK;
            out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            LgRecordTamperEvent(L"http host denied");
            return;
        }
    }

    out->actionType = FWP_ACTION_CONTINUE;
}
```

Plus `FwpsFlowAssociateContext0` / `FwpsFlowRemoveContext0` plumbing so each flow gets exactly one `LG_FLOW_CTX` allocated on first send and freed when the flow tears down. Without flow context, every packet would re-parse from scratch and the perf cost would be real.

The existing LAN-only filters (`wfp.c`) continue to permit RFC1918 outright, with no SNI inspection. SNI inspection only runs against public-IP destinations, so printer traffic and link-local mDNS keep working untouched.

## DNS sinkhole sketch

In `watchdog/dns_windows.go`:

```go
func startDnsSinkhole() {
    h := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
        resp := new(dns.Msg)
        resp.SetReply(m)
        if len(m.Question) == 0 || !inWhitelist(m.Question[0].Name) {
            resp.Rcode = dns.RcodeNameError // NXDOMAIN
            w.WriteMsg(resp); return
        }
        // Forward to upstream.
        upstreamResp, _, err := upstream.Exchange(m, cfg.UpstreamDNS+":53")
        if err != nil { resp.Rcode = dns.RcodeServerFailure; w.WriteMsg(resp); return }
        w.WriteMsg(upstreamResp)
    })
    go dns.ListenAndServe("127.0.0.1:53", "udp", h)
    go dns.ListenAndServe("127.0.0.1:53", "tcp", h)
}
```

Then force every adapter to use `127.0.0.1` as its only resolver via `Set-DnsClientServerAddress` in the installer, watch-and-reapply via the watchdog tick, and let the existing kernel registry callback deny tampering.

## Installer integration

Add phase **[12.5/14]** to `Install-Lockguard.ps1`:

```
[12.5/14] Browsing whitelist (optional)
        Prompt: "Enable curated browsing whitelist? [y/N]"
        If yes:
          - Prompt for upstream DNS resolver (default: 9.9.9.9)
          - Loop prompt for allowed hostnames until empty input
          - Validate each entry against ^([a-z0-9-]+\.)+[a-z]{2,}$|^\*\.
          - Write config\browse-whitelist.json
          - Sign with recovery key
          - Push to driver via IOCTL_SET_WHITELIST
          - Set every adapter's DNS to 127.0.0.1
          - Apply Edge/Chrome browser policies:
              DnsOverHttpsMode = "off"
              EncryptedClientHelloEnabled = false
              ExtensionInstallAllowlist = (empty)
              QuicAllowed = false       (forces TCP TLS so SNI is parseable)
          - Watchdog goroutine starts the local DNS server on next tick.
        If no:
          - Skip; system stays internet-dead per main plan.
```

## Block-page UX — friendly redirect instead of "connection refused"

When the WFP kernel drops a connection, the browser shows a generic error (`ERR_CONNECTION_RESET`, "Hmm, we can't reach this page"). Functional, but ugly. We want every blocked navigation to redirect to a hosted block page at `https://filterpage.pages.dev/?blocked=<original-url>` that renders a clean "this site is blocked — talk to Shalom if you need it added" message.

### Why a local-HTTP redirect won't work for HTTPS

The intuitive plan — DNS-sinkhole `youtube.com` to `127.0.0.1`, run a local HTTP server returning a 302 to `filterpage.pages.dev` — works for plain HTTP. For HTTPS it fails: the browser opens a TLS handshake to `127.0.0.1` expecting a cert valid for `youtube.com`, and our local server can't produce one without installing a Lockguard root CA (TLS MITM, which we explicitly rejected). The user sees "Your connection is not private" with a `NET::ERR_CERT_AUTHORITY_INVALID`, no block page renders.

Similarly, the "render localhost in an iframe inside `filterpage.pages.dev`" idea hits two walls: (1) mixed-content blocking (HTTPS pages can't load HTTP frames), and (2) same-origin policy (a `pages.dev` origin can't read or interact with a `127.0.0.1` iframe). Not workable.

### What does work: a forced Edge extension

A Manifest V3 Edge extension hooks every navigation **before TLS even starts**. It can read the destination URL, decide allow/redirect, and replace the navigation with `https://filterpage.pages.dev/?blocked=...`. The browser then loads the block page over its own valid TLS — no cert tricks needed.

Force-installed and lock-it-on via Edge Group Policy registry:

```
HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist
  1 = "<extension-id>;file:///C:/ProgramData/Lockguard/extension/lockguard-block.crx"

HKLM\Software\Policies\Microsoft\Edge\ExtensionSettings
  <extension-id> = {
    "installation_mode": "force_installed",
    "update_url": "file:///C:/ProgramData/Lockguard/extension/updates.xml",
    "toolbar_pin": "force_pinned"
  }
```

`force_installed` means the user cannot disable or remove it. The watchdog re-applies these registry values on every tick; the kernel registry callback denies tampering even between ticks.

### New component

| File | Type | Purpose |
|---|---|---|
| `extension/manifest.json` | MV3 manifest | Permissions: `declarativeNetRequest`, `declarativeNetRequestWithHostAccess`, `tabs`, `<all_urls>` |
| `extension/background.js` | service worker | Reads whitelist (baked-in JSON, hash-pinned at build time), registers a `declarativeNetRequest` rule that matches `*://*/*` and uses `regexSubstitution` to redirect to `https://filterpage.pages.dev/?blocked=\\0`. Whitelisted hostnames get exempt rules at higher priority. |
| `extension/whitelist.json` | JSON | The same hostnames as `config/browse-whitelist.json`, baked into the .crx at build time. Watchdog detects mutation and rebuilds-and-redeploys the extension on whitelist edits. |
| `extension/lockguard-block.crx` | packaged | Built by `Build-Lockguard.ps1`; signed with the Lockguard key. |
| `extension/updates.xml` | local CRX update manifest | Points to local file path so Edge believes the extension auto-updates from `C:\ProgramData\Lockguard\extension\`. |

The block page itself lives at `filterpage.pages.dev` (Cloudflare Pages) — you own it, host whatever HTML/CSS you want there. It reads the `blocked` query parameter, decodes it, and shows "Lockguard blocked this site: [domain]" with an explanation and a request-access button. Pure static HTML, no backend required.

### The extension must be able to reach the block page

`filterpage.pages.dev` (and Cloudflare's edge IPs) must be in the whitelist permanently. Add to install-time defaults:

```json
{
  "hosts": [
    "filterpage.pages.dev",
    "*.pages.dev"
  ],
  "_always_included": true
}
```

If a friend's whitelist edit somehow removes it, the watchdog refuses to apply the change and logs a tamper event — the block page is non-negotiable infrastructure.

### Defense in depth: extension + kernel both fire

The extension is the **user-facing** filter — it produces the nice redirect. The kernel WFP SNI callout is the **enforcement** filter — it produces the deny if the extension is somehow bypassed (developer mode, a different non-extension-aware HTTP client, a malicious script). Both run; either catching the request is sufficient to deny.

A friend who manages to disable the extension still gets `ERR_CONNECTION_RESET` from the kernel layer instead of a redirect. The kernel is authoritative. The extension is cosmetic-plus-quality-of-life.

### Implementation notes

1. The extension's whitelist is **baked in at build time** and the .crx is signed. The browser only loads .crx files matching the signing key, and `force_installed` ignores user overrides. So editing the whitelist in the admin dashboard triggers a rebuild of the .crx — the watchdog detects the new `browse-whitelist.json`, repackages and re-signs the extension, replaces the file on disk, and Edge auto-reloads the extension on its next update check (~5 hour cadence, or immediate if we bump `manifest.json`'s `version`).
2. Alternative we could explore later: a **native-messaging host** that lets the extension query the watchdog's whitelist over a local pipe. Faster updates (no .crx rebuild), but adds a new attack surface. Skip for v1.
3. The block page's query parameters should be sanitized — pass only the hostname, not the full URL, so we don't leak query strings or session tokens to the block page hoster.

## Edge cases / leaks to plug

These are the ways a clever friend would try to escape; each one needs an explicit countermeasure or it's a hole.

### DoH (DNS over HTTPS)
Edge and Chrome default to DoH against `dns.quad9.net`, `cloudflare-dns.com`, `dns.google`. That bypasses the L1 sinkhole entirely — the browser ships DNS queries inside TLS to a public IP.

**Fix:** three coats of paint.
1. Browser policy: `DnsOverHttpsMode = off` (Edge + Chrome both honor it).
2. WFP block at the kernel: list of known DoH endpoint SNIs goes into the deny pre-list; even if the policy is somehow bypassed, the TLS hostname matches the deny rule.
3. The watchdog re-enforces the browser policy registry keys every tick.

### ECH (Encrypted Client Hello)
TLS 1.3 extension (`encrypted_client_hello`, type `0xfe0d`) that encrypts the SNI itself. Chromium has shipped support behind a flag; Cloudflare publishes ECH keys for ~10% of the web today.

**Fix:** if the parser sees an ECH extension in the ClientHello, drop the connection. Browsers fall back to plaintext SNI on retry. Document the trade-off: a small fraction of sites that only serve via ECH may fail; they can be allow-listed by IP if truly needed.

### HTTP/3 over QUIC (UDP/443)
Chromium prefers QUIC for big sites (Google, Cloudflare, Meta). The L2 callout is on TCP streams — QUIC traffic bypasses it.

**Fix easy:** WFP-block all outbound UDP/443. Browsers transparently retry over TCP TLS, which L2 catches. We lose a bit of latency on whitelisted sites; we keep correctness.

**Fix thorough:** add a second callout at `FWPM_LAYER_DATAGRAM_DATA_V4` that parses the QUIC Initial packet's SNI. ~200 more lines. Defer until "easy" proves insufficient.

### Direct IP entry
Friend types `https://93.184.216.34` instead of `example.com`. DNS isn't involved; the TLS ClientHello may still send SNI (browsers usually do, even when navigating by IP), but a hand-crafted client could omit it.

**Fix:** if `ClientHello` has no SNI extension at all, drop. Plus the watchdog tracks per-process "recently resolved IPs from the sinkhole" and the kernel only permits connections whose destination IP appears in that set. Direct-IP gets a TCP RST.

### VPN / Tor
Endpoint is a public IP. Existing LAN-only filter (without whitelist mode) blocks them. With whitelist mode, only the whitelisted hostnames pass — a VPN endpoint matching a whitelisted hostname is exotic and unlikely. Documented limit.

### Browser extensions doing proxy work
WDAC blocks new browser installs. Edge extension installs locked via `ExtensionInstallAllowlist = []`. Watchdog re-enforces. Chromium command-line proxy flags (`--proxy-server=...`) are mooted because WDAC blocks Chrome and Edge launches Edge.exe through the explorer shell with no flags.

### Hosts file / hosts-equivalent tricks
`%SYSTEMROOT%\System32\drivers\etc\hosts` could redirect `wikipedia.org` to a malicious IP outside the LAN. Once L2 enforces "destination IP must come from the sinkhole's recent answers," this becomes harmless — the IP from `hosts` doesn't match.

### Captive portals
Many WiFi networks intercept HTTP/HTTPS to redirect to a login page. If the friend's home WiFi has one, his first attempt to reach a whitelisted site might 302-redirect to `login.netgear.local` which isn't on the whitelist and gets dropped. Documented trade-off; user can add the portal hostname to the whitelist.

## Open decisions

1. **DNS server library**: `miekg/dns` (battle-tested, 5MB vendored) or hand-rolled (~400 lines, no dependency, smaller binary, less robust). **Default: `miekg/dns`.**
2. **QUIC handling**: block UDP/443 outright (easy) vs. add a QUIC SNI parser callout (thorough). **Default: block UDP/443 in v1; add the parser only if real users complain.**
3. **Whitelist edit workflow**: require the full 10-minute recovery window via `Recover-Lockguard.ps1` first, then edit (clean but slow), vs. a dedicated `Update-BrowseWhitelist.ps1` that asks the password and signs a single IOCTL (fast). **Default: dedicated script, same password — the password is the trust root either way.**
4. **Wildcard semantics**: `*.wikipedia.org` matches subdomains only (`en.wikipedia.org`) but not the apex (`wikipedia.org`), so users supply both. Vs. `wikipedia.org` matches apex + all subdomains by default. **Default: `wikipedia.org` matches apex + all subs (less surprising), explicit `*.x` is a synonym.**
5. **Whether to allow IP literals in the whitelist** (`192.30.255.117` for raw GitHub mirrors etc.): yes for IPv4, no for IPv6 (rare for end-user use), validated against not being an RFC1918 / link-local / loopback. **Default: IPv4 literals allowed, watchdog warns at install time.**

## Order of work (when this branch is taken)

1. Implement TLS / HTTP parsers in user-mode first with a unit test harness against captured `ClientHello` bytes. Easier to iterate without kernel reboots.
2. Port parsers to `driver/sni_parse.c` once they pass tests.
3. Add `driver/whitelist.c` (in-kernel hash table) with the SET/GET IOCTLs.
4. Add the WFP callout in `driver/sni.c` and wire it from `DriverEntry`.
5. Add `watchdog/dns_windows.go` and the policy enforcers for Edge.
6. Add `Update-BrowseWhitelist.ps1` and the install phase.
7. Add the leak-plug rules (DoH SNI deny list, UDP/443 block, IP-from-sinkhole enforcement).
8. Update `Plan.md` and `README.md` to document whitelist mode as an optional install flag.

## Verification (after install + reboot, with whitelist mode on)

```powershell
# DNS sinkhole answering
nslookup wikipedia.org      # resolves
nslookup youtube.com        # NXDOMAIN
nslookup wikipedia.org 8.8.8.8   # blocked by WFP — sinkhole is the only resolver

# WFP SNI layer authoritative even on direct IP
curl --resolve wikipedia.org:443:93.184.216.34 https://wikipedia.org   # passes (SNI matches)
curl --resolve youtube.com:443:142.250.190.46  https://youtube.com     # dropped (SNI denied)
curl https://142.250.190.46                                            # dropped (no SNI / not from sinkhole)

# DoH locked
curl https://cloudflare-dns.com/dns-query?name=youtube.com             # SNI = cloudflare-dns.com, dropped

# QUIC blocked
curl --http3 https://www.google.com   # times out (UDP/443 blocked)
curl       https://www.google.com   # fails — google.com not whitelisted, even on TCP

# Whitelisted browsing works end-to-end
# Open Edge, navigate to wikipedia.org → loads
# Navigate to youtube.com → "Hmm, we can't reach this page"

# Whitelist edit requires password
.\Update-BrowseWhitelist.ps1 add news.ycombinator.com   # prompts, signs, refreshes driver
# Bad password attempt → driver denies the SET IOCTL
```

## Status

Not started. Lives on `feat/browse-whitelist` once cut. `main` keeps internet-fully-dead behavior as the safe default.
