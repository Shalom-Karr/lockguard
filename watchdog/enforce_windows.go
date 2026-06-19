//go:build windows && amd64

// enforce_windows.go — the 30 s enforcement loop.
//
// Each tick we walk a list of checks (driver loaded, audio muted, WDAC
// policy present, file associations, WLAN filter, IFEO blocks, BCD,
// ACLs, file integrity) and remediate any drift. Then heartbeat to the
// driver so it knows we're alive.
//
// Single-pass mode (-once) for debugging the same logic without SCM.

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// BCD output is locale-translated and column spacing varies by Windows
// version; match key/value pairs with a case-insensitive whitespace-tolerant
// regex rather than fixed English substrings.
var (
	bcdTestSigningRe   = regexp.MustCompile(`(?i)\btestsigning\s+yes\b`)
	bcdBootMenuStdRe   = regexp.MustCompile(`(?i)\bbootmenupolicy\s+standard\b`)
	bcdSafeBootPresent = regexp.MustCompile(`(?i)\bsafeboot\b`)
)

const (
	enforceInterval  = 30 * time.Second
	restorePath      = `C:\Windows\Lockguard-Restore`
	programDataPath  = `C:\ProgramData\Lockguard`
	driverPathPrimary = `C:\Windows\System32\drivers\lockguard.sys`
	driverPathBackup  = `C:\Windows\Lockguard-Restore\lockguard.sys`
	wdacPolicyDir    = `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`
)

type checker struct {
	name string
	fn   func() error
}

var checks = []checker{
	{"driver-running", ensureDriverRunning},
	{"audio-disabled", ensureAudioDisabled},
	{"audio-endpoint-disabled", ensureAudioEndpointDisabled},
	{"bcd-state", ensureBCDState},
	{"wdac-policy", ensureWDACPolicy},
	{"wlan-filter", ensureWLANFilter},
	{"ifeo-blocks", ensureIFEOBlocks},
	{"file-integrity", ensureFileIntegrity},
}

func enforceOnce() {
	for _, c := range checks {
		if err := c.fn(); err != nil {
			log.Printf("[enforce] %s: %v", c.name, err)
		} else {
			log.Printf("[enforce] %s: ok", c.name)
		}
	}
}

func enforceLoop(stop <-chan struct{}) {
	t := time.NewTicker(enforceInterval)
	defer t.Stop()

	enforceOnce()
	if err := sendHeartbeat(); err != nil {
		log.Printf("[hb] %v", err)
	}

	for {
		select {
		case <-stop:
			return
		case <-t.C:
			enforceOnce()
			if err := sendHeartbeat(); err != nil {
				log.Printf("[hb] %v", err)
			}
		}
	}
}

// ---------- individual checks ----------

func runQuiet(cmd string, args ...string) (string, error) {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	return string(out), err
}

func ensureDriverRunning() error {
	out, _ := runQuiet("sc.exe", "query", "lockguard")
	if strings.Contains(out, "RUNNING") {
		return nil
	}
	_, err := runQuiet("sc.exe", "start", "lockguard")
	return err
}

func ensureServiceDisabled(name string) error {
	out, _ := runQuiet("sc.exe", "qc", name)
	if strings.Contains(out, "DISABLED") {
		// Also make sure it's not running.
		runQuiet("sc.exe", "stop", name)
		return nil
	}
	if _, err := runQuiet("sc.exe", "config", name, "start=", "disabled"); err != nil {
		return err
	}
	runQuiet("sc.exe", "stop", name)
	return nil
}

func ensureAudioDisabled() error          { return ensureServiceDisabled("audiosrv") }
func ensureAudioEndpointDisabled() error  { return ensureServiceDisabled("AudioEndpointBuilder") }

func ensureBCDState() error {
	// Confirm test-signing=on, bootmenupolicy=standard, safeboot absent.
	//
	// bcdedit.exe must NOT appear in blockedImages below — the IFEO Debugger
	// trampoline would otherwise prevent our own watchdog from invoking it.
	// Output is parsed with case-insensitive, whitespace-tolerant regexes so
	// it works on non-English Windows and across column-width changes.
	out, _ := runQuiet("bcdedit.exe", "/enum", "{current}")
	if !bcdTestSigningRe.MatchString(out) {
		runQuiet("bcdedit.exe", "/set", "testsigning", "on")
	}
	if !bcdBootMenuStdRe.MatchString(out) {
		runQuiet("bcdedit.exe", "/set", "bootmenupolicy", "standard")
	}
	if bcdSafeBootPresent.MatchString(out) {
		runQuiet("bcdedit.exe", "/deletevalue", "safeboot")
	}
	return nil
}

func ensureWDACPolicy() error {
	matches, err := filepath.Glob(filepath.Join(wdacPolicyDir, "*.cip"))
	if err != nil {
		return err
	}
	if len(matches) > 0 {
		return nil
	}
	// Redeploy from backup.
	backup := filepath.Join(programDataPath, `config`, `WDACPolicy.cip`)
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("no policy on disk and no backup at %s", backup)
	}
	dst := filepath.Join(wdacPolicyDir, "lockguard.cip")
	// Copy the .cip into the CiPolicies\Active directory. On Win10 1903+ /
	// Win11 multi-policy format this file-drop is the native CI deployment
	// mechanism: the policy is loaded by the CI driver at next boot. We
	// intentionally do NOT shell out to CiTool.exe here because CiTool is
	// not on the WDAC allowlist, so WDAC would block its execution and the
	// watchdog would be unable to recover. The file presence in Active is
	// what persists the policy across reboots.
	return copyFile(backup, dst)
}

func ensureWLANFilter() error {
	// netsh.exe is denied by WDAC, so we drive WlanAPI directly via
	// wlanapi.dll in-proc. See wlan_windows.go.
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.PrinterSSID == "" {
		return nil // nothing to do; install hasn't picked an SSID yet
	}
	ok, err := wlanFiltersOK(cfg.PrinterSSID)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return applyWLANFilters(cfg.PrinterSSID)
}

// NOTE: bcdedit.exe is intentionally NOT in this list — ensureBCDState()
// needs to invoke it. Other admin-recovery tools remain blocked.
var blockedImages = []string{
	"regedit.exe", "taskmgr.exe",
	"procmon.exe", "procmon64.exe",
	"procexp.exe", "procexp64.exe",
	"pchunter.exe", "pchunter64.exe",
	"dbgview.exe", "windbg.exe", "x64dbg.exe",
	"autoruns.exe", "autorunsc.exe",
	"powershell_ise.exe",
}

func ensureIFEOBlocks() error {
	// Each blocked image gets an IFEO "Debugger" value pointing at a no-op
	// trampoline (lockguard-svc.exe --silent-exit) so launches exit instantly.
	// Use the native registry API so we don't depend on reg.exe (which WDAC
	// denies once the policy is enforcing).
	exe, _ := os.Executable()
	debugger := fmt.Sprintf(`"%s" --silent-exit`, exe)
	const ifeoBase = `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	for _, img := range blockedImages {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ifeoBase+`\`+img, registry.SET_VALUE)
		if err != nil {
			log.Printf("[ifeo] create %s: %v", img, err)
			continue
		}
		if err := k.SetStringValue("Debugger", debugger); err != nil {
			log.Printf("[ifeo] set %s: %v", img, err)
		}
		k.Close()
	}
	return nil
}

func ensureFileIntegrity() error {
	pairs := []struct{ primary, backup string }{
		{driverPathPrimary, driverPathBackup},
		{filepath.Join(programDataPath, "bin", "lockguard-svc.exe"),
			filepath.Join(restorePath, "lockguard-svc.exe")},
	}
	for _, p := range pairs {
		ph, perr := fileHash(p.primary)
		bh, berr := fileHash(p.backup)

		switch {
		case perr != nil && berr == nil:
			// Primary missing — restore from backup.
			if err := copyFile(p.backup, p.primary); err != nil {
				return fmt.Errorf("restore %s: %w", p.primary, err)
			}
		case perr == nil && berr == nil && ph != bh:
			// Primary mutated — overwrite from backup.
			if err := atomicReplace(p.backup, p.primary); err != nil {
				return fmt.Errorf("repair %s: %w", p.primary, err)
			}
		}
	}
	return nil
}

// ---------- file helpers ----------

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// atomicReplace stages dst.new then MoveFileEx(replace_existing).
func atomicReplace(src, dst string) error {
	stage := dst + ".new"
	if err := copyFile(src, stage); err != nil {
		return err
	}
	return os.Rename(stage, dst)
}
