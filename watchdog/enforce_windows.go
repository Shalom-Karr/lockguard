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
	"strings"
	"time"
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
	out, _ := runQuiet("bcdedit.exe", "/enum", "{current}")
	if !strings.Contains(strings.ToLower(out), "testsigning             yes") {
		runQuiet("bcdedit.exe", "/set", "testsigning", "on")
	}
	if !strings.Contains(strings.ToLower(out), "bootmenupolicy          standard") {
		runQuiet("bcdedit.exe", "/set", "bootmenupolicy", "standard")
	}
	if strings.Contains(strings.ToLower(out), "safeboot") {
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
	if err := copyFile(backup, dst); err != nil {
		return err
	}
	_, err = runQuiet("CiTool.exe", "--update-policy", dst)
	return err
}

func ensureWLANFilter() error {
	out, _ := runQuiet("netsh.exe", "wlan", "show", "filters")
	if strings.Contains(out, "Permit") && strings.Contains(out, "Deny") {
		return nil
	}
	// Re-apply from saved config (lockguard.json carries the SSID).
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.PrinterSSID == "" {
		return nil // nothing to do; install hasn't picked an SSID yet
	}
	runQuiet("netsh.exe", "wlan", "add", "filter",
		"permission=allow", "ssid="+cfg.PrinterSSID, "networktype=infrastructure")
	runQuiet("netsh.exe", "wlan", "add", "filter",
		"permission=denyall", "networktype=infrastructure")
	runQuiet("netsh.exe", "wlan", "add", "filter",
		"permission=denyall", "networktype=adhoc")
	return nil
}

var blockedImages = []string{
	"regedit.exe", "taskmgr.exe", "bcdedit.exe",
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
	exe, _ := os.Executable()
	for _, img := range blockedImages {
		key := `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` + img
		runQuiet("reg.exe", "add", key, "/v", "Debugger", "/t", "REG_SZ",
			"/d", fmt.Sprintf(`"%s" --silent-exit`, exe), "/f")
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
