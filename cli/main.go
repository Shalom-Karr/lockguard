// lockguard-cli — recovery / admin client. Talks to the lockguard kernel
// driver over the documented IOCTL protocol to open a 10-minute permissive
// window, change the recovery password, or query status.
//
//	lockguard-cli.exe --recover           # prompt for password, unlock for 10 min
//	lockguard-cli.exe --set-password      # change the recovery / uninstall password
//	lockguard-cli.exe --status            # print driver status
//
// On --recover success, prints "Unlocked — 10:00 remaining." Within that
// window the admin can run Uninstall-Lockguard.ps1, edit protected registry
// keys, delete the .sys file, etc.
//
// --set-password verifies the current password first (same challenge-
// response as --recover), opens the permissive window, then prompts for and
// stores a new password. The new password takes effect immediately for
// future --recover / Uninstall-Lockguard.ps1 runs.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/term"
)

const (
	deviceUNC = `\\.\Lockguard`

	verifierLabel = "LOCKGUARD-VERIFIER-V1"

	recoveryRegKey = `SYSTEM\Lockguard\Recovery`

	derivedKeyLen = 32
	nonceLen      = 32
	verifierLen   = 32
)

func main() {
	recover := flag.Bool("recover", false, "prompt for password and unlock the driver for 10 minutes")
	setPw   := flag.Bool("set-password", false, "verify current password then set a new recovery / uninstall password")
	status  := flag.Bool("status", false, "print driver status (permissive window, tamper count)")
	flag.Parse()

	switch {
	case *recover:
		if err := doRecover(); err != nil {
			fmt.Fprintf(os.Stderr, "recover: %v\n", err)
			os.Exit(1)
		}
	case *setPw:
		if err := doSetPassword(); err != nil {
			fmt.Fprintf(os.Stderr, "set-password: %v\n", err)
			os.Exit(1)
		}
	case *status:
		if err := doStatus(); err != nil {
			fmt.Fprintf(os.Stderr, "status: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Println("lockguard-cli: recovery / admin client for the Lockguard kernel driver.")
		flag.PrintDefaults()
		os.Exit(2)
	}
}

// ---------- recover ----------

func doRecover() error {
	salt, iter, verifier, err := readRecoveryRegistry()
	if err != nil {
		return fmt.Errorf("read HKLM\\%s: %w", recoveryRegKey, err)
	}

	fmt.Print("Recovery password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	derived := pbkdf2.Key(pw, salt, int(iter), derivedKeyLen, sha256.New)
	zero(pw)

	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte(verifierLabel))
	computed := mac.Sum(nil)

	if !hmac.Equal(computed, verifier) {
		zero(derived)
		return fmt.Errorf("wrong password")
	}

	h, err := openDriver()
	if err != nil {
		zero(derived)
		return err
	}
	defer windows.CloseHandle(h)

	nonce, err := ioctlGetNonceCall(h)
	if err != nil {
		zero(derived)
		return fmt.Errorf("get nonce: %w", err)
	}

	respMac := hmac.New(sha256.New, derived)
	respMac.Write(nonce)
	response := respMac.Sum(nil)

	if err := ioctlUnlockCall(h, response, derived); err != nil {
		zero(derived)
		return fmt.Errorf("unlock: %w", err)
	}
	zero(derived)

	fmt.Printf("Unlocked — %d:00 remaining.\n", 10)
	return nil
}

// ---------- status ----------

func doStatus() error {
	h, err := openDriver()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	st, err := ioctlStatusCall(h)
	if err != nil {
		return err
	}
	fmt.Printf("Permissive:        %t\n", st.Permissive != 0)
	if st.Permissive != 0 {
		expires := time.Unix(0, (st.PermissiveExpiresSystemTime-116444736000000000)*100)
		fmt.Printf("Window expires at: %s (%s remaining)\n",
			expires.Format(time.RFC3339), time.Until(expires).Round(time.Second))
	}
	fmt.Printf("Tamper events:     %d\n", st.TamperEventCount)
	if st.LastHeartbeatSystemTime > 0 {
		hb := time.Unix(0, (st.LastHeartbeatSystemTime-116444736000000000)*100)
		fmt.Printf("Last heartbeat:    %s (%s ago)\n",
			hb.Format(time.RFC3339), time.Since(hb).Round(time.Second))
	} else {
		fmt.Println("Last heartbeat:    (never)")
	}
	return nil
}

// ---------- set-password ----------

func doSetPassword() error {
	salt, iter, verifier, err := readRecoveryRegistry()
	if err != nil {
		return fmt.Errorf("read HKLM\\%s: %w", recoveryRegKey, err)
	}

	fmt.Print("Current password: ")
	curPw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	derived := pbkdf2.Key(curPw, salt, int(iter), derivedKeyLen, sha256.New)
	zero(curPw)

	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte(verifierLabel))
	if !hmac.Equal(mac.Sum(nil), verifier) {
		zero(derived)
		return fmt.Errorf("wrong current password")
	}

	// Open the permissive window so the registry callback allows our write.
	h, err := openDriver()
	if err != nil {
		zero(derived)
		return err
	}
	defer windows.CloseHandle(h)

	nonce, err := ioctlGetNonceCall(h)
	if err != nil {
		zero(derived)
		return fmt.Errorf("get nonce: %w", err)
	}
	respMac := hmac.New(sha256.New, derived)
	respMac.Write(nonce)
	response := respMac.Sum(nil)
	if err := ioctlUnlockCall(h, response, derived); err != nil {
		zero(derived)
		return fmt.Errorf("unlock: %w", err)
	}
	zero(derived)
	fmt.Println("Current password verified. Permissive window open. Set the new password.")

	newPw, err := readStrongPasswordTwice()
	if err != nil {
		return err
	}

	newSalt := make([]byte, 32)
	if _, err := rand.Read(newSalt); err != nil {
		zero(newPw)
		return err
	}
	newIter := uint32(1000000)
	newDerived := pbkdf2.Key(newPw, newSalt, int(newIter), derivedKeyLen, sha256.New)
	zero(newPw)

	newMac := hmac.New(sha256.New, newDerived)
	newMac.Write([]byte(verifierLabel))
	newVerifier := newMac.Sum(nil)
	zero(newDerived)

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, recoveryRegKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry for write (permissive window may have expired): %w", err)
	}
	defer k.Close()

	if err := k.SetBinaryValue("InstallSalt", newSalt); err != nil {
		return fmt.Errorf("write InstallSalt: %w", err)
	}
	if err := k.SetDWordValue("Iterations", newIter); err != nil {
		return fmt.Errorf("write Iterations: %w", err)
	}
	if err := k.SetBinaryValue("Verifier", newVerifier); err != nil {
		return fmt.Errorf("write Verifier: %w", err)
	}

	fmt.Println("Password changed.")
	fmt.Println("The new password is required for any future --recover, --set-password,")
	fmt.Println("or Uninstall-Lockguard.ps1 run. Store it safely; there is no key file.")
	return nil
}

func readStrongPasswordTwice() ([]byte, error) {
	for {
		fmt.Print("New password (12+ chars, mixed case + digit): ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		fmt.Print("Confirm new password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			zero(a)
			return nil, err
		}

		ok := func() bool {
			if !bytes.Equal(a, b) {
				fmt.Println("Mismatch. Retry.")
				return false
			}
			if len(a) < 12 {
				fmt.Println("Too short (need ≥ 12 chars).")
				return false
			}
			var hasU, hasL, hasD bool
			for _, c := range a {
				switch {
				case c >= 'A' && c <= 'Z':
					hasU = true
				case c >= 'a' && c <= 'z':
					hasL = true
				case c >= '0' && c <= '9':
					hasD = true
				}
			}
			if !hasU {
				fmt.Println("Need an uppercase letter.")
				return false
			}
			if !hasL {
				fmt.Println("Need a lowercase letter.")
				return false
			}
			if !hasD {
				fmt.Println("Need a digit.")
				return false
			}
			return true
		}()

		zero(b)
		if ok {
			return a, nil
		}
		zero(a)
	}
}

// ---------- registry ----------

func readRecoveryRegistry() (salt []byte, iter uint32, verifier []byte, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryRegKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, 0, nil, err
	}
	defer k.Close()

	salt, _, err = k.GetBinaryValue("InstallSalt")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("InstallSalt: %w", err)
	}
	v, _, err := k.GetIntegerValue("Iterations")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("Iterations: %w", err)
	}
	iter = uint32(v)
	verifier, _, err = k.GetBinaryValue("Verifier")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("Verifier: %w", err)
	}
	if len(verifier) != verifierLen {
		return nil, 0, nil, fmt.Errorf("verifier length %d, want %d", len(verifier), verifierLen)
	}
	return salt, iter, verifier, nil
}

// ---------- IOCTL ----------

const (
	deviceTypeUnknown = uint32(0x22)
	methodBuffered    = uint32(0)
	fileAnyAccess     = uint32(0)
	fileWriteAccess   = uint32(2)
)

func ctlCode(devType, function, method, access uint32) uint32 {
	return (devType << 16) | (access << 14) | (function << 2) | method
}

var (
	ctlGetNonce = ctlCode(deviceTypeUnknown, 0x801, methodBuffered, fileAnyAccess)
	ctlUnlock   = ctlCode(deviceTypeUnknown, 0x802, methodBuffered, fileAnyAccess)
	ctlStatus   = ctlCode(deviceTypeUnknown, 0x804, methodBuffered, fileAnyAccess)
)

type statusReply struct {
	Version                     uint32
	Permissive                  uint8
	_                           [3]byte
	PermissiveExpiresSystemTime int64
	TamperEventCount            uint32
	_                           [4]byte
	LastHeartbeatSystemTime     int64
}

func openDriver() (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(deviceUNC)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s (is the Lockguard driver running?): %w", deviceUNC, err)
	}
	return h, nil
}

func ioctlGetNonceCall(h windows.Handle) ([]byte, error) {
	out := make([]byte, nonceLen)
	var ret uint32
	err := windows.DeviceIoControl(h, ctlGetNonce, nil, 0, &out[0], uint32(len(out)), &ret, nil)
	if err != nil {
		return nil, err
	}
	if ret != nonceLen {
		return nil, fmt.Errorf("nonce: got %d bytes, want %d", ret, nonceLen)
	}
	return out, nil
}

func ioctlUnlockCall(h windows.Handle, response, derivedKey []byte) error {
	if len(response) != nonceLen || len(derivedKey) != derivedKeyLen {
		return fmt.Errorf("bad arg lengths")
	}
	buf := make([]byte, nonceLen+derivedKeyLen)
	copy(buf[:nonceLen], response)
	copy(buf[nonceLen:], derivedKey)

	var ret uint32
	return windows.DeviceIoControl(h, ctlUnlock, &buf[0], uint32(len(buf)), nil, 0, &ret, nil)
}

func ioctlStatusCall(h windows.Handle) (statusReply, error) {
	buf := make([]byte, 40)
	var ret uint32
	err := windows.DeviceIoControl(h, ctlStatus, nil, 0, &buf[0], uint32(len(buf)), &ret, nil)
	if err != nil {
		return statusReply{}, err
	}
	return *(*statusReply)(unsafe.Pointer(&buf[0])), nil
}

// ---------- helpers ----------

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
