// lockguard-cli — recovery client. Talks to the lockguard kernel driver
// over the documented IOCTL protocol to open a 10-minute permissive window.
//
//	lockguard-cli.exe --recover           # prompt for password, unlock
//	lockguard-cli.exe --status            # print driver status
//	lockguard-cli.exe --quote             # print the unlock protocol spec
//
// On success, prints "Unlocked — 10:00 remaining." Within that window the
// admin can run Uninstall-Lockguard.ps1, edit protected registry keys,
// delete the .sys file, etc.
package main

import (
	"crypto/hmac"
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
	status := flag.Bool("status", false, "print driver status (permissive window, tamper count)")
	flag.Parse()

	switch {
	case *recover:
		if err := doRecover(); err != nil {
			fmt.Fprintf(os.Stderr, "recover: %v\n", err)
			os.Exit(1)
		}
	case *status:
		if err := doStatus(); err != nil {
			fmt.Fprintf(os.Stderr, "status: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Println("lockguard-cli: recovery client for the Lockguard kernel driver.")
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
