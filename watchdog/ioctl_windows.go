//go:build windows && amd64

// IOCTL plumbing — talks to the lockguard.sys driver via DeviceIoControl.

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const (
	deviceUNC = `\\.\Lockguard`

	// Must match driver/lockguard.h.
	ioctlGetNonce   = 0x80000801<<2 | 0 // CTL_CODE(UNKNOWN, 0x801, METHOD_BUFFERED, ANY_ACCESS)
	ioctlUnlock     = 0x80000802<<2 | 0
	ioctlHeartbeat  = 0x80000803<<2 | 0
	ioctlStatus     = 0x80000804<<2 | 0
)

func ctlCode(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

var (
	ctlGetNonce  = ctlCode(0x22, 0x801, 0, 0) // FILE_DEVICE_UNKNOWN=0x22, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0
	ctlUnlock    = ctlCode(0x22, 0x802, 0, 0)
	ctlHeartbeat = ctlCode(0x22, 0x803, 0, 2) // FILE_WRITE_ACCESS=2
	ctlStatus    = ctlCode(0x22, 0x804, 0, 0)
)

type statusReply struct {
	Version                       uint32
	Permissive                    uint8
	_                             [3]byte // pad to align next int64
	PermissiveExpiresSystemTime   int64
	TamperEventCount              uint32
	_                             [4]byte
	LastHeartbeatSystemTime       int64
}

func openDriver() (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(deviceUNC)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", deviceUNC, err)
	}
	return h, nil
}

func sendHeartbeat() error {
	h, err := openDriver()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	var bytesReturned uint32
	return windows.DeviceIoControl(h, ctlHeartbeat, nil, 0, nil, 0, &bytesReturned, nil)
}

func getStatus() (statusReply, error) {
	var reply statusReply
	h, err := openDriver()
	if err != nil {
		return reply, err
	}
	defer windows.CloseHandle(h)

	var bytesReturned uint32
	sz := uint32(40) // packed size of statusReply on amd64
	buf := make([]byte, sz)
	err = windows.DeviceIoControl(h, ctlStatus, nil, 0, &buf[0], sz, &bytesReturned, nil)
	if err != nil {
		return reply, err
	}
	// Manual unpacking — keeps us off cgo and avoids alignment surprises.
	reply.Version = leU32(buf[0:4])
	reply.Permissive = buf[4]
	reply.PermissiveExpiresSystemTime = leI64(buf[8:16])
	reply.TamperEventCount = leU32(buf[16:20])
	reply.LastHeartbeatSystemTime = leI64(buf[24:32])
	return reply, nil
}

func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leI64(b []byte) int64 {
	u := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return int64(u)
}
