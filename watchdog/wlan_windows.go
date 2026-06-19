//go:build windows && amd64

// wlan_windows.go — native WlanAPI bindings replacing the netsh.exe
// shell-outs that ensureWLANFilter() used to make. netsh.exe is denied
// by WDAC (config/WDACPolicy.xml: ID_DENY_NETSH), so any code path that
// shells to it silently fails. wlanapi.dll, by contrast, is a normal
// system DLL that the lockguard-svc.exe process loads in-proc — WDAC
// does not gate DLL loads from an already-allowed image.
//
// Two helpers consumed by enforce_windows.go:
//
//   wlanFiltersOK(ssid)    — does every WLAN iface currently have a
//                            permit entry for ssid AND a deny-all entry?
//   applyWLANFilters(ssid) — install permit(ssid) + deny-all on each
//                            iface, for both infrastructure and adhoc.
//
// Errors from WlanAPI are returned, never discarded — that was the
// other half of the original bug.

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wlanapi = windows.NewLazySystemDLL("wlanapi.dll")

	procWlanOpenHandle     = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanGetFilterList  = wlanapi.NewProc("WlanGetFilterList")
	procWlanSetFilterList  = wlanapi.NewProc("WlanSetFilterList")
	procWlanFreeMemory     = wlanapi.NewProc("WlanFreeMemory")
)

const wlanAPIVersion = 0x00000002

type dot11SSID struct {
	SSIDLength uint32
	SSID       [32]byte
}

type wlanInterfaceInfo struct {
	InterfaceGuid        windows.GUID
	InterfaceDescription [256]uint16
	IsState              uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

type dot11Network struct {
	SSID    dot11SSID
	BSSType uint32 // 1 = infrastructure, 2 = independent (adhoc)
}

const (
	wlanFilterListGroupPolicyPermit = 0
	wlanFilterListGroupPolicyDeny   = 1

	dot11BSSTypeInfrastructure = 1
	dot11BSSTypeIndependent    = 2
)

type dot11NetworkList struct {
	NumberOfItems uint32
	Index         uint32
}

func ssidFromString(s string) (dot11SSID, error) {
	var out dot11SSID
	b := []byte(s)
	if len(b) > 32 {
		return out, fmt.Errorf("ssid %q exceeds 32 bytes", s)
	}
	out.SSIDLength = uint32(len(b))
	copy(out.SSID[:], b)
	return out, nil
}

func ssidEquals(d dot11SSID, s string) bool {
	if int(d.SSIDLength) != len(s) || d.SSIDLength > 32 {
		return false
	}
	return string(d.SSID[:d.SSIDLength]) == s
}

func wlanOpen() (windows.Handle, error) {
	var h windows.Handle
	var negotiated uint32
	r, _, _ := procWlanOpenHandle.Call(
		uintptr(wlanAPIVersion),
		0,
		uintptr(unsafe.Pointer(&negotiated)),
		uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 {
		return 0, fmt.Errorf("WlanOpenHandle: %w", syscall.Errno(r))
	}
	return h, nil
}

func wlanClose(h windows.Handle) {
	procWlanCloseHandle.Call(uintptr(h), 0)
}

func wlanFreeMem(p unsafe.Pointer) {
	if p != nil {
		procWlanFreeMemory.Call(uintptr(p))
	}
}

func wlanEnumInterfaces(h windows.Handle) ([]windows.GUID, error) {
	var listPtr *wlanInterfaceInfoList
	r, _, _ := procWlanEnumInterfaces.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&listPtr)),
	)
	if r != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces: %w", syscall.Errno(r))
	}
	if listPtr == nil {
		return nil, nil
	}
	defer wlanFreeMem(unsafe.Pointer(listPtr))

	n := int(listPtr.NumberOfItems)
	if n == 0 {
		return nil, nil
	}
	base := unsafe.Pointer(uintptr(unsafe.Pointer(listPtr)) + unsafe.Sizeof(*listPtr))
	entrySize := unsafe.Sizeof(wlanInterfaceInfo{})
	guids := make([]windows.GUID, 0, n)
	for i := 0; i < n; i++ {
		e := (*wlanInterfaceInfo)(unsafe.Pointer(uintptr(base) + uintptr(i)*entrySize))
		guids = append(guids, e.InterfaceGuid)
	}
	return guids, nil
}

func wlanGetFilter(h windows.Handle, iface *windows.GUID, listType uint32) ([]dot11Network, error) {
	var listPtr *dot11NetworkList
	r, _, _ := procWlanGetFilterList.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(iface)),
		uintptr(listType),
		0,
		uintptr(unsafe.Pointer(&listPtr)),
	)
	if r != 0 {
		return nil, fmt.Errorf("WlanGetFilterList(type=%d): %w", listType, syscall.Errno(r))
	}
	if listPtr == nil {
		return nil, nil
	}
	defer wlanFreeMem(unsafe.Pointer(listPtr))

	n := int(listPtr.NumberOfItems)
	if n == 0 {
		return nil, nil
	}
	base := unsafe.Pointer(uintptr(unsafe.Pointer(listPtr)) + unsafe.Sizeof(*listPtr))
	entrySize := unsafe.Sizeof(dot11Network{})
	out := make([]dot11Network, n)
	for i := 0; i < n; i++ {
		e := (*dot11Network)(unsafe.Pointer(uintptr(base) + uintptr(i)*entrySize))
		out[i] = *e
	}
	return out, nil
}

func wlanSetFilter(h windows.Handle, iface *windows.GUID, listType uint32, nets []dot11Network) error {
	hdrSize := unsafe.Sizeof(dot11NetworkList{})
	entrySize := unsafe.Sizeof(dot11Network{})
	bufLen := hdrSize + entrySize*uintptr(len(nets))
	buf := make([]byte, bufLen)
	hdr := (*dot11NetworkList)(unsafe.Pointer(&buf[0]))
	hdr.NumberOfItems = uint32(len(nets))
	hdr.Index = 0
	if len(nets) > 0 {
		base := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + hdrSize)
		for i := range nets {
			e := (*dot11Network)(unsafe.Pointer(uintptr(base) + uintptr(i)*entrySize))
			*e = nets[i]
		}
	}
	r, _, _ := procWlanSetFilterList.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(iface)),
		uintptr(listType),
		uintptr(unsafe.Pointer(&buf[0])),
		0,
	)
	if r != 0 {
		return fmt.Errorf("WlanSetFilterList(type=%d): %w", listType, syscall.Errno(r))
	}
	return nil
}

func wlanFiltersOK(allowSSID string) (bool, error) {
	h, err := wlanOpen()
	if err != nil {
		return false, err
	}
	defer wlanClose(h)

	ifaces, err := wlanEnumInterfaces(h)
	if err != nil {
		return false, err
	}
	if len(ifaces) == 0 {
		return true, nil
	}

	for i := range ifaces {
		g := ifaces[i]
		permit, err := wlanGetFilter(h, &g, wlanFilterListGroupPolicyPermit)
		if err != nil {
			return false, err
		}
		deny, err := wlanGetFilter(h, &g, wlanFilterListGroupPolicyDeny)
		if err != nil {
			return false, err
		}
		found := false
		for _, n := range permit {
			if ssidEquals(n.SSID, allowSSID) && n.BSSType == dot11BSSTypeInfrastructure {
				found = true
				break
			}
		}
		if !found || len(deny) == 0 {
			return false, nil
		}
	}
	return true, nil
}

// applyWLANFilters installs permit(allowSSID) + deny-all on every WLAN
// interface, mirroring the three netsh add-filter calls the install script
// makes. An empty-SSID entry with BSSType set is how WlanAPI expresses
// "deny every network of this BSS type."
func applyWLANFilters(allowSSID string) error {
	ssid, err := ssidFromString(allowSSID)
	if err != nil {
		return err
	}
	h, err := wlanOpen()
	if err != nil {
		return err
	}
	defer wlanClose(h)

	ifaces, err := wlanEnumInterfaces(h)
	if err != nil {
		return err
	}
	if len(ifaces) == 0 {
		return nil
	}

	permit := []dot11Network{
		{SSID: ssid, BSSType: dot11BSSTypeInfrastructure},
	}
	deny := []dot11Network{
		{SSID: dot11SSID{}, BSSType: dot11BSSTypeInfrastructure},
		{SSID: dot11SSID{}, BSSType: dot11BSSTypeIndependent},
	}

	for i := range ifaces {
		g := ifaces[i]
		if err := wlanSetFilter(h, &g, wlanFilterListGroupPolicyPermit, permit); err != nil {
			return err
		}
		if err := wlanSetFilter(h, &g, wlanFilterListGroupPolicyDeny, deny); err != nil {
			return err
		}
	}
	return nil
}
