/*
 * lockguard.h — common definitions for the lockguard kernel driver.
 *
 * Implements the WFP LAN-only filter, registry/process/file/object self-
 * protection callbacks, and the password-based IOCTL recovery channel
 * described in ..\..\README.md.
 */

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <fltKernel.h>
#include <bcrypt.h>

#define LG_TAG  'gkcL'   // pool tag — 'Lckg' little-endian

#define LG_DEVICE_NAME     L"\\Device\\Lockguard"
#define LG_SYMLINK_NAME    L"\\??\\Lockguard"

#define LG_RECOVERY_KEY    L"\\Registry\\Machine\\SYSTEM\\Lockguard\\Recovery"
#define LG_SERVICE_KEY     L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Lockguard"
#define LG_SERVICE_KEY_SVC L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\lockguard-svc"
#define LG_BCD_KEY         L"\\Registry\\Machine\\BCD00000000"
#define LG_WLANSVC_KEY     L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Wlansvc"
#define LG_NETCLASS_KEY    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"

#define LG_PROTECTED_DIR_NT L"\\??\\C:\\ProgramData\\Lockguard"
#define LG_PROTECTED_SYS_NT L"\\??\\C:\\Windows\\System32\\drivers\\lockguard.sys"
#define LG_PROTECTED_BCD_NT L"\\??\\C:\\EFI\\Microsoft\\Boot\\BCD"

#define LG_VERIFIER_LABEL  "LOCKGUARD-VERIFIER-V1"
#define LG_VERIFIER_LEN    32   // SHA-256 output
#define LG_NONCE_LEN       32
#define LG_SALT_MAX_LEN    64
#define LG_DERIVED_KEY_LEN 32

#define LG_UNLOCK_WINDOW_SECONDS  600  // 10 minutes
#define LG_NONCE_TTL_SECONDS      60

// Custom IOCTLs. METHOD_BUFFERED + FILE_ANY_ACCESS so an unprivileged caller
// can open the device; the actual auth happens inside the unlock handler.
#define LG_IOCTL_GET_NONCE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LG_IOCTL_UNLOCK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LG_IOCTL_HEARTBEAT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define LG_IOCTL_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _LG_UNLOCK_REQUEST {
    UCHAR Response[LG_NONCE_LEN];       // HMAC(nonce, derived_key)
    UCHAR DerivedKey[LG_DERIVED_KEY_LEN];
} LG_UNLOCK_REQUEST, *PLG_UNLOCK_REQUEST;

typedef struct _LG_STATUS_REPLY {
    ULONG  Version;                      // 1
    BOOLEAN Permissive;                  // TRUE = unlock window active
    LONG64  PermissiveExpiresSystemTime; // 100-ns units since 1601
    ULONG   TamperEventCount;            // monotonic counter
    LONG64  LastHeartbeatSystemTime;     // last watchdog ping
} LG_STATUS_REPLY, *PLG_STATUS_REPLY;

// Forward decls.
DRIVER_INITIALIZE DriverEntry;
DRIVER_DISPATCH   LgDispatchCreateClose;
DRIVER_DISPATCH   LgDispatchDeviceControl;

// Subsystem init/teardown (called from DriverEntry).
NTSTATUS LgWfpInitialize(VOID);
VOID     LgWfpFinalize(VOID);

NTSTATUS LgRegCbInitialize(VOID);
VOID     LgRegCbFinalize(VOID);

NTSTATUS LgProcNotifyInitialize(VOID);
VOID     LgProcNotifyFinalize(VOID);

NTSTATUS LgMiniFilterInitialize(PDRIVER_OBJECT DriverObject);
VOID     LgMiniFilterFinalize(VOID);

NTSTATUS LgObCallbacksInitialize(VOID);
VOID     LgObCallbacksFinalize(VOID);

// IOCTL handlers.
NTSTATUS LgHandleGetNonce(PIRP Irp, PIO_STACK_LOCATION Stk);
NTSTATUS LgHandleUnlock(PIRP Irp, PIO_STACK_LOCATION Stk);
NTSTATUS LgHandleHeartbeat(PIRP Irp, PIO_STACK_LOCATION Stk);
NTSTATUS LgHandleStatus(PIRP Irp, PIO_STACK_LOCATION Stk);

// Crypto helpers (BCrypt in kernel).
NTSTATUS LgHmacSha256(
    _In_reads_bytes_(KeyLen)  PUCHAR Key,    _In_ ULONG KeyLen,
    _In_reads_bytes_(DataLen) PUCHAR Data,   _In_ ULONG DataLen,
    _Out_writes_bytes_(32)    PUCHAR OutMac);

NTSTATUS LgGenerateRandom(_Out_writes_bytes_(Len) PUCHAR Buf, _In_ ULONG Len);

// Permissive window control (set when unlock succeeds, cleared on expiry).
VOID     LgEnterPermissiveWindow(VOID);
BOOLEAN  LgIsPermissive(VOID);
LONG64   LgPermissiveExpiresAt(VOID);

// Tamper accounting (incremented when a callback denies an action).
VOID     LgRecordTamperEvent(_In_ PCWSTR Reason);
ULONG    LgTamperEventCount(VOID);

// Heartbeat accounting.
VOID     LgRecordHeartbeat(VOID);
LONG64   LgLastHeartbeatSystemTime(VOID);

// Recovery verifier loaded once at DriverEntry from HKLM\SYSTEM\Lockguard\Recovery.
// LgUnlockTryVerify recomputes verifier = HMAC(LG_VERIFIER_LABEL, derived_key)
// and constant-time compares to the loaded copy.
NTSTATUS LgRecoveryLoadVerifier(VOID);
NTSTATUS LgRecoveryCheckKey(_In_reads_bytes_(LG_DERIVED_KEY_LEN) PUCHAR DerivedKey);

// Constant-time memcmp.
__forceinline BOOLEAN LgConstantTimeEqual(_In_reads_bytes_(Len) const UCHAR* A,
                                          _In_reads_bytes_(Len) const UCHAR* B,
                                          _In_ ULONG Len)
{
    UCHAR diff = 0;
    for (ULONG i = 0; i < Len; ++i) diff |= (UCHAR)(A[i] ^ B[i]);
    return diff == 0;
}
