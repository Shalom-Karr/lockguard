/*
 * lockguard.c — DriverEntry, device + IOCTL dispatcher, permissive-window
 * state machine, crypto helpers, recovery-verifier loader.
 *
 * DriverEntry wires all subsystems (WFP, registry callback, process notify,
 * minifilter, object callbacks) in order; on any failure it tears down the
 * partial state and returns. There is intentionally NO DriverUnload — once
 * the driver is loaded, SCM cannot ask it to leave.
 */

#include "lockguard.h"

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "ksecdd.lib")
#pragma comment(lib, "uuid.lib")

// -------- Global state -------------------------------------------------------

static PDEVICE_OBJECT gDeviceObject = NULL;
static UNICODE_STRING gSymlinkName;

static KSPIN_LOCK     gNonceLock;
static UCHAR          gPendingNonce[LG_NONCE_LEN];
static BOOLEAN        gNonceValid = FALSE;
static LARGE_INTEGER  gNonceIssuedAt;

static KSPIN_LOCK     gPermissiveLock;
static volatile BOOLEAN gPermissive = FALSE;
static volatile LONG64  gPermissiveExpires = 0;   // 100-ns FILETIME

static volatile LONG    gTamperCount = 0;
static volatile LONG64  gLastHeartbeat = 0;

// Loaded once from HKLM\SYSTEM\Lockguard\Recovery at DriverEntry.
static UCHAR  gInstallSalt[LG_SALT_MAX_LEN];
static ULONG  gInstallSaltLen = 0;
static ULONG  gIterations = 0;
static UCHAR  gStoredVerifier[LG_VERIFIER_LEN];
static BOOLEAN gVerifierLoaded = FALSE;

// -------- Permissive window --------------------------------------------------

VOID LgEnterPermissiveWindow(VOID)
{
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LONG64 expires = now.QuadPart + (LONG64)LG_UNLOCK_WINDOW_SECONDS * 10000000LL;

    KIRQL irql;
    KeAcquireSpinLock(&gPermissiveLock, &irql);
    gPermissive = TRUE;
    gPermissiveExpires = expires;
    KeReleaseSpinLock(&gPermissiveLock, irql);

    DbgPrint("[lockguard] entered permissive window for %d seconds\n",
             LG_UNLOCK_WINDOW_SECONDS);
}

BOOLEAN LgIsPermissive(VOID)
{
    if (!gPermissive) return FALSE;

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL irql;
    KeAcquireSpinLock(&gPermissiveLock, &irql);
    BOOLEAN active = gPermissive && (now.QuadPart < gPermissiveExpires);
    if (gPermissive && !active) {
        gPermissive = FALSE;
        gPermissiveExpires = 0;
    }
    KeReleaseSpinLock(&gPermissiveLock, irql);

    return active;
}

LONG64 LgPermissiveExpiresAt(VOID) { return gPermissiveExpires; }

// -------- Tamper accounting --------------------------------------------------

VOID LgRecordTamperEvent(_In_ PCWSTR Reason)
{
    InterlockedIncrement(&gTamperCount);
    DbgPrint("[lockguard] tamper denied: %ws (count=%d)\n",
             Reason ? Reason : L"(unknown)", gTamperCount);
}

ULONG LgTamperEventCount(VOID) { return (ULONG)gTamperCount; }

VOID LgRecordHeartbeat(VOID)
{
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    InterlockedExchange64(&gLastHeartbeat, now.QuadPart);
}

LONG64 LgLastHeartbeatSystemTime(VOID) { return gLastHeartbeat; }

// -------- Crypto -------------------------------------------------------------

NTSTATUS LgGenerateRandom(_Out_writes_bytes_(Len) PUCHAR Buf, _In_ ULONG Len)
{
    return BCryptGenRandom(NULL, Buf, Len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

NTSTATUS LgHmacSha256(_In_reads_bytes_(KeyLen)  PUCHAR Key,    _In_ ULONG KeyLen,
                     _In_reads_bytes_(DataLen) PUCHAR Data,   _In_ ULONG DataLen,
                     _Out_writes_bytes_(32)    PUCHAR OutMac)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                          BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, Key, KeyLen, 0);
    if (!NT_SUCCESS(status)) goto done;

    status = BCryptHashData(hHash, Data, DataLen, 0);
    if (!NT_SUCCESS(status)) goto done;

    status = BCryptFinishHash(hHash, OutMac, 32, 0);

done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

// -------- Recovery verifier (HKLM\SYSTEM\Lockguard\Recovery) -----------------

static NTSTATUS LgReadRegBytes(HANDLE Key, PCWSTR Name,
                               PUCHAR Buf, ULONG BufLen, PULONG OutLen)
{
    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, Name);

    UCHAR stackBuf[512];
    ULONG resultLen = 0;
    NTSTATUS status = ZwQueryValueKey(Key, &valueName, KeyValuePartialInformation,
                                       stackBuf, sizeof(stackBuf), &resultLen);
    if (!NT_SUCCESS(status)) return status;

    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)stackBuf;
    if (info->DataLength > BufLen) return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(Buf, info->Data, info->DataLength);
    if (OutLen) *OutLen = info->DataLength;
    return STATUS_SUCCESS;
}

static NTSTATUS LgReadRegDword(HANDLE Key, PCWSTR Name, PULONG OutValue)
{
    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, Name);

    UCHAR stackBuf[64];
    ULONG resultLen = 0;
    NTSTATUS status = ZwQueryValueKey(Key, &valueName, KeyValuePartialInformation,
                                       stackBuf, sizeof(stackBuf), &resultLen);
    if (!NT_SUCCESS(status)) return status;

    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)stackBuf;
    if (info->Type != REG_DWORD || info->DataLength != sizeof(ULONG))
        return STATUS_OBJECT_TYPE_MISMATCH;

    *OutValue = *(PULONG)info->Data;
    return STATUS_SUCCESS;
}

NTSTATUS LgRecoveryLoadVerifier(VOID)
{
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, LG_RECOVERY_KEY);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    HANDLE key = NULL;
    NTSTATUS status = ZwOpenKey(&key, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[lockguard] could not open recovery key: 0x%x\n", status);
        return status;
    }

    ULONG saltLen = 0;
    status = LgReadRegBytes(key, L"InstallSalt",
                            gInstallSalt, sizeof(gInstallSalt), &saltLen);
    if (!NT_SUCCESS(status)) goto done;
    gInstallSaltLen = saltLen;

    status = LgReadRegDword(key, L"Iterations", &gIterations);
    if (!NT_SUCCESS(status)) goto done;

    ULONG verifierLen = 0;
    status = LgReadRegBytes(key, L"Verifier",
                            gStoredVerifier, sizeof(gStoredVerifier), &verifierLen);
    if (!NT_SUCCESS(status)) goto done;
    if (verifierLen != LG_VERIFIER_LEN) { status = STATUS_INVALID_PARAMETER; goto done; }

    gVerifierLoaded = TRUE;

done:
    if (key) ZwClose(key);
    return status;
}

NTSTATUS LgRecoveryCheckKey(_In_reads_bytes_(LG_DERIVED_KEY_LEN) PUCHAR DerivedKey)
{
    if (!gVerifierLoaded) return STATUS_NOT_FOUND;

    UCHAR computed[LG_VERIFIER_LEN];
    NTSTATUS status = LgHmacSha256(DerivedKey, LG_DERIVED_KEY_LEN,
                                    (PUCHAR)LG_VERIFIER_LABEL,
                                    (ULONG)strlen(LG_VERIFIER_LABEL),
                                    computed);
    if (!NT_SUCCESS(status)) return status;

    if (!LgConstantTimeEqual(computed, gStoredVerifier, LG_VERIFIER_LEN))
        return STATUS_ACCESS_DENIED;

    return STATUS_SUCCESS;
}

// -------- IOCTL handlers -----------------------------------------------------

NTSTATUS LgHandleGetNonce(PIRP Irp, PIO_STACK_LOCATION Stk)
{
    if (Stk->Parameters.DeviceIoControl.OutputBufferLength < LG_NONCE_LEN)
        return STATUS_BUFFER_TOO_SMALL;

    UCHAR nonce[LG_NONCE_LEN];
    NTSTATUS status = LgGenerateRandom(nonce, LG_NONCE_LEN);
    if (!NT_SUCCESS(status)) return status;

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL irql;
    KeAcquireSpinLock(&gNonceLock, &irql);
    RtlCopyMemory(gPendingNonce, nonce, LG_NONCE_LEN);
    gNonceValid = TRUE;
    gNonceIssuedAt = now;
    KeReleaseSpinLock(&gNonceLock, irql);

    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, nonce, LG_NONCE_LEN);
    Irp->IoStatus.Information = LG_NONCE_LEN;
    return STATUS_SUCCESS;
}

NTSTATUS LgHandleUnlock(PIRP Irp, PIO_STACK_LOCATION Stk)
{
    if (Stk->Parameters.DeviceIoControl.InputBufferLength < sizeof(LG_UNLOCK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    PLG_UNLOCK_REQUEST req = (PLG_UNLOCK_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    UCHAR nonce[LG_NONCE_LEN];
    BOOLEAN nonceOk = FALSE;
    LARGE_INTEGER issuedAt;

    KIRQL irql;
    KeAcquireSpinLock(&gNonceLock, &irql);
    if (gNonceValid) {
        RtlCopyMemory(nonce, gPendingNonce, LG_NONCE_LEN);
        issuedAt = gNonceIssuedAt;
        gNonceValid = FALSE;  // single-use
        RtlSecureZeroMemory(gPendingNonce, LG_NONCE_LEN);
        nonceOk = TRUE;
    }
    KeReleaseSpinLock(&gNonceLock, irql);

    if (!nonceOk) {
        LgRecordTamperEvent(L"unlock without nonce");
        return STATUS_ACCESS_DENIED;
    }

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LONG64 age100ns = now.QuadPart - issuedAt.QuadPart;
    if (age100ns > (LONG64)LG_NONCE_TTL_SECONDS * 10000000LL) {
        LgRecordTamperEvent(L"unlock with stale nonce");
        return STATUS_TIMEOUT;
    }

    NTSTATUS status = LgRecoveryCheckKey(req->DerivedKey);
    if (!NT_SUCCESS(status)) {
        LgRecordTamperEvent(L"unlock with wrong key");
        RtlSecureZeroMemory(req, sizeof(*req));
        return STATUS_ACCESS_DENIED;
    }

    UCHAR expected[LG_NONCE_LEN];
    status = LgHmacSha256(req->DerivedKey, LG_DERIVED_KEY_LEN,
                          nonce, LG_NONCE_LEN, expected);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(req, sizeof(*req));
        return status;
    }

    if (!LgConstantTimeEqual(req->Response, expected, LG_NONCE_LEN)) {
        LgRecordTamperEvent(L"unlock challenge mismatch");
        RtlSecureZeroMemory(req, sizeof(*req));
        return STATUS_ACCESS_DENIED;
    }

    LgEnterPermissiveWindow();
    RtlSecureZeroMemory(req, sizeof(*req));
    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

NTSTATUS LgHandleHeartbeat(PIRP Irp, PIO_STACK_LOCATION Stk)
{
    UNREFERENCED_PARAMETER(Stk);
    LgRecordHeartbeat();
    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

NTSTATUS LgHandleStatus(PIRP Irp, PIO_STACK_LOCATION Stk)
{
    if (Stk->Parameters.DeviceIoControl.OutputBufferLength < sizeof(LG_STATUS_REPLY))
        return STATUS_BUFFER_TOO_SMALL;

    PLG_STATUS_REPLY reply = (PLG_STATUS_REPLY)Irp->AssociatedIrp.SystemBuffer;
    reply->Version = 1;
    reply->Permissive = LgIsPermissive();
    reply->PermissiveExpiresSystemTime = gPermissiveExpires;
    reply->TamperEventCount = LgTamperEventCount();
    reply->LastHeartbeatSystemTime = LgLastHeartbeatSystemTime();

    Irp->IoStatus.Information = sizeof(LG_STATUS_REPLY);
    return STATUS_SUCCESS;
}

// -------- Dispatch routines --------------------------------------------------

NTSTATUS LgDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS LgDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    switch (stk->Parameters.DeviceIoControl.IoControlCode) {
    case LG_IOCTL_GET_NONCE:  status = LgHandleGetNonce(Irp, stk);  break;
    case LG_IOCTL_UNLOCK:     status = LgHandleUnlock(Irp, stk);    break;
    case LG_IOCTL_HEARTBEAT:  status = LgHandleHeartbeat(Irp, stk); break;
    case LG_IOCTL_STATUS:     status = LgHandleStatus(Irp, stk);    break;
    default:                  status = STATUS_INVALID_DEVICE_REQUEST; break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// -------- DriverEntry --------------------------------------------------------

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING devName;
    BOOLEAN devCreated = FALSE, symCreated = FALSE;
    BOOLEAN wfpUp = FALSE, regUp = FALSE, procUp = FALSE, miniUp = FALSE, obUp = FALSE;

    KeInitializeSpinLock(&gNonceLock);
    KeInitializeSpinLock(&gPermissiveLock);

    // INTENTIONALLY no DriverObject->DriverUnload assigned. Once loaded,
    // the driver cannot be unloaded by SCM — only by reboot.

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = LgDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = LgDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LgDispatchDeviceControl;

    RtlInitUnicodeString(&devName, LG_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);
    if (!NT_SUCCESS(status)) goto fail;
    devCreated = TRUE;

    RtlInitUnicodeString(&gSymlinkName, LG_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&gSymlinkName, &devName);
    if (!NT_SUCCESS(status)) goto fail;
    symCreated = TRUE;

    // Load recovery verifier; failure here means the install never wrote it,
    // which is a serious misconfiguration. Continue anyway so a partially
    // installed driver still blocks network and self-protects; recovery just
    // won't work until the verifier is present on next boot.
    NTSTATUS rvs = LgRecoveryLoadVerifier();
    if (!NT_SUCCESS(rvs)) {
        DbgPrint("[lockguard] WARN: verifier not loaded (0x%x) — recovery disabled\n",
                 rvs);
    }

    status = LgWfpInitialize();
    if (!NT_SUCCESS(status)) goto fail;
    wfpUp = TRUE;

    status = LgRegCbInitialize();
    if (!NT_SUCCESS(status)) goto fail;
    regUp = TRUE;

    status = LgProcNotifyInitialize();
    if (!NT_SUCCESS(status)) goto fail;
    procUp = TRUE;

    status = LgMiniFilterInitialize(DriverObject);
    if (!NT_SUCCESS(status)) goto fail;
    miniUp = TRUE;

    status = LgObCallbacksInitialize();
    if (!NT_SUCCESS(status)) goto fail;
    obUp = TRUE;

    DbgPrint("[lockguard] DriverEntry succeeded\n");
    return STATUS_SUCCESS;

fail:
    DbgPrint("[lockguard] DriverEntry failed: 0x%x\n", status);
    if (obUp)   LgObCallbacksFinalize();
    if (miniUp) LgMiniFilterFinalize();
    if (procUp) LgProcNotifyFinalize();
    if (regUp)  LgRegCbFinalize();
    if (wfpUp)  LgWfpFinalize();
    if (symCreated) IoDeleteSymbolicLink(&gSymlinkName);
    if (devCreated) IoDeleteDevice(gDeviceObject);
    return status;
}
