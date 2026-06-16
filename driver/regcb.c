/*
 * regcb.c — registry callback (CmRegisterCallbackEx).
 *
 * Denies writes/deletes on:
 *   HKLM\SYSTEM\CurrentControlSet\Services\Lockguard*
 *   HKLM\SYSTEM\CurrentControlSet\Services\Wlansvc\*  (WLAN filter list)
 *   HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-...}\*  (NIC props)
 *   \Registry\Machine\BCD00000000\*
 *   HKLM\SYSTEM\Lockguard\Recovery\*
 *
 * Reads are always allowed. Permissive window: when LgIsPermissive() is TRUE,
 * the callback returns STATUS_SUCCESS for writes too (so recovery + uninstall
 * can edit these keys).
 */

#include "lockguard.h"

static LARGE_INTEGER gRegCookie;
static BOOLEAN       gRegRegistered = FALSE;

// Each protected prefix matches by case-insensitive starts-with.
static const PCWSTR gProtectedPrefixes[] = {
    LG_SERVICE_KEY,
    LG_SERVICE_KEY_SVC,
    LG_BCD_KEY,
    LG_WLANSVC_KEY,
    LG_RECOVERY_KEY,
    LG_NETCLASS_KEY,
};

static BOOLEAN LgKeyNameMatchesAny(PCUNICODE_STRING name)
{
    if (name == NULL || name->Buffer == NULL) return FALSE;

    for (ULONG i = 0; i < RTL_NUMBER_OF(gProtectedPrefixes); ++i) {
        UNICODE_STRING pfx;
        RtlInitUnicodeString(&pfx, gProtectedPrefixes[i]);

        if (name->Length < pfx.Length) continue;

        UNICODE_STRING head;
        head.Buffer = name->Buffer;
        head.Length = pfx.Length;
        head.MaximumLength = pfx.Length;

        if (RtlEqualUnicodeString(&head, &pfx, TRUE)) return TRUE;
    }
    return FALSE;
}

static NTSTATUS LgResolveKeyName(PVOID Object, PUNICODE_STRING Out)
{
    if (Object == NULL) return STATUS_INVALID_PARAMETER;

    ULONG sizeNeeded = 0;
    NTSTATUS s = CmCallbackGetKeyObjectIDEx(&gRegCookie, Object, NULL, NULL, 0);
    UNREFERENCED_PARAMETER(s);  // probe doesn't return size that way

    // Use the documented helper — it allocates the name buffer.
    PUNICODE_STRING name = NULL;
    s = CmCallbackGetKeyObjectIDEx(&gRegCookie, Object, NULL,
                                    (PCUNICODE_STRING*)&name, 0);
    if (!NT_SUCCESS(s) || name == NULL) return s;

    Out->Buffer = name->Buffer;
    Out->Length = name->Length;
    Out->MaximumLength = name->MaximumLength;
    return STATUS_SUCCESS;
}

static VOID LgFreeKeyName(PUNICODE_STRING Name)
{
    if (Name && Name->Buffer) {
        CmCallbackReleaseKeyObjectIDEx((PCUNICODE_STRING)Name);
    }
}

NTSTATUS LgRegistryCallback(_In_ PVOID CallbackContext,
                            _In_opt_ PVOID Argument1,
                            _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if (Argument1 == NULL) return STATUS_SUCCESS;

    REG_NOTIFY_CLASS klass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PVOID obj = NULL;
    PCWSTR reason = L"reg-block";

    switch (klass) {
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        obj = info ? info->Object : NULL;
        reason = L"reg set value";
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        obj = info ? info->Object : NULL;
        reason = L"reg delete value";
        break;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        obj = info ? info->Object : NULL;
        reason = L"reg delete key";
        break;
    }
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        obj = info ? info->Object : NULL;
        reason = L"reg rename key";
        break;
    }
    case RegNtPreCreateKeyEx: {
        // For creates, we don't have an existing object — the parent name
        // is in info->CompleteName. Most attacks come via SetValue, so we
        // let creates through. (A child key under a protected parent would
        // be denied at the SetValue level anyway.)
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_SUCCESS;
    }

    if (obj == NULL) return STATUS_SUCCESS;

    UNICODE_STRING fullName = { 0 };
    NTSTATUS s = LgResolveKeyName(obj, &fullName);
    if (!NT_SUCCESS(s)) return STATUS_SUCCESS;

    BOOLEAN deny = LgKeyNameMatchesAny(&fullName);
    LgFreeKeyName(&fullName);

    if (!deny) return STATUS_SUCCESS;

    if (LgIsPermissive()) return STATUS_SUCCESS;

    LgRecordTamperEvent(reason);
    return STATUS_ACCESS_DENIED;
}

NTSTATUS LgRegCbInitialize(VOID)
{
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"360100");  // arbitrary unique altitude

    NTSTATUS s = CmRegisterCallbackEx(LgRegistryCallback, &altitude, NULL,
                                       NULL, &gRegCookie, NULL);
    if (NT_SUCCESS(s)) gRegRegistered = TRUE;
    return s;
}

VOID LgRegCbFinalize(VOID)
{
    if (gRegRegistered) {
        CmUnRegisterCallback(gRegCookie);
        gRegRegistered = FALSE;
    }
}
