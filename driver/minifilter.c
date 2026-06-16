/*
 * minifilter.c — FltMgr minifilter denying delete/rename/write on the
 * lockguard files. Path-based, so admin/SYSTEM/TrustedInstaller all bounce.
 *
 * Protected paths (full-path case-insensitive prefix match):
 *   \Device\HarddiskVolumeN\ProgramData\Lockguard\*
 *   \Device\HarddiskVolumeN\Windows\System32\drivers\lockguard.sys
 *   \Device\HarddiskVolumeN\Windows\Lockguard-Restore\*
 *   \Device\HarddiskVolumeN\EFI\Microsoft\Boot\BCD
 *
 * Permissive window bypasses the deny so the recovery + uninstall scripts
 * can edit files.
 */

#include "lockguard.h"

static PFLT_FILTER gFilter = NULL;

static const PCWSTR gProtectedSuffixes[] = {
    L"\\ProgramData\\Lockguard\\",
    L"\\Windows\\System32\\drivers\\lockguard.sys",
    L"\\Windows\\Lockguard-Restore\\",
    L"\\EFI\\Microsoft\\Boot\\BCD",
};

static BOOLEAN LgPathMatches(PCFLT_RELATED_OBJECTS Flt, PFLT_CALLBACK_DATA Data)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS s = FltGetFileNameInformation(Data,
                                            FLT_FILE_NAME_NORMALIZED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                            &nameInfo);
    if (!NT_SUCCESS(s) || nameInfo == NULL) return FALSE;

    FltParseFileNameInformation(nameInfo);

    BOOLEAN hit = FALSE;
    for (ULONG i = 0; i < RTL_NUMBER_OF(gProtectedSuffixes); ++i) {
        UNICODE_STRING needle;
        RtlInitUnicodeString(&needle, gProtectedSuffixes[i]);

        // Case-insensitive substring match: walk the name and look for needle.
        // Names like \Device\HarddiskVolume3\ProgramData\Lockguard\...
        // contain the needle starting at offset of "\ProgramData\Lockguard\".
        if (nameInfo->Name.Length < needle.Length) continue;

        USHORT lastStart = (USHORT)((nameInfo->Name.Length - needle.Length) / sizeof(WCHAR));
        for (USHORT off = 0; off <= lastStart; ++off) {
            UNICODE_STRING window;
            window.Buffer = &nameInfo->Name.Buffer[off];
            window.Length = needle.Length;
            window.MaximumLength = needle.Length;
            if (RtlEqualUnicodeString(&window, &needle, TRUE)) {
                hit = TRUE; break;
            }
        }
        if (hit) break;
    }

    FltReleaseFileNameInformation(nameInfo);
    UNREFERENCED_PARAMETER(Flt);
    return hit;
}

static FLT_PREOP_CALLBACK_STATUS LgPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS Flt,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    ULONG opts = Data->Iopb->Parameters.Create.Options;
    BOOLEAN wantsDelete = (opts & FILE_DELETE_ON_CLOSE) != 0;
    BOOLEAN wantsWrite  = (Data->Iopb->Parameters.Create.SecurityContext &&
                          (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
                           (DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER))) != 0;

    if (!wantsDelete && !wantsWrite) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!LgPathMatches(Flt, Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (LgIsPermissive()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    LgRecordTamperEvent(L"file create write/delete");
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS LgPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS Flt,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    FILE_INFORMATION_CLASS klass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    BOOLEAN dangerous = (klass == FileDispositionInformation) ||
                        (klass == FileDispositionInformationEx) ||
                        (klass == FileRenameInformation) ||
                        (klass == FileRenameInformationEx) ||
                        (klass == FileEndOfFileInformation) ||
                        (klass == FileAllocationInformation);
    if (!dangerous) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!LgPathMatches(Flt, Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (LgIsPermissive()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    LgRecordTamperEvent(L"file set-info");
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS LgPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS Flt,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!LgPathMatches(Flt, Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (LgIsPermissive()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    LgRecordTamperEvent(L"file write");
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE,          0, LgPreCreate,         NULL },
    { IRP_MJ_SET_INFORMATION, 0, LgPreSetInformation, NULL },
    { IRP_MJ_WRITE,           0, LgPreWrite,          NULL },
    { IRP_MJ_OPERATION_END }
};

static NTSTATUS LgUnloadGuard(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    // Refuse to unload outside the permissive window.
    if (!LgIsPermissive()) {
        LgRecordTamperEvent(L"minifilter unload attempt");
        return STATUS_FLT_DO_NOT_DETACH;
    }
    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,           // ContextRegistration
    gCallbacks,
    LgUnloadGuard,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS LgMiniFilterInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS s = FltRegisterFilter(DriverObject, &gRegistration, &gFilter);
    if (!NT_SUCCESS(s)) return s;
    s = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(s)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return s;
}

VOID LgMiniFilterFinalize(VOID)
{
    if (gFilter) { FltUnregisterFilter(gFilter); gFilter = NULL; }
}
