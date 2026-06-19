/*
 * procnotify.c — process-creation notify routine.
 *
 * Blocks launches of named blacklisted images (regedit.exe, taskmgr.exe,
 * procexp*.exe, etc.) by setting CreationStatus = STATUS_ACCESS_DENIED in
 * the PS_CREATE_NOTIFY_INFO. This is belt to the WDAC user-mode whitelist.
 */

#include "lockguard.h"

static BOOLEAN gProcNotifyRegistered = FALSE;

// Lower-case basenames. Wildcards handled with explicit prefix match.
static const PCWSTR gBlocked[] = {
    L"regedit.exe",
    L"taskmgr.exe",
    L"bcdedit.exe",
    L"procmon.exe",
    L"procmon64.exe",
    L"procexp.exe",
    L"procexp64.exe",
    L"pchunter.exe",
    L"pchunter64.exe",
    L"dbgview.exe",
    L"kdbgctrl.exe",
    L"windbg.exe",
    L"x64dbg.exe",
    L"ollydbg.exe",
    L"autoruns.exe",
    L"autorunsc.exe",
    L"powershell_ise.exe",
    L"cmd.exe",     // covered by WDAC, but belt
    L"mmc.exe",     // blocks services.msc / devmgmt.msc / gpedit.msc snap-in host
    L"wmic.exe",
    L"tasklist.exe",
    L"runas.exe",
    L"sdbinst.exe",
    L"mavinject.exe",
    L"installutil.exe",
    L"regsvr32.exe",
    L"schtasks.exe",
    L"dnscmd.exe",
};

static PCWSTR LgBasename(PCUNICODE_STRING path)
{
    if (!path || !path->Buffer || path->Length == 0) return NULL;

    USHORT i = path->Length / sizeof(WCHAR);
    while (i > 0) {
        if (path->Buffer[i - 1] == L'\\' || path->Buffer[i - 1] == L'/') break;
        --i;
    }
    return &path->Buffer[i];
}

static BOOLEAN LgIsBlocked(PCWSTR basename, USHORT lenChars)
{
    if (!basename) return FALSE;

    for (ULONG i = 0; i < RTL_NUMBER_OF(gBlocked); ++i) {
        SIZE_T blen = wcslen(gBlocked[i]);
        if ((SIZE_T)lenChars != blen) continue;
        if (_wcsnicmp(basename, gBlocked[i], blen) == 0) return TRUE;
    }
    return FALSE;
}

static VOID LgProcessNotifyEx(_Inout_ PEPROCESS Process,
                              _In_ HANDLE ProcessId,
                              _Inout_opt_ PPS_CREATE_NOTIFY_INFO Info)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (Info == NULL) return;  // process exit
    if (Info->ImageFileName == NULL) return;

    if (LgIsPermissive()) return;

    PCWSTR base = LgBasename(Info->ImageFileName);
    if (!base) return;

    USHORT baseChars = (USHORT)(Info->ImageFileName->Length / sizeof(WCHAR)
                                - (base - Info->ImageFileName->Buffer));

    if (LgIsBlocked(base, baseChars)) {
        LgRecordTamperEvent(base);
        Info->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

NTSTATUS LgProcNotifyInitialize(VOID)
{
    NTSTATUS s = PsSetCreateProcessNotifyRoutineEx(LgProcessNotifyEx, FALSE);
    if (NT_SUCCESS(s)) gProcNotifyRegistered = TRUE;
    return s;
}

VOID LgProcNotifyFinalize(VOID)
{
    if (gProcNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(LgProcessNotifyEx, TRUE);
        gProcNotifyRegistered = FALSE;
    }
}
