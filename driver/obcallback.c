/*
 * obcallback.c — Process object callbacks (ObRegisterCallbacks).
 *
 * Strips PROCESS_TERMINATE / PROCESS_VM_WRITE / PROCESS_SUSPEND_RESUME from
 * any handle to lockguard-svc.exe or services.exe. Without these rights,
 * Stop-Process / TerminateProcess / DebugActiveProcess all fail.
 *
 * Identification is by image-file basename (resolved via
 * PsQueryFullProcessImageName-equivalent) — a malicious admin can't rename
 * the binary on disk because the minifilter blocks it.
 */

#include "lockguard.h"

static PVOID gObRegHandle = NULL;

#define PROC_DENIED_MASK (PROCESS_TERMINATE | PROCESS_VM_WRITE | \
                          PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | \
                          PROCESS_CREATE_THREAD)

static BOOLEAN LgPidIsProtected(HANDLE Pid)
{
    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &proc))) return FALSE;

    BOOLEAN protectedProc = FALSE;
    PUNICODE_STRING imgName = NULL;
    if (NT_SUCCESS(SeLocateProcessImageName(proc, &imgName)) && imgName) {
        // Walk to basename.
        USHORT i = imgName->Length / sizeof(WCHAR);
        while (i > 0 && imgName->Buffer[i - 1] != L'\\') --i;
        PCWSTR base = &imgName->Buffer[i];
        USHORT baseLen = (USHORT)(imgName->Length / sizeof(WCHAR) - i);

        static const PCWSTR names[] = {
            L"lockguard-svc.exe",
            L"services.exe",
        };
        for (ULONG k = 0; k < RTL_NUMBER_OF(names); ++k) {
            SIZE_T nlen = wcslen(names[k]);
            if ((SIZE_T)baseLen == nlen && _wcsnicmp(base, names[k], nlen) == 0) {
                protectedProc = TRUE; break;
            }
        }
        ExFreePool(imgName);
    }
    ObDereferenceObject(proc);
    return protectedProc;
}

static OB_PREOP_CALLBACK_STATUS LgPreProcessHandle(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;
    if (LgIsPermissive()) return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId((PEPROCESS)Info->Object);
    if (!LgPidIsProtected(targetPid)) return OB_PREOP_SUCCESS;

    ACCESS_MASK denied = 0;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        denied = Info->Parameters->CreateHandleInformation.DesiredAccess & PROC_DENIED_MASK;
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROC_DENIED_MASK;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        denied = Info->Parameters->DuplicateHandleInformation.DesiredAccess & PROC_DENIED_MASK;
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROC_DENIED_MASK;
    }
    if (denied) LgRecordTamperEvent(L"process handle strip");

    return OB_PREOP_SUCCESS;
}

NTSTATUS LgObCallbacksInitialize(VOID)
{
    OB_OPERATION_REGISTRATION ops[1] = { 0 };
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = LgPreProcessHandle;

    OB_CALLBACK_REGISTRATION reg = { 0 };
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = ops;
    RtlInitUnicodeString(&reg.Altitude, L"360101");

    return ObRegisterCallbacks(&reg, &gObRegHandle);
}

VOID LgObCallbacksFinalize(VOID)
{
    if (gObRegHandle) { ObUnRegisterCallbacks(gObRegHandle); gObRegHandle = NULL; }
}
