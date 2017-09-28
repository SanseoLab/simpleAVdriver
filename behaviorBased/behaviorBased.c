#include "structs.h"
#include "utils.h"


extern UCHAR *PsGetProcessImageFileName(IN PEPROCESS Process);;


LPSTR GetProcessNameFromPid(HANDLE pid) {

	PEPROCESS Process;

	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER) {
		return "[ SelfProtect ] [ ERROR ]  PID required.";
	}

	return (LPSTR)PsGetProcessImageFileName(Process);

}


VOID OnImageLoadCallback(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO ImageInfo)
{
	LPSTR processName;
	processName = GetProcessNameFromPid(InProcessId);

	if (!_stricmp(processName, "notepad.exe")) {
		DbgPrint("[ kernelAPC ] It's notepad.exe \n");
		if (InProcessId != 0 && InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"ntdll.dll"))
		{
			DbgPrint("[ kernelAPC ] It's ntdll.dll \n");
		}
	}
	else {
		return;
	}


	// check If ntdll is loading
	if (InProcessId != 0 && InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"ntdll.dll"))
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS pProcess = NULL;
		status = PsLookupProcessByProcessId(InProcessId, &pProcess);
		BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;


		// check if 64 bit ntdll is loading in 32 bit process
		if (isWow64 && wcsstr(InFullImageName->Buffer, L"System32"))
			return;

		// check if target process is protected
		if (PsIsProtectedProcess(pProcess))
			return;

		if (NT_SUCCESS(status))
		{
			KAPC_STATE apc;
			UNICODE_STRING ustrPath;
			PVOID pNtdll = NULL;
			PVOID LdrLoadDllLocal = NULL;

			KeStackAttachProcess(pProcess, &apc);

			// Get Ntdll address
			pNtdll = ImageInfo->ImageBase;

			// Get LdrLoadDll addresss
			LdrLoadDllLocal = SWIDGetModuleExport(pNtdll, "LdrLoadDll", pProcess, NULL);

			if (!LdrLoadDllLocal)
			{
				DPRINT("System Wide Injection Driver: %s: Failed to get LdrLoadDll address.\n", __FUNCTION__);
				status = STATUS_NOT_FOUND;
				KeUnstackDetachProcess(&apc);
				return;
			}

			// Call LdrLoadDll
			if (NT_SUCCESS(status))
			{
				PINJECT_BUFFER pUserBuf;
				if (isWow64)
				{
					RtlInitUnicodeString(&ustrPath, L"InjectionMitigationDLLx86.dll");
					pUserBuf = SWIDGetWow64Code(LdrLoadDllLocal, &ustrPath);
				}
				else
				{
					RtlInitUnicodeString(&ustrPath, L"InjectionMitigationDLLx64.dll");
					pUserBuf = SWIDGetNativeCode(LdrLoadDllLocal, &ustrPath);
				}

				status = SWIDApcInject(pUserBuf, (HANDLE)InProcessId);
				DPRINT("After SWIDApcInject() \n", __FUNCTION__);
			}

			KeUnstackDetachProcess(&apc);
		}
		else
		{
			DPRINT("System Wide Injection Driver: %s: PsLookupProcessByProcessId failed with status 0x%X.\n", __FUNCTION__, status);

			if (pProcess)
				ObDereferenceObject(pProcess);

			return;
		}

		if (pProcess)
			ObDereferenceObject(pProcess);
	}
}


NTSTATUS DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	PsRemoveLoadImageNotifyRoutine(OnImageLoadCallback);
	DPRINT("System Wide Injection Driver: %s: UnloadDriver.\n", __FUNCTION__);
}




NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	
	NTSTATUS status;
	UNREFERENCED_PARAMETER(RegistryPath);
	
	DriverObject->DriverUnload = UnloadDriver;
  
  	PsSetLoadImageNotifyRoutine(OnImageLoadCallback);
  
}
