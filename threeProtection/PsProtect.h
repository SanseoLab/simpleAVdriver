VOID ProcessNotifyCallbackEx(
	PEPROCESS  Process,
	HANDLE  ProcessId,
	PPS_CREATE_NOTIFY_INFO  CreateInfo)
{

	UNICODE_STRING ExecutableBlocked[] = {
		RTL_CONSTANT_STRING(L"*OLLYDBG*.EXE"),
		RTL_CONSTANT_STRING(L"*MSPAINT*.EXE"),
		RTL_CONSTANT_STRING(L"*NOTEPAD*.EXE")
	};
	ULONG ExecutableCount = sizeof(ExecutableBlocked) / sizeof(UNICODE_STRING);

	BOOLEAN Matched = FALSE;
	ULONG Idx;

	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo) {

		for (Idx = 0; Idx < ExecutableCount; Idx++) {
			if (FsRtlIsNameInExpression(&ExecutableBlocked[Idx], (PUNICODE_STRING)CreateInfo->ImageFileName, TRUE, NULL)) {
				Matched = TRUE;
				break;
			}
		}

		if (Matched) {
			DbgPrint("[ PsProtect ] Preventing Process (%wZ) Execution\n", CreateInfo->ImageFileName);
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}
		else {
			DbgPrint("[ PsProtect ] Starting Process: %wZ\n", CreateInfo->ImageFileName);
		}
	}

	return;
}


NTSTATUS InstallProcessProtect() {
	NTSTATUS Status = STATUS_SUCCESS;

	if (!NT_SUCCESS(Status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE)))
	{
		DbgPrint("[ PsProtect ] [ ERROR ] PsSetCreateProcessNotifyRoutineEx Resistering Failed : (%x)\n", Status);
		return Status;
	} else {
    		DbgPrint("[ PsProtect ] [ SUCCESS ] PsSetCreateProcessNotifyRoutineEx Resistering Success\n");
   }

	return STATUS_SUCCESS;

}

VOID UnInstallProcessProtect() {
	
	if (!NT_SUCCESS(Status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE))) {
		DbgPrint("[ PsProtect ] [ ERROR ] PsSetCreateProcessNotifyRoutineEx Unresistering Failed : (%x)\n", Status);
	} else {
    		DbgPrint("[ PsProtect ] [ SUCCESS ] PsSetCreateProcessNotifyRoutineEx Unresistering Success\n");
	}
	
}
