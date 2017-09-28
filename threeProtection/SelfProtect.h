#define PROCESS_TERMINATE      (0x0001)
#define PROCESS_VM_READ        (0x0010)
#define PROCESS_VM_WRITE       (0x0020)
#define PROCESS_VM_OPERATION   (0x0008) 


OB_PREOP_CALLBACK_STATUS	ObjectPreCallBack(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);
VOID				ObjectPostCallBack(IN  PVOID RegistrationContext, IN  POB_POST_OPERATION_INFORMATION OperationInformation);
LPSTR				GetProcessNameFromPid(HANDLE pid);
NTSTATUS			InstallProcessProtect();
VOID				UnInstallProcessProtect();

extern UCHAR *PsGetProcessImageFileName(IN PEPROCESS Process);

PVOID	RegistrationHandle = NULL;
HANDLE	ProtectedProcess = NULL;

PACCESS_MASK thisis = NULL;
ACCESS_MASK thisis2 = 0;


OB_PREOP_CALLBACK_STATUS
ObjectPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {

	LPSTR ProcssName;

	PACCESS_MASK DesiredAccess = NULL;
	ACCESS_MASK OriginalDesiredAccess = 0;

	HANDLE ProcessIdOfTargetThread;

	if (OperationInformation->ObjectType == *PsProcessType) {
		if (OperationInformation->Object == PsGetCurrentProcess()) {
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,"ObCallbackTest: CBTdPreOperationCallback: ignore process open/duplicate from the protected process itself\n");
			return OB_PREOP_SUCCESS;
		}
	} else if (OperationInformation->ObjectType == *PsThreadType) {
		ProcessIdOfTargetThread = PsGetThreadProcessId((PETHREAD)OperationInformation->Object);
		if (ProcessIdOfTargetThread == PsGetCurrentProcessId()) {
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,"ObCallbackTest: CBTdPreOperationCallback: ignore thread open/duplicate from the protected process itself\n");
			return OB_PREOP_SUCCESS;
		}
	} else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"ObCallbackTest: CBTdPreOperationCallback: unexpected object type\n");
		return OB_PREOP_SUCCESS;
	}

	ProcssName = GetProcessNameFromPid(PsGetProcessId((PEPROCESS)OperationInformation->Object));

	if (OperationInformation->KernelHandle == 1) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[ SelfProtect ] [ KERNEL ] ObjectPreCallback ----> Process Name [%s] \n", ProcssName);
		return OB_PREOP_SUCCESS;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[ SelfProtect ] [ USER ] ObjectPreCallback ----> Process Name [%s] \n", ProcssName);

	if (!_stricmp(ProcssName, "calc.exe")) {
		DbgPrint("[ SelfProtect ] It's notepad \n");
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {

			DesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
			OriginalDesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

			if ((OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE) {
				*DesiredAccess &= ~PROCESS_TERMINATE;
				DbgPrint("[ SelfProtect ] [ CreateHandleInformation ] Disabling terminate \n");
			}
			
			if ((OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION) {
				*DesiredAccess &= ~PROCESS_VM_OPERATION;
				DbgPrint("[ SelfProtect ] [ CreateHandleInformation ] Disabling vm operation \n");
			}
			if ((OriginalDesiredAccess & ~PROCESS_VM_READ) == PROCESS_VM_READ) {
				*DesiredAccess &= ~PROCESS_VM_READ;
				DbgPrint("[ SelfProtect ] [ CreateHandleInformation ] Disabling vm read \n");
			}
			if ((OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE) {
				*DesiredAccess &= ~PROCESS_VM_WRITE;
				DbgPrint("[ SelfProtect ] [ CreateHandleInformation ] Disabling vm write \n");
			}
			
		} else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {

			DesiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
			OriginalDesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

			if ((OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE) {
				*DesiredAccess &= ~PROCESS_TERMINATE;
				DbgPrint("[ SelfProtect ] [ DuplicateHandleInformation ] Disabling terminate \n");
			}
			if ((OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION) {
				*DesiredAccess &= ~PROCESS_VM_OPERATION;
				DbgPrint("[ SelfProtect ] [ DuplicateHandleInformation ] Disabling vm operation \n");
			}
			if ((OriginalDesiredAccess & ~PROCESS_VM_READ) == PROCESS_VM_READ) {
				*DesiredAccess &= ~PROCESS_VM_READ;
				DbgPrint("[ SelfProtect ] [ DuplicateHandleInformation ] Disabling vm read \n");
			}
			if ((OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE) {
				*DesiredAccess &= ~PROCESS_VM_WRITE;
				DbgPrint("[ SelfProtect ] [ DuplicateHandleInformation ] Disabling vm write \n");
			}
			
		}
	}
	
	return OB_PREOP_SUCCESS;
}

VOID ObjectPostCallBack(IN  PVOID RegistrationContext, IN  POB_POST_OPERATION_INFORMATION OperationInformation) {
}


LPSTR GetProcessNameFromPid(HANDLE pid) {

	PEPROCESS Process;
	
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER) {
		return "[ SelfProtect ] [ ERROR ]  PID required.";
	}

	return (LPSTR)PsGetProcessImageFileName(Process);

}


NTSTATUS InstallSelfProtect() {

	NTSTATUS	Status;
	OB_CALLBACK_REGISTRATION	CallBackRegistration;
	OB_OPERATION_REGISTRATION	OperationRegistration;

	OperationRegistration.ObjectType = PsProcessType;
	OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE;		// For creating handle.
	OperationRegistration.PreOperation = ObjectPreCallBack;			// Registering Callback function.
	OperationRegistration.PostOperation = ObjectPostCallBack;

	RtlInitUnicodeString(&CallBackRegistration.Altitude, L"370000");
	CallBackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	CallBackRegistration.OperationRegistrationCount = 1;
	CallBackRegistration.RegistrationContext = NULL;
	CallBackRegistration.OperationRegistration = &OperationRegistration;

	// [[ ObRegisterCallbacks() ]]
	if (!NT_SUCCESS(Status = ObRegisterCallbacks(&CallBackRegistration, &RegistrationHandle))) {
		DbgPrint("[ SelfProtect ] [ ERROR ] ObRegisterCallbacks Failed : (%x)\n", Status);
		return Status;
	} else {
		DbgPrint("[ SelfProtect ] [ SUCCESS ] ObRegisterCallbacks Success\n");
	}

	return STATUS_SUCCESS;

}

VOID UnInstallSelfProtect() {

	if (RegistrationHandle) {
		ObUnRegisterCallbacks(RegistrationHandle);
	}

}
