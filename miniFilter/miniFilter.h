#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>




typedef struct {
	/* The filter that results from a call to FltRegisterFilter. */
	PFLT_FILTER filter;
} DRIVER_DATA;

static DRIVER_DATA driver_data;




NTSTATUS InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	return (VolumeDeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM) ?
		STATUS_SUCCESS :
		STATUS_FLT_DO_NOT_ATTACH;
}


NTSTATUS InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	return STATUS_SUCCESS;
}


BOOLEAN get_file_name_information(PFLT_CALLBACK_DATA data,
	PFLT_FILE_NAME_INFORMATION* name_info)
{
	/* Get name information. */
	if (NT_SUCCESS(FltGetFileNameInformation(
		data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		name_info
	))) {
		/* Parse file name information. */
		if (NT_SUCCESS(FltParseFileNameInformation(*name_info))) {
			return TRUE;
		}

		FltReleaseFileNameInformation(*name_info);
	}

	return FALSE;
}


FLT_PREOP_CALLBACK_STATUS process_irp(PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext,
	BOOLEAN bit)
{
	PFLT_FILE_NAME_INFORMATION name_info;
	PFLT_DEFERRED_IO_WORKITEM work;

	/* Get name information. */
	if (get_file_name_information(Data, &name_info)) {
		if (bit == TRUE)
			DbgPrint("##newDriver [ miniFilter ] [ Writed ] Filename: '%wZ'.", &name_info->Name);
		else if (bit == FALSE)
			DbgPrint("##newDriver [ miniFilter ] [ Deleted ] Filename: '%wZ'.", &name_info->Name);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
	//DbgPrint("##newDriver [ miniFilter ] PreOperationCallback Called \n");

	if (FLT_IS_IRP_OPERATION(Data)) {
		/* Open file? */
		if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
			/* Open file for writing/appending? */
			if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
				(FILE_WRITE_DATA | FILE_APPEND_DATA)) {
				return process_irp(Data, FltObjects, CompletionContext, TRUE);
			}
		}
		else if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation) {
				if (((FILE_DISPOSITION_INFORMATION*)
					Data->Iopb->Parameters.SetFileInformation.InfoBuffer
					)->DeleteFile) {
					return process_irp(Data, FltObjects, CompletionContext, FALSE);
				}
			}
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	FltUnregisterFilter(driver_data.filter);
	DbgPrint("##newDriver [ miniFilter ] Stop Filtering \n");

	return STATUS_SUCCESS;
}




CONST FLT_OPERATION_REGISTRATION callbacks[] = {
	{ IRP_MJ_CREATE,          0, PreOperationCallback, NULL },
	{ IRP_MJ_SET_INFORMATION, 0, PreOperationCallback, NULL },
	{ IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION filter_registration = {
	sizeof(FLT_REGISTRATION),             /* Size. */
	FLT_REGISTRATION_VERSION,             /* Version. */
	0,                                    /* Flags. */
	NULL,                                 /* ContextRegistration. */
	callbacks,                            /* OperationRegistration. */
	FilterUnload,                         /* FilterUnloadCallback. */
	InstanceSetup,                        /* InstanceSetupCallback. */
	InstanceQueryTeardown,                /* InstanceQueryTeardownCallback. */
	NULL,                                 /* InstanceTeardownStartCallback. */
	NULL,                                 /* InstanceTeardownCompleteCallback. */
	NULL,                                 /* GenerateFileNameCallback. */
	NULL,                                 /* NormalizeNameComponentCallback. */
	NULL                                  /* NormalizeContextCleanupCallback. */

#if FLT_MGR_LONGHORN
	, NULL                                /* TransactionNotificationCallback. */
	, NULL                                /* NormalizeNameComponentExCallback. */
#endif /* FLT_MGR_LONGHORN */
#if FLT_MFG_WIN8
	, NULL                                /* SectionNotificationCallback. */
#endif
};
