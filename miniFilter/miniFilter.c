#include "miniFilter.h"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {

NTSTATUS status;
	UNREFERENCED_PARAMETER(RegistryPath);

status = FltRegisterFilter(DriverObject,
		&filter_registration,
		&driver_data.filter);

	if (NT_SUCCESS(status)) {
		status = FltStartFiltering(driver_data.filter);

		if (!NT_SUCCESS(status)) {
			FltUnregisterFilter(driver_data.filter);
		}
		DbgPrint("##newDriver [ miniFilter ] Start Filtering \n");
	}

	return status;
  
}
