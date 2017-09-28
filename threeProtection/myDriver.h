#include <ntifs.h>


NTSTATUS	DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID					DriverUnload(IN PDRIVER_OBJECT DriverObject);


#pragma alloc_text(INIT, DriverEntry)
