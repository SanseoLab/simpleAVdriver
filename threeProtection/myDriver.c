#include "myDriver.h"
#include "SelfProtect.h"
#include "RegMonitor.h"
#include "PsProtect.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;

	DbgPrint("[ myDriver ] Driver Loaded\n");

  // installing Self Protection
	InstallSelfProtect();

  // installing Register Monitor
	InstallRegMonitor(DriverObject);

  // installing Process Protection
	InstallProcessProtect();

	return Status;
}


VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UnInstallSelfProtect();

	UnInstallRegMonitor();

	UnInstallProcessProtect();

	DbgPrint("[ myDriver ] Unloaded\n");
}
