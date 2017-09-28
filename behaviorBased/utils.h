#pragma once
#include <ntimage.h>
#include <ntstrsafe.h>

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, format, __VA_ARGS__)
#define CALL_COMPLETE   0xC0371E7E
#define POOL_TAG 'Inj'

typedef VOID(NTAPI * PKNORMAL_ROUTINE) (
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE * NormalRoutine,
	PVOID * NormalContext,
	PVOID * SystemArgument1,
	PVOID * SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI * PKKERNEL_ROUTINE);

typedef VOID(NTAPI * PKRUNDOWN_ROUTINE) (
	PRKAPC Apc
	);


void NTAPI KernelRoutine(PKAPC apc, PKNORMAL_ROUTINE * NormalRoutine, PVOID * NormalContext, \
	PVOID * SystemArgument1, PVOID * SystemArgument2);

void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
LPSTR PsGetProcessImageFileName(PEPROCESS Process);


NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();

NTSTRSAFEWORKERDDI
RtlStringLengthWorkerW(
	_In_reads_or_z_(cchMax) STRSAFE_PCNZWCH psz,
	_In_ _In_range_(<= , NTSTRSAFE_MAX_CCH) size_t cchMax,
	_Out_opt_ _Deref_out_range_(<, cchMax) _Deref_out_range_(<= , _String_length_(psz)) size_t* pcchLength);

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(IN PEPROCESS Process);

NTSYSAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	IN  PULONG ReturnLength
);


NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(IN PEPROCESS Process);

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(IN PEPROCESS Process);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);


/// <summary>
/// Get module base address by name
/// </summary>
/// <param name="pProcess">Target process</param>
/// <param name="ModuleName">Nodule name to search for</param>
/// <param name="isWow64">If TRUE - search in 32-bit PEB</param>
/// <returns>Found address, NULL if not found</returns>
PVOID SWIDGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64);

/// <summary>
/// Allocate new Unicode string from Paged pool
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="size">Buffer size in bytes to alloacate</param>
/// <returns>Status code</returns>
NTSTATUS SWIDSafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size);


/// <summary>
/// Search for substring
/// </summary>
/// <param name="source">Source string</param>
/// <param name="target">Target string</param>
/// <param name="CaseInSensitive">Case insensitive search</param>
/// <returns>Found position or -1 if not found</returns>
LONG SWIDSafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive);


/// <summary>
/// Allocate and copy string
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="source">Source string</param>
/// <returns>Status code</returns>
NTSTATUS SWIDSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source);


/// <summary>
/// Get file name from full path
/// </summary>
/// <param name="path">Path.</param>
/// <param name="name">Resulting name</param>
/// <returns>Status code</returns>
NTSTATUS SWIDStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name);


/// <summary>
/// Try to resolve image via API SET map
/// </summary>
/// <param name="pProcess">Target process. Must be run in the context of this process</param>
/// <param name="name">Name to resolve</param>
/// <param name="baseImage">Parent image name</param>
/// <param name="resolved">Resolved name if any</param>
/// <returns>Status code</returns>
NTSTATUS SWIDResolveApiSet(
	IN PEPROCESS pProcess,
	IN PUNICODE_STRING name,
	IN PUNICODE_STRING baseImage,
	OUT PUNICODE_STRING resolved
);

/// <summary>
/// Get exported function address
/// </summary>
/// <param name="pBase">Module base</param>
/// <param name="name_ord">Function name or ordinal</param>
/// <param name="pProcess">Target process for user module</param>
/// <param name="baseName">Dll name for api schema</param>
/// <returns>Found address, NULL if not found</returns>
PVOID SWIDGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName);


ULONG GenPrologue32(IN PUCHAR pBuf);
ULONG GenPrologue64(IN PUCHAR pBuf);
ULONG GenPrologueT(IN BOOLEAN wow64, IN PUCHAR pBuf);

ULONG GenCall32V(IN PUCHAR pBuf, IN PVOID pFn, IN INT argc, IN va_list vl);
ULONG GenCall64V(IN PUCHAR pBuf, IN PVOID pFn, IN INT argc, IN va_list vl);
ULONG GenCallTV(IN BOOLEAN wow64, IN PUCHAR pBuf, IN PVOID pFn, IN INT argc, IN va_list vl);

ULONG GenEpilogue32(IN PUCHAR pBuf, IN INT retSize);
ULONG GenEpilogue64(IN PUCHAR pBuf, IN INT retSize);
ULONG GenEpilogueT(IN BOOLEAN wow64, IN PUCHAR pBuf, IN INT retSize);

ULONG GenSync32(IN PUCHAR pBuf, IN PNTSTATUS pStatus, IN PVOID pSetEvent, IN HANDLE hEvent);
ULONG GenSync64(IN PUCHAR pBuf, IN PNTSTATUS pStatus, IN PVOID pSetEvent, IN HANDLE hEvent);
ULONG GenSyncT(IN BOOLEAN wow64, IN PUCHAR pBuf, IN PNTSTATUS pStatus, IN PVOID pSetEvent, IN HANDLE hEvent);

VOID KernelApcInjectCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);

//
// Injection APC routines
//
VOID KernelApcPrepareCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);

/// <summary>
/// Queue user-mode APC to the target thread
/// </summary>
/// <param name="pThread">Target thread</param>
/// <param name="pUserFunc">APC function</param>
/// <param name="Arg1">Argument 1</param>
/// <param name="Arg2">Argument 2</param>
/// <param name="Arg3">Argument 3</param>
/// <param name="bForce">If TRUE - force delivery by issuing special kernel APC</param>
/// <returns>Status code</returns>
NTSTATUS SWIDQueueUserApc(
	IN PETHREAD pThread,
	IN PVOID pUserFunc,
	IN PVOID Arg1,
	IN PVOID Arg2,
	IN PVOID Arg3,
	IN BOOLEAN bForce);

/// <summary>
/// Call arbitrary function
/// </summary>
/// <param name="newThread">Perform call in a separate thread</param>
/// <param name="pContext">Loader context</param>
/// <param name="pRoutine">Routine to call.</param>
/// <param name="argc">Number of arguments.</param>
/// <param name="...">Arguments</param>
/// <returns>Status code</returns>
NTSTATUS SWIDCallRoutine(IN PMMAP_CONTEXT pContext, IN PVOID pRoutine, IN INT argc, ...);

/// <summary>
/// Get directory path name from full path
/// </summary>
/// <param name="path">Path</param>
/// <param name="name">Resulting directory path</param>
/// <returns>Status code</returns>
NTSTATUS SWIDStripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir);

/// <summary>
/// Check if file exists
/// </summary>
/// <param name="path">Fully qualifid path to a file</param>
/// <returns>Status code</returns>
NTSTATUS SWIDFileExists(IN PUNICODE_STRING path);

/// <summary>
///Try to resolve image via SxS isolation
/// </summary>
/// <param name="pContext">Loader context.</param>
/// <param name="name">Name to resolve</param>
/// <param name="resolved">Resolved name if any</param>
/// <returns>Status code</returns>
NTSTATUS SWIDResolveSxS(
	IN PMMAP_CONTEXT pContext,
	IN PUNICODE_STRING name,
	OUT PUNICODE_STRING resolved
);


/// <summary>
/// Resolve image name to fully qualified path
/// </summary>
/// <param name="pContext">Loader context</param>
/// <param name="pProcess">Target process. Must be running in the context of this process</param>
/// <param name="flags">Flags</param>
/// <param name="path">Image name to resolve</param>
/// <param name="baseImage">Base image name for API SET translation</param>
/// <param name="resolved">Resolved image path</param>
/// <returns>Status code</returns>
NTSTATUS SWIDResolveImagePath(
	IN PMMAP_CONTEXT pContext,
	IN PEPROCESS pProcess,
	IN ResolveFlags flags,
	IN PUNICODE_STRING path,
	IN PUNICODE_STRING baseImage,
	OUT PUNICODE_STRING resolved
);

/// <summary>
/// Build injection code for wow64 process
/// Must be running in target process context
/// </summary>
/// <param name="LdrLoadDll">LdrLoadDll address</param>
/// <param name="pPath">Path to the dll</param>
/// <returns>Code pointer. When not needed, it should be freed with ZwFreeVirtualMemory</returns>
PINJECT_BUFFER SWIDGetWow64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath);

/// <summary>
/// Build injection code for native x64 process
/// Must be running in target process context
/// </summary>
/// <param name="LdrLoadDll">LdrLoadDll address</param>
/// <param name="pPath">Path to the dll</param>
/// <returns>Code pointer. When not needed it should be freed with ZwFreeVirtualMemory</returns>
PINJECT_BUFFER SWIDGetNativeCode(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath);

/// <summary>
/// Find first thread of the target process
/// </summary>
/// <param name="pid">Target PID.</param>
/// <param name="ppThread">Found thread. Thread object reference count is increased by 1</param>
/// <returns>Status code</returns>
NTSTATUS SWIDLookupProcessThread(IN HANDLE pid, OUT PETHREAD* ppThread);

/// <summary>
/// Inject dll using APC
/// Must be running in target process context
/// </summary>
/// <param name="pUserBuf">Injcetion code</param>
/// <param name="pid">Target process ID</param>
/// <returns>Status code</returns>
NTSTATUS SWIDApcInject(IN PINJECT_BUFFER pUserBuf, IN HANDLE pid);
