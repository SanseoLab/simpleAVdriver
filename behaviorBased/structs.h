#pragma once
#include <ntifs.h>

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;

	union
	{
		LIST_ENTRY HashLinks;

		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};

	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};

	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _INJECT_INFO
{
	ULONG ProcessId;
	wchar_t DllName[1024];
} INJECT_INFO, *PINJECT_INFO;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;


typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	union
	{
		UNICODE_STRING path;
		UNICODE_STRING32 path32;
	};

	wchar_t buffer[488];
	PVOID module;
	ULONG complete;
} INJECT_BUFFER, *PINJECT_BUFFER;

// Image name resolve flags
typedef enum _ResolveFlags
{
	KApiShemaOnly = 1,
	KSkipSxS = 2,
	KFullPath = 4,
} ResolveFlags;

typedef struct tagACTCTXW
{
	ULONG  cbSize;
	ULONG  dwFlags;
	PWCH   lpSource;
	USHORT wProcessorArchitecture;
	USHORT wLangId;
	PWCH   lpAssemblyDirectory;
	PWCH   lpResourceName;
	PWCH   lpApplicationName;
	PVOID  hModule;
} ACTCTXW, *PACTCTXW;

typedef struct tagACTCTXW32
{
	ULONG  cbSize;
	ULONG  dwFlags;
	ULONG  lpSource;
	USHORT wProcessorArchitecture;
	USHORT wLangId;
	ULONG  lpAssemblyDirectory;
	ULONG  lpResourceName;
	ULONG  lpApplicationName;
	ULONG  hModule;
} ACTCTXW32, *PACTCTXW32;

/// <summary>
/// User-mode memory region
/// </summary>
typedef struct _USER_CONTEXT
{
	UCHAR code[0x1000];             // Code buffer
	union
	{
		UNICODE_STRING ustr;
		UNICODE_STRING32 ustr32;
	};
	wchar_t buffer[0x400];          // Buffer for unicode string


									// Activation context data
	union
	{
		ACTCTXW actx;
		ACTCTXW32 actx32;
	};
	HANDLE hCTX;
	ULONG hCookie;

	PVOID ptr;                      // Tmp data
	union
	{
		NTSTATUS status;            // Last execution status
		PVOID retVal;               // Function return value
		ULONG retVal32;             // Function return value
	};

	//UCHAR tlsBuf[0x100];
} USER_CONTEXT, *PUSER_CONTEXT;

/// <summary>
/// Manual map context
/// </summary>
typedef struct _MMAP_CONTEXT
{
	PEPROCESS pProcess;     // Target process
	PVOID pWorkerBuf;       // Worker thread code buffer
	HANDLE hWorker;         // Worker thread handle
	PETHREAD pWorker;       // Worker thread object
	LIST_ENTRY modules;     // Manual module list
	PUSER_CONTEXT userMem;  // Tmp buffer in user space
	HANDLE hSync;           // APC sync handle
	PKEVENT pSync;          // APC sync object
	PVOID pSetEvent;        // ZwSetEvent address
	PVOID pLoadImage;       // LdrLoadDll address
	BOOLEAN tlsInitialized; // Static TLS was initialized
} MMAP_CONTEXT, *PMMAP_CONTEXT;



typedef struct _API_SET_VALUE_ENTRY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

typedef struct _API_SET_VALUE_ARRAY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG Unk;
	ULONG NameLength;
	ULONG DataOffset;
	ULONG Count;
} API_SET_VALUE_ARRAY, *PAPI_SET_VALUE_ARRAY;

typedef struct _API_SET_NAMESPACE_ENTRY
{
	ULONG Limit;
	ULONG Size;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_NAMESPACE_ARRAY
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG Start;
	ULONG End;
	ULONG Unk[2];
} API_SET_NAMESPACE_ARRAY, *PAPI_SET_NAMESPACE_ARRAY;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation, // obsolete ... delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation, // system process information
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation, // system module
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;


typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;


typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
