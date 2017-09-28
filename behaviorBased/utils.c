#include "structs.h"
#include "utils.h"

void NTAPI KernelRoutine(PKAPC apc, PKNORMAL_ROUTINE * NormalRoutine, PVOID * NormalContext, \
	PVOID * SystemArgument1, PVOID * SystemArgument2)
{
	ExFreePool(apc);
}

/// <summary>
/// Get module base address by name
/// </summary>
/// <param name="pProcess">Target process</param>
/// <param name="ModuleName">Nodule name to search for</param>
/// <param name="isWow64">If TRUE - search in 32-bit PEB</param>
/// <returns>Found address, NULL if not found</returns>
PVOID SWIDGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
{
	ASSERT(pProcess != NULL);
	if (pProcess == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		LARGE_INTEGER time = { 0 };
		time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

												// Wow64 process
		if (isWow64)
		{
			PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
			if (pPeb32 == NULL)
			{
				DPRINT("System Wide Injection Driver: %s: No PEB32 present. Aborting.\n", __FUNCTION__);
				return NULL;
			}

			// Wait for loader a bit
			for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
			{
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb32->Ldr)
			{
				DPRINT("System Wide Injection Driver: %s: Loader32 was not intialiezd in time. Aborting.\n", __FUNCTION__);
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
				pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
				pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
			{
				UNICODE_STRING ustr;
				PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

				if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
					return (PVOID)pEntry->DllBase;
			}
		}
		// Native process
		else
		{
			PPEB pPeb = PsGetProcessPeb(pProcess);

			if (!pPeb)
			{
				DPRINT("System Wide Injection Driver: %s: No PEB64 present. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Wait for loader a bit
			for (INT i = 0; !pPeb->Ldr && i < 10; i++)
			{
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb->Ldr)
			{
				DPRINT("System Wide Injection Driver: %s: Loader64 was not intialiezd in time. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
				pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
				pListEntry = pListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
					return pEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("System Wide Injection Driver: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	return NULL;
}

/// <summary>
/// Allocate new Unicode string from Paged pool
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="size">Buffer size in bytes to alloacate</param>
/// <returns>Status code</returns>
NTSTATUS SWIDSafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size)
{
	ASSERT(result != NULL);
	if (result == NULL || size == 0)
		return STATUS_INVALID_PARAMETER;

	result->Buffer = ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
	result->Length = 0;
	result->MaximumLength = size;

	if (result->Buffer)
		RtlZeroMemory(result->Buffer, size);
	else
		return STATUS_NO_MEMORY;

	return STATUS_SUCCESS;
}


/// <summary>
/// Search for substring
/// </summary>
/// <param name="source">Source string</param>
/// <param name="target">Target string</param>
/// <param name="CaseInSensitive">Case insensitive search</param>
/// <returns>Found position or -1 if not found</returns>
LONG SWIDSafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive)
{
	ASSERT(source != NULL && target != NULL);
	if (source == NULL || target == NULL || source->Buffer == NULL || target->Buffer == NULL)
		return STATUS_INVALID_PARAMETER;

	// Size mismatch
	if (source->Length < target->Length)
		return -1;

	USHORT diff = source->Length - target->Length;
	for (USHORT i = 0; i < diff; i++)
	{
		if (RtlCompareUnicodeStrings(
			source->Buffer + i / sizeof(WCHAR),
			target->Length / sizeof(WCHAR),
			target->Buffer,
			target->Length / sizeof(WCHAR),
			CaseInSensitive
		) == 0)
		{
			return i;
		}
	}

	return -1;
}


/// <summary>
/// Allocate and copy string
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="source">Source string</param>
/// <returns>Status code</returns>
NTSTATUS SWIDSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source)
{
	ASSERT(result != NULL && source != NULL);
	if (result == NULL || source == NULL || source->Buffer == NULL)
		return STATUS_INVALID_PARAMETER;

	// No data to copy
	if (source->Length == 0)
	{
		result->Length = result->MaximumLength = 0;
		result->Buffer = NULL;
		return STATUS_SUCCESS;
	}

	result->Buffer = ExAllocatePoolWithTag(NonPagedPool, source->MaximumLength, POOL_TAG);
	result->Length = source->Length;
	result->MaximumLength = source->MaximumLength;

	//memcpy(result->Buffer, source->Buffer, source->Length);
	RtlCopyMemory(result->Buffer, source->Buffer, source->Length);
	return STATUS_SUCCESS;
}


/// <summary>
/// Get file name from full path
/// </summary>
/// <param name="path">Path.</param>
/// <param name="name">Resulting name</param>
/// <returns>Status code</returns>
NTSTATUS SWIDStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name)
{
	ASSERT(path != NULL && name);
	if (path == NULL || name == NULL)
		return STATUS_INVALID_PARAMETER;

	// Empty string
	if (path->Length < 2)
	{
		*name = *path;
		return STATUS_NOT_FOUND;
	}

	for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
	{
		if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
		{
			name->Buffer = &path->Buffer[i + 1];
			name->Length = name->MaximumLength = path->Length - (i + 1) * sizeof(WCHAR);
			return STATUS_SUCCESS;
		}
	}

	*name = *path;
	return STATUS_NOT_FOUND;
}


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
)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
	PPEB pPeb = PsGetProcessPeb(pProcess);
	PAPI_SET_NAMESPACE_ARRAY pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY)(pPeb32 != NULL ? (PVOID)pPeb32->ApiSetMap : pPeb->ApiSetMap);

	// Invalid name
	if (name == NULL || name->Length < 4 * sizeof(WCHAR) || name->Buffer == NULL ||
		(memcmp(name->Buffer, L"api-", 4) != 0 && memcmp(name->Buffer, L"ext-", 4) != 0))
		return STATUS_NOT_FOUND;

	// Iterate api set map
	for (ULONG i = 0; i < pApiSetMap->Count; i++)
	{
		PAPI_SET_NAMESPACE_ENTRY pDescriptor = NULL;
		PAPI_SET_VALUE_ARRAY pHostArray = NULL;
		wchar_t apiNameBuf[255] = { 0 };
		UNICODE_STRING apiName = { 0 };


		pDescriptor = (PAPI_SET_NAMESPACE_ENTRY)((PUCHAR)pApiSetMap + pApiSetMap->End + i * sizeof(API_SET_NAMESPACE_ENTRY));
		pHostArray = (PAPI_SET_VALUE_ARRAY)((PUCHAR)pApiSetMap + pApiSetMap->Start + sizeof(API_SET_VALUE_ARRAY) * pDescriptor->Size);

		memcpy(apiNameBuf, (PUCHAR)pApiSetMap + pHostArray->NameOffset, pHostArray->NameLength);

		RtlUnicodeStringInit(&apiName, apiNameBuf);

		// Check if this is a target api
		if (SWIDSafeSearchString(name, &apiName, TRUE) >= 0)
		{
			PAPI_SET_VALUE_ENTRY pHost = NULL;
			wchar_t apiHostNameBuf[255] = { 0 };
			UNICODE_STRING apiHostName = { 0 };

			pHost = (PAPI_SET_VALUE_ENTRY)((PUCHAR)pApiSetMap + pHostArray->DataOffset);

			// Sanity check
			if (pHostArray->Count < 1)
				return STATUS_NOT_FOUND;

			memcpy(apiHostNameBuf, (PUCHAR)pApiSetMap + pHost->ValueOffset, pHost->ValueLength);
			RtlUnicodeStringInit(&apiHostName, apiHostNameBuf);

			// No base name redirection
			if (pHostArray->Count == 1 || baseImage == NULL || baseImage->Buffer[0] == 0)
			{
				SWIDSafeInitString(resolved, &apiHostName);
				return STATUS_SUCCESS;
			}
			// Redirect accordingly to base name
			else
			{
				UNICODE_STRING baseImageName = { 0 };
				SWIDStripPath(baseImage, &baseImageName);

				if (RtlCompareUnicodeString(&apiHostName, &baseImageName, TRUE) == 0)
				{
					memset(apiHostNameBuf, 0, sizeof(apiHostNameBuf));
					memcpy(apiHostNameBuf, (PUCHAR)pApiSetMap + pHost[1].ValueOffset, pHost[1].ValueLength);
					RtlCreateUnicodeString(resolved, apiHostNameBuf);
					return STATUS_SUCCESS;
				}
				else
				{
					SWIDSafeInitString(resolved, &apiHostName);
					return STATUS_SUCCESS;
				}
			}
		}
	}

	return status;
}

/// <summary>
/// Get exported function address
/// </summary>
/// <param name="pBase">Module base</param>
/// <param name="name_ord">Function name or ordinal</param>
/// <param name="pProcess">Target process for user module</param>
/// <param name="baseName">Dll name for api schema</param>
/// <returns>Found address, NULL if not found</returns>
PVOID SWIDGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;

	ASSERT(pBase != NULL);
	if (pBase == NULL)
		return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DPRINT("System Wide Injection Driver: %s: != IMAGE_DOS_SIGNATURE.\n", __FUNCTION__);
		return NULL;
	}

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
	{
		DPRINT("System Wide Injection Driver: %s: != IMAGE_NT_SIGNATURE.\n", __FUNCTION__);
		return NULL;
	}

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 bit image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		// Find by index
		if ((ULONG_PTR)name_ord <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else
		{
			DPRINT("System Wide Injection Driver: %s: != Weird params.\n", __FUNCTION__);
			return NULL;
		}

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

			// Check forwarded export
			if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
			{
				WCHAR strbuf[256] = { 0 };
				ANSI_STRING forwarder = { 0 };
				ANSI_STRING import = { 0 };

				UNICODE_STRING uForwarder = { 0 };
				ULONG delimIdx = 0;
				PVOID forwardBase = NULL;
				PVOID result = NULL;

				// System image, not supported
				if (pProcess == NULL)
				{
					DPRINT("System Wide Injection Driver: %s: System image, not supported.\n", __FUNCTION__);
					return NULL;
				}

				RtlInitAnsiString(&forwarder, (PCSZ)pAddress);
				RtlInitEmptyUnicodeString(&uForwarder, strbuf, sizeof(strbuf));

				RtlAnsiStringToUnicodeString(&uForwarder, &forwarder, FALSE);
				for (ULONG j = 0; j < uForwarder.Length / sizeof(WCHAR); j++)
				{
					if (uForwarder.Buffer[j] == L'.')
					{
						uForwarder.Length = (USHORT)(j * sizeof(WCHAR));
						uForwarder.Buffer[j] = L'\0';
						delimIdx = j;
						break;
					}
				}

				// Get forward function name/ordinal
				RtlInitAnsiString(&import, forwarder.Buffer + delimIdx + 1);
				RtlAppendUnicodeToString(&uForwarder, L".dll");

				//
				// Check forwarded module
				//
				UNICODE_STRING resolved = { 0 };
				UNICODE_STRING resolvedName = { 0 };
				SWIDResolveImagePath(NULL, pProcess, KApiShemaOnly, &uForwarder, baseName, &resolved);
				SWIDStripPath(&resolved, &resolvedName);

				forwardBase = SWIDGetUserModule(pProcess, &resolvedName, PsGetProcessWow64Process(pProcess) != NULL);
				result = SWIDGetModuleExport(forwardBase, import.Buffer, pProcess, &resolvedName);
				RtlFreeUnicodeString(&resolved);

				return result;
			}

			break;
		}
	}

	return (PVOID)pAddress;
}


ULONG GenPrologue32(IN PUCHAR pBuf)
{
	*pBuf = 0x55;
	*(PUSHORT)(pBuf + 1) = 0xE589;

	return 3;
}

ULONG GenPrologue64(IN PUCHAR pBuf)
{
	*(PULONG)(pBuf + 0) = 0x244C8948;       // mov [rsp + 0x08], rcx
	*(PUCHAR)(pBuf + 4) = 0x8;              // 
	*(PULONG)(pBuf + 5) = 0x24548948;       // mov [rsp + 0x10], rdx
	*(PUCHAR)(pBuf + 9) = 0x10;             // 
	*(PULONG)(pBuf + 10) = 0x2444894C;      // mov [rsp + 0x18], r8
	*(PUCHAR)(pBuf + 14) = 0x18;            // 
	*(PULONG)(pBuf + 15) = 0x244C894C;      // mov [rsp + 0x20], r9
	*(PUCHAR)(pBuf + 19) = 0x20;            // 
	return 20;
}

ULONG GenPrologueT(IN BOOLEAN wow64, IN PUCHAR pBuf)
{
	return wow64 ? GenPrologue32(pBuf) : GenPrologue64(pBuf);
}

ULONG GenCall32V(IN PUCHAR pBuf, IN PVOID pFn, IN INT argc, IN va_list vl)
{
	ULONG ofst = 0;

	PULONG pArgBuf = ExAllocatePoolWithTag(NonPagedPool, argc * sizeof(ULONG), POOL_TAG);

	// cast args
	for (INT i = 0; i < argc; i++)
	{
		PVOID arg = va_arg(vl, PVOID);
		pArgBuf[i] = (ULONG)(ULONG_PTR)arg;
	}

	// push args
	for (INT i = argc - 1; i >= 0; i--)
	{
		*(PUSHORT)(pBuf + ofst) = 0x68;                 // push arg
		*(PULONG)(pBuf + ofst + 1) = pArgBuf[i];        //
		ofst += 5;
	}

	*(PUCHAR)(pBuf + ofst) = 0xB8;                      // mov eax, pFn
	*(PULONG)(pBuf + ofst + 1) = (ULONG)(ULONG_PTR)pFn; //
	ofst += 5;

	*(PUSHORT)(pBuf + ofst) = 0xD0FF;                   // call eax
	ofst += 2;

	ExFreePoolWithTag(pArgBuf, 0);

	return ofst;
}
ULONG GenCall64V(IN PUCHAR pBuf, IN PVOID pFn, IN INT argc, IN va_list vl)
{
	USHORT rsp_diff = 0x28;
	ULONG ofst = 0;
	if (argc > 4)
	{
		rsp_diff = (USHORT)(argc * sizeof(ULONG_PTR));
		if (rsp_diff % 0x10)
			rsp_diff = ((rsp_diff / 0x10) + 1) * 0x10;
		rsp_diff += 8;
	}

	// sub rsp, rsp_diff
	*(PULONG)(pBuf + ofst) = (0x00EC8348 | rsp_diff << 24);
	ofst += 4;

	if (argc > 0)
	{
		PVOID arg = va_arg(vl, PVOID);
		*(PUSHORT)(pBuf + ofst) = 0xB948;           // mov rcx, arg
		*(PVOID*)(pBuf + ofst + 2) = arg;           //
		ofst += 10;
	}
	if (argc > 1)
	{
		PVOID arg = va_arg(vl, PVOID);
		*(PUSHORT)(pBuf + ofst) = 0xBA48;           // mov rdx, arg
		*(PVOID*)(pBuf + ofst + 2) = arg;           //
		ofst += 10;
	}
	if (argc > 2)
	{
		PVOID arg = va_arg(vl, PVOID);
		*(PUSHORT)(pBuf + ofst) = 0xB849;           // mov r8, arg
		*(PVOID*)(pBuf + ofst + 2) = arg;           //
		ofst += 10;
	}
	if (argc > 3)
	{
		PVOID arg = va_arg(vl, PVOID);
		*(PUSHORT)(pBuf + ofst) = 0xB949;           // mov r9, arg
		*(PVOID*)(pBuf + ofst + 2) = arg;           //
		ofst += 10;
	}

	for (INT i = 4; i < argc; i++)
	{
		PVOID arg = va_arg(vl, PVOID);

		*(PUSHORT)(pBuf + ofst) = 0xB848;           // mov rcx, arg
		*(PVOID*)(pBuf + ofst + 2) = arg;           //
		ofst += 10;

		// mov [rsp + i*8], rax
		*(PULONG)(pBuf + ofst) = 0x24448948;
		*(PUCHAR)(pBuf + ofst + 4) = (UCHAR)(0x20 + (i - 4) * sizeof(arg));
		ofst += 5;
	}


	*(PUSHORT)(pBuf + ofst) = 0xB848;               // mov rax, pFn
	*(PVOID*)(pBuf + ofst + 2) = pFn;               //
	ofst += 10;

	*(PUSHORT)(pBuf + ofst) = 0xD0FF;               // call rax
	ofst += 2;

	// add rsp, rsp_diff
	*(PULONG)(pBuf + ofst) = (0x00C48348 | rsp_diff << 24);
	ofst += 4;

	return ofst;
}

ULONG GenCallTV(IN BOOLEAN wow64, IN PUCHAR pBuf, IN PVOID pFn, IN INT argc, IN va_list vl)
{
	return wow64 ? GenCall32V(pBuf, pFn, argc, vl) : GenCall64V(pBuf, pFn, argc, vl);
}


ULONG GenEpilogue32(IN PUCHAR pBuf, IN INT retSize)
{
	*(PUSHORT)pBuf = 0xEC89;
	*(pBuf + 2) = 0x5D;
	*(pBuf + 3) = 0xC2;
	*(PUSHORT)(pBuf + 4) = (USHORT)retSize;

	return 6;
}

ULONG GenEpilogue64(IN PUCHAR pBuf, IN INT retSize)
{
	UNREFERENCED_PARAMETER(retSize);

	*(PULONG)(pBuf + 0) = 0x244C8B48;       // mov rcx, [rsp + 0x08]
	*(PUCHAR)(pBuf + 4) = 0x8;              // 
	*(PULONG)(pBuf + 5) = 0x24548B48;       // mov rdx, [rsp + 0x10]
	*(PUCHAR)(pBuf + 9) = 0x10;             // 
	*(PULONG)(pBuf + 10) = 0x24448B4C;      // mov r8, [rsp + 0x18]
	*(PUCHAR)(pBuf + 14) = 0x18;            // 
	*(PULONG)(pBuf + 15) = 0x244C8B4C;      // mov r9, [rsp + 0x20]
	*(PUCHAR)(pBuf + 19) = 0x20;            // 
	*(PUCHAR)(pBuf + 20) = 0xC3;            // ret
	return 21;
}
ULONG GenEpilogueT(IN BOOLEAN wow64, IN PUCHAR pBuf, IN INT retSize)
{
	return wow64 ? GenEpilogue32(pBuf, retSize) : GenEpilogue64(pBuf, retSize);
}

ULONG GenSync32(IN PUCHAR pBuf, IN PNTSTATUS pStatus, IN PVOID pSetEvent, IN HANDLE hEvent)
{
	ULONG ofst = 0;

	*(PUCHAR)(pBuf + ofst) = 0xA3;                  // mov [pStatus], eax
	*(PVOID*)(pBuf + ofst + 1) = pStatus;           //
	ofst += 5;

	*(PUSHORT)(pBuf + ofst) = 0x006A;               // push FALSE
	ofst += 2;

	*(PUCHAR)(pBuf + ofst) = 0x68;                  // push hEvent
	*(PULONG)(pBuf + ofst + 1) = (ULONG)(ULONG_PTR)hEvent;  //
	ofst += 5;

	*(PUCHAR)(pBuf + ofst) = 0xB8;                  // mov eax, pSetEvent
	*(PULONG)(pBuf + ofst + 1) = (ULONG)(ULONG_PTR)pSetEvent;//
	ofst += 5;

	*(PUSHORT)(pBuf + ofst) = 0xD0FF;               // call eax
	ofst += 2;

	return ofst;
}
ULONG GenSync64(IN PUCHAR pBuf, IN PNTSTATUS pStatus, IN PVOID pSetEvent, IN HANDLE hEvent)
{
	ULONG ofst = 0;

	*(PUSHORT)(pBuf + ofst) = 0xA348;           // mov [pStatus], rax
	*(PVOID*)(pBuf + ofst + 2) = pStatus;       //
	ofst += 10;

	*(PUSHORT)(pBuf + ofst) = 0xB948;           // mov rcx, hEvent
	*(PHANDLE)(pBuf + ofst + 2) = hEvent;       //
	ofst += 10;

	*(pBuf + ofst) = 0x48;                      // xor rdx, rdx
	*(PUSHORT)(pBuf + ofst + 1) = 0xD231;       //
	ofst += 3;

	*(PUSHORT)(pBuf + ofst) = 0xB848;           // mov rax, pSetEvent
	*(PVOID*)(pBuf + ofst + 2) = pSetEvent;     //
	ofst += 10;

	*(PUSHORT)(pBuf + ofst) = 0xD0FF;           // call rax
	ofst += 2;

	return ofst;
}


ULONG GenSyncT(IN BOOLEAN wow64, IN PUCHAR pBuf, IN PNTSTATUS pStatus, IN PVOID pSetEvent, IN HANDLE hEvent)
{
	return wow64 ? GenSync32(pBuf, pStatus, pSetEvent, hEvent) : GenSync64(pBuf, pStatus, pSetEvent, hEvent);
}

VOID KernelApcInjectCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// Skip execution
	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL;

	// Fix Wow64 APC
	if (PsGetCurrentProcessWow64Process() != NULL)
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);

	ExFreePoolWithTag(Apc, 0);
}

//
// Injection APC routines
//
VOID KernelApcPrepareCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// Alert current thread
	KeTestAlertThread(UserMode);
	ExFreePoolWithTag(Apc, 0);
}
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
	IN BOOLEAN bForce)
{
	ASSERT(pThread != NULL);
	if (pThread == NULL)
		return STATUS_INVALID_PARAMETER;

	// Allocate APC
	PKAPC pPrepareApc = NULL;
	PKAPC pInjectApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), POOL_TAG);

	if (pInjectApc == NULL)
	{
		DPRINT("System Wide Injection Driver: %s: Failed to allocate APC.\n", __FUNCTION__);
		return STATUS_NO_MEMORY;
	}

	// Actual APC
	KeInitializeApc(
		pInjectApc, (PKTHREAD)pThread,
		OriginalApcEnvironment, &KernelApcInjectCallback,
		NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)pUserFunc, UserMode, Arg1
	);

	// Setup force-delivery APC
	if (bForce)
	{
		pPrepareApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), POOL_TAG);
		KeInitializeApc(
			pPrepareApc, (PKTHREAD)pThread,
			OriginalApcEnvironment, &KernelApcPrepareCallback,
			NULL, NULL, KernelMode, NULL
		);
	}

	// Insert APC
	if (KeInsertQueueApc(pInjectApc, Arg2, Arg3, 0))
	{
		if (bForce && pPrepareApc) {
			KeInsertQueueApc(pPrepareApc, NULL, NULL, 0);
		}
		DPRINT("In 1 SWIDQueueUserApc() \n", __FUNCTION__);

		return STATUS_SUCCESS;
	}
	else
	{
		DPRINT("System Wide Injection Driver: %s: Failed to insert APC.\n", __FUNCTION__);

		ExFreePoolWithTag(pInjectApc, 0);

		if (pPrepareApc)
			ExFreePoolWithTag(pPrepareApc, 0);

		return STATUS_NOT_CAPABLE;
	}
}

/// <summary>
/// Call arbitrary function
/// </summary>
/// <param name="newThread">Perform call in a separate thread</param>
/// <param name="pContext">Loader context</param>
/// <param name="pRoutine">Routine to call.</param>
/// <param name="argc">Number of arguments.</param>
/// <param name="...">Arguments</param>
/// <returns>Status code</returns>
NTSTATUS SWIDCallRoutine(IN PMMAP_CONTEXT pContext, IN PVOID pRoutine, IN INT argc, ...)
{
	NTSTATUS status = STATUS_SUCCESS;
	va_list vl;
	BOOLEAN wow64 = PsGetProcessWow64Process(pContext->pProcess) != NULL;

	va_start(vl, argc);
	ULONG ofst = GenPrologueT(wow64, pContext->userMem->code);
	ofst += GenCallTV(wow64, pContext->userMem->code + ofst, pRoutine, argc, vl);
	ofst += GenSyncT(wow64, pContext->userMem->code + ofst, &pContext->userMem->status, pContext->pSetEvent, pContext->hSync);
	ofst += GenEpilogueT(wow64, pContext->userMem->code + ofst, argc * sizeof(ULONG));

	KeResetEvent(pContext->pSync);
	status = SWIDQueueUserApc(pContext->pWorker, pContext->userMem->code, NULL, NULL, NULL, FALSE);
	if (NT_SUCCESS(status))
	{
		LARGE_INTEGER timeout = { 0 };
		timeout.QuadPart = -(10ll * 10 * 1000 * 1000);  // 10s

		status = KeWaitForSingleObject(pContext->pSync, Executive, UserMode, TRUE, &timeout);

		timeout.QuadPart = -(1ll * 10 * 1000);          // 1ms
		KeDelayExecutionThread(KernelMode, TRUE, &timeout);
	}

	va_end(vl);

	return status;
}

/// <summary>
/// Get directory path name from full path
/// </summary>
/// <param name="path">Path</param>
/// <param name="name">Resulting directory path</param>
/// <returns>Status code</returns>
NTSTATUS SWIDStripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir)
{
	ASSERT(path != NULL && dir);
	if (path == NULL || dir == NULL)
		return STATUS_INVALID_PARAMETER;

	// Empty string
	if (path->Length < 2)
	{
		*dir = *path;
		return STATUS_NOT_FOUND;
	}

	for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
	{
		if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
		{
			dir->Buffer = path->Buffer;
			dir->Length = dir->MaximumLength = i * sizeof(WCHAR);
			return STATUS_SUCCESS;
		}
	}

	*dir = *path;
	return STATUS_NOT_FOUND;
}

/// <summary>
/// Check if file exists
/// </summary>
/// <param name="path">Fully qualifid path to a file</param>
/// <returns>Status code</returns>
NTSTATUS SWIDFileExists(IN PUNICODE_STRING path)
{
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK statusBlock = { 0 };
	OBJECT_ATTRIBUTES obAttr = { 0 };
	InitializeObjectAttributes(&obAttr, path, OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwCreateFile(
		&hFile, FILE_READ_DATA | SYNCHRONIZE, &obAttr,
		&statusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0
	);

	if (NT_SUCCESS(status))
		ZwClose(hFile);

	return status;
}

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
)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	UNICODE_STRING ustrNtdll = { 0 };
	BOOLEAN wow64 = PsGetProcessWow64Process(pContext->pProcess) != NULL;

	typedef struct _STRIBG_BUF
	{
		union
		{
			UNICODE_STRING name1;
			UNICODE_STRING32 name132;
		};
		union
		{
			UNICODE_STRING name2;
			UNICODE_STRING32 name232;
		};
		union
		{
			UNICODE_STRING origName;
			UNICODE_STRING32 origName32;
		};
		union
		{
			PUNICODE_STRING pResolved;
			ULONG pResolved32;
		};
		wchar_t origBuf[0x100];
		wchar_t staticBuf[0x200];
	} STRIBG_BUF, *PSTRIBG_BUF;

	PSTRIBG_BUF pStringBuf = (PSTRIBG_BUF)pContext->userMem->buffer;

	RtlUnicodeStringInit(&ustrNtdll, L"ntdll.dll");

	PVOID hNtdll = SWIDGetUserModule(pContext->pProcess, &ustrNtdll, wow64);
	PVOID pQueryName = SWIDGetModuleExport(hNtdll, "RtlDosApplyFileIsolationRedirection_Ustr", pContext->pProcess, NULL);

	if (pQueryName == NULL)
	{
		DPRINT("System Wide Injection Driver: %s: Failed to get RtlDosApplyFileIsolationRedirection_Ustr.\n", __FUNCTION__);
		return STATUS_NOT_FOUND;
	}

	RtlZeroMemory(pStringBuf->origBuf, sizeof(pStringBuf->origBuf));
	RtlZeroMemory(pStringBuf->staticBuf, sizeof(pStringBuf->staticBuf));

	// Fill params
	memcpy(pStringBuf->origBuf, name->Buffer, name->Length);
	if (wow64)
	{
		pStringBuf->origName32.Buffer = (ULONG)(ULONG_PTR)pStringBuf->origBuf;
		pStringBuf->origName32.MaximumLength = sizeof(pStringBuf->origBuf);
		pStringBuf->origName32.Length = name->Length;

		pStringBuf->name132.Buffer = (ULONG)(ULONG_PTR)pStringBuf->staticBuf;
		pStringBuf->name132.MaximumLength = sizeof(pStringBuf->staticBuf);
		pStringBuf->name132.Length = 0;

		pStringBuf->name232.Buffer = 0;
		pStringBuf->name232.Length = pStringBuf->name232.MaximumLength = 0;
	}
	else
	{
		RtlInitUnicodeString(&pStringBuf->origName, pStringBuf->origBuf);
		RtlInitEmptyUnicodeString(&pStringBuf->name1, pStringBuf->staticBuf, sizeof(pStringBuf->staticBuf));
		RtlInitEmptyUnicodeString(&pStringBuf->name2, NULL, 0);
	}


	// Prevent some unpredictable shit
	__try
	{
		// RtlDosApplyFileIsolationRedirection_Ustr
		status = SWIDCallRoutine(
			pContext, pQueryName, 9,
			(PVOID)TRUE, &pStringBuf->origName, NULL,
			&pStringBuf->name1, &pStringBuf->name2, &pStringBuf->pResolved,
			NULL, NULL, NULL
		);

		if (NT_SUCCESS(status) && NT_SUCCESS(pContext->userMem->status))
		{
			if (wow64)
			{
				ULONG tmp = ((PUNICODE_STRING32)pStringBuf->pResolved32)->Buffer;
				pStringBuf->pResolved = &pStringBuf->name1;
				pStringBuf->pResolved->Buffer = (PWCH)tmp;
			}

			RtlDowncaseUnicodeString(resolved, pStringBuf->pResolved, TRUE);
			// TODO: name2 cleanup
		}

		return NT_SUCCESS(status) ? pContext->userMem->status : status;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("System Wide Injection Driver: %s: Exception. Code: 0x%X.\n", __FUNCTION__, GetExceptionCode());
		return STATUS_UNHANDLED_EXCEPTION;
	}
}


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
)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING pathLow = { 0 };
	UNICODE_STRING filename = { 0 };
	UNICODE_STRING fullResolved = { 0 };

	UNREFERENCED_PARAMETER(baseImage);

	ASSERT(pProcess != NULL && path != NULL && resolved != NULL);
	if (pProcess == NULL || path == NULL || resolved == NULL)
	{
		DPRINT("System Wide Injection Driver: %s: Missing parameter.\n", __FUNCTION__);
		return STATUS_INVALID_PARAMETER;
	}

	RtlDowncaseUnicodeString(&pathLow, path, TRUE);
	SWIDStripPath(&pathLow, &filename);

	// API Schema
	if (NT_SUCCESS(SWIDResolveApiSet(pProcess, &filename, baseImage, resolved)))
	{
		SWIDSafeAllocateString(&fullResolved, 512);

		// Perpend system directory
		if (PsGetProcessWow64Process(pProcess) != NULL)
			RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\SysWow64\\");
		else
			RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\System32\\");

		RtlUnicodeStringCat(&fullResolved, resolved);
		RtlFreeUnicodeString(resolved);
		RtlFreeUnicodeString(&pathLow);

		*resolved = fullResolved;
		return STATUS_SUCCESS;
	}

	// Api schema only
	if (flags & KApiShemaOnly)
		goto skip;

	if (flags & KSkipSxS)
		goto SkipSxS;

	// SxS
	status = SWIDResolveSxS(pContext, &filename, resolved);
	if (pContext && NT_SUCCESS(status))
	{
		SWIDSafeAllocateString(&fullResolved, 1024);
		RtlUnicodeStringCatString(&fullResolved, L"\\??\\");
		RtlUnicodeStringCat(&fullResolved, resolved);

		RtlFreeUnicodeString(resolved);
		RtlFreeUnicodeString(&pathLow);

		*resolved = fullResolved;
		return STATUS_SUCCESS;
	}
	else if (status == STATUS_UNHANDLED_EXCEPTION)
	{
		*resolved = pathLow;
		return status;
	}
	else
		status = STATUS_SUCCESS;

SkipSxS:
	SWIDSafeAllocateString(&fullResolved, 0x400);

	//
	// Executable directory
	//
	ULONG bytes = 0;
	if (NT_SUCCESS(ZwQueryInformationProcess(ZwCurrentProcess(), ProcessImageFileName, fullResolved.Buffer + 0x100, 0x200, &bytes)))
	{
		PUNICODE_STRING pPath = (PUNICODE_STRING)(fullResolved.Buffer + 0x100);
		UNICODE_STRING parentDir = { 0 };
		SWIDStripFilename(pPath, &parentDir);

		RtlCopyUnicodeString(&fullResolved, &parentDir);
		RtlUnicodeStringCatString(&fullResolved, L"\\");
		RtlUnicodeStringCat(&fullResolved, &filename);

		if (NT_SUCCESS(SWIDFileExists(&fullResolved)))
		{
			RtlFreeUnicodeString(resolved);
			RtlFreeUnicodeString(&pathLow);

			*resolved = fullResolved;
			return STATUS_SUCCESS;
		}
	}

	fullResolved.Length = 0;
	RtlZeroMemory(fullResolved.Buffer, 0x400);

	//
	// System directory
	//
	if (PsGetProcessWow64Process(pProcess) != NULL)
		RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\SysWOW64\\");
	else
		RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\System32\\");

	RtlUnicodeStringCat(&fullResolved, &filename);
	if (NT_SUCCESS(SWIDFileExists(&fullResolved)))
	{
		RtlFreeUnicodeString(resolved);
		RtlFreeUnicodeString(&pathLow);

		*resolved = fullResolved;
		return STATUS_SUCCESS;
	}

	RtlFreeUnicodeString(&fullResolved);

	// Nothing found
skip:
	*resolved = pathLow;
	return status;
}

/// <summary>
/// Build injection code for wow64 process
/// Must be running in target process context
/// </summary>
/// <param name="LdrLoadDll">LdrLoadDll address</param>
/// <param name="pPath">Path to the dll</param>
/// <returns>Code pointer. When not needed, it should be freed with ZwFreeVirtualMemory</returns>
PINJECT_BUFFER SWIDGetWow64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	PINJECT_BUFFER pBuffer = NULL;
	SIZE_T size = PAGE_SIZE;

	// Code
	UCHAR code[] =
	{
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
		0xC2, 0x04, 0x00                        // ret 4
	};

	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		// Copy path
		PUNICODE_STRING32 pUserPath = &pBuffer->path32;
		pUserPath->Length = pPath->Length;
		pUserPath->MaximumLength = pPath->MaximumLength;
		pUserPath->Buffer = (ULONG)(ULONG_PTR)pBuffer->buffer;

		// Copy path
		memcpy((PVOID)pUserPath->Buffer, pPath->Buffer, pPath->Length);

		// Copy code
		memcpy(pBuffer, code, sizeof(code));

		// Fill stubs
		*(ULONG*)((PUCHAR)pBuffer + 1) = (ULONG)(ULONG_PTR)&pBuffer->module;
		*(ULONG*)((PUCHAR)pBuffer + 6) = (ULONG)(ULONG_PTR)pUserPath;
		*(ULONG*)((PUCHAR)pBuffer + 15) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)pBuffer + 15) - 5 + 1);
		*(ULONG*)((PUCHAR)pBuffer + 20) = (ULONG)(ULONG_PTR)&pBuffer->complete;

		return pBuffer;
	}

	UNREFERENCED_PARAMETER(pPath);
	return NULL;
}

/// <summary>
/// Build injection code for native x64 process
/// Must be running in target process context
/// </summary>
/// <param name="LdrLoadDll">LdrLoadDll address</param>
/// <param name="pPath">Path to the dll</param>
/// <returns>Code pointer. When not needed it should be freed with ZwFreeVirtualMemory</returns>
PINJECT_BUFFER SWIDGetNativeCode(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	PINJECT_BUFFER pBuffer = NULL;
	SIZE_T size = PAGE_SIZE;

	// Code
	UCHAR code[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
		0xFF, 0xD0,                             // call rax
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret
	};

	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		// Copy path
		PUNICODE_STRING pUserPath = &pBuffer->path;
		pUserPath->Length = 0;
		pUserPath->MaximumLength = sizeof(pBuffer->buffer);
		pUserPath->Buffer = pBuffer->buffer;

		RtlUnicodeStringCopy(pUserPath, pPath);

		// Copy code
		memcpy(pBuffer, code, sizeof(code));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)pBuffer + 12) = (ULONGLONG)pUserPath;
		*(ULONGLONG*)((PUCHAR)pBuffer + 22) = (ULONGLONG)&pBuffer->module;
		*(ULONGLONG*)((PUCHAR)pBuffer + 32) = (ULONGLONG)LdrLoadDll;
		*(ULONGLONG*)((PUCHAR)pBuffer + 44) = (ULONGLONG)&pBuffer->complete;

		return pBuffer;
	}

	UNREFERENCED_PARAMETER(pPath);
	return NULL;
}

/// <summary>
/// Find first thread of the target process
/// </summary>
/// <param name="pid">Target PID.</param>
/// <param name="ppThread">Found thread. Thread object reference count is increased by 1</param>
/// <returns>Status code</returns>
NTSTATUS SWIDLookupProcessThread(IN HANDLE pid, OUT PETHREAD* ppThread)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pBuf = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, POOL_TAG);
	PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)pBuf;

	ASSERT(ppThread != NULL);
	if (ppThread == NULL)
		return STATUS_INVALID_PARAMETER;

	if (!pInfo)
	{
		DPRINT("System Wide Injection Driver: %s: Failed to allocate memory for process list\n", __FUNCTION__);
		return STATUS_NO_MEMORY;
	}

	// Get the process thread list
	status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(pBuf, 0);
		return status;
	}

	// Find target thread
	if (NT_SUCCESS(status))
	{
		status = STATUS_NOT_FOUND;
		for (;;)
		{
			if (pInfo->UniqueProcessId == pid)
			{
				status = STATUS_SUCCESS;
				break;
			}
			else if (pInfo->NextEntryOffset)
				pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
			else
				break;
		}
	}

	// Reference target thread
	if (NT_SUCCESS(status))
	{
		status = STATUS_NOT_FOUND;

		// Get first thread
		for (ULONG i = 0; i < pInfo->NumberOfThreads; i++)
		{
			// Skip current thread
			if (/*pInfo->Threads[i].WaitReason == Suspended ||
				pInfo->Threads[i].ThreadState == 5 ||*/
				pInfo->Threads[i].ClientId.UniqueThread == PsGetCurrentThread())
			{
				continue;
			}

			status = PsLookupThreadByThreadId(pInfo->Threads[i].ClientId.UniqueThread, ppThread);
			break;
		}
	}
	else
		DPRINT("System Wide Injection Driver : %s: Failed to locate process.\n", __FUNCTION__);

	if (pBuf)
		ExFreePoolWithTag(pBuf, 0);

	return status;
}


//#define SEC_IMAGE   0x1000000 


/// <summary>
/// Inject dll using APC
/// Must be running in target process context
/// </summary>
/// <param name="pUserBuf">Injcetion code</param>
/// <param name="pid">Target process ID</param>
/// <returns>Status code</returns>
NTSTATUS SWIDApcInject(IN PINJECT_BUFFER pUserBuf, IN HANDLE pid)
{
	NTSTATUS status = STATUS_SUCCESS;
	PETHREAD pThread = NULL;

	// Get suitable thread
	status = SWIDLookupProcessThread(pid, &pThread);

	if (NT_SUCCESS(status))
	{
		status = SWIDQueueUserApc(pThread, pUserBuf->code, NULL, NULL, NULL, FALSE);

		if (!NT_SUCCESS(status))
			DPRINT("System Wide Injection Driver: %s: SWIDQueueUserApc Failed.\n", __FUNCTION__);
	}
	else
		DPRINT("System Wide Injection Driver: %s: Failed to locate thread.\n", __FUNCTION__);

	if (pThread)
		ObDereferenceObject(pThread);

	return status;
}
