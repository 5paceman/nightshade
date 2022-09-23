#pragma once
#include <Windows.h>
#include <winnt.h>
#include "Utils.h"

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char*);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HMODULE, const char*);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void*, DWORD, void*);

struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hMod;
};

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall ManualMapShellcode(MANUAL_MAPPING_DATA* data)
{
	BYTE* pBase = RCast<BYTE*>(data);
	IMAGE_OPTIONAL_HEADER* pOpt = &RCast<IMAGE_NT_HEADERS*>(pBase + RCast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

	f_LoadLibraryA _LoadLibraryA = data->pLoadLibraryA;
	f_GetProcAddress _GetProcAddress = data->pGetProcAddress;
	f_DLL_ENTRY_POINT _DllMain = RCast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		IMAGE_BASE_RELOCATION* pRelocData = RCast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntry = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = RCast<WORD*>(pRelocData + 1);
			for (UINT i = 0; i != AmountOfEntry; i++, pRelativeInfo++)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = RCast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += RCast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = RCast<IMAGE_BASE_RELOCATION*>(RCast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* pImportDesc = RCast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDesc->Name)
		{
			char* szMod = RCast<char*>(pBase + pImportDesc->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			ULONG_PTR* pThunkRef = RCast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = RCast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; pThunkRef++, pFuncRef++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, RCast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDesc;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* pTLS = RCast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* pCallback = RCast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; pCallback++)
		{
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	data->hMod = RCast<HINSTANCE>(pBase);
}

using f_LdrLoadDll = NTSTATUS(NTAPI*)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
using f_RtlInitUnicodeString = void(NTAPI*)(PUNICODE_STRING, PCWSTR);

struct LDR_LOAD_DLL_DATA {
	f_LdrLoadDll pLdrLoadDll;
	f_RtlInitUnicodeString pRtlInitUnicodeString;
	const wchar_t* dllName;
	HANDLE hDll;
};

void __stdcall LdrLoadDllShellcode(LDR_LOAD_DLL_DATA* data)
{
	HANDLE hDll = 0;
	f_LdrLoadDll _LdrLoadDll = data->pLdrLoadDll;
	f_RtlInitUnicodeString _RltInitUnicodeString = data->pRtlInitUnicodeString;
	UNICODE_STRING unicodePath;
	_RltInitUnicodeString(&unicodePath, data->dllName);
	_LdrLoadDll(NULL, 0, &unicodePath, &hDll);
}
