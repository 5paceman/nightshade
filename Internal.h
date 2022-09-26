#pragma once

#include <Windows.h>
#include <winternl.h>
#include <vector>
#include "Utils.h"


namespace nightshade {

	template <class T>
	inline bool Write(uintptr_t address, T value)
	{
		*RCast<T*>(address) = value;
	}

	inline uintptr_t ReadOffset(uintptr_t address, std::vector<uintptr_t>offsets)
	{
		uintptr_t result = address;
		for (uintptr_t offset : offsets)
		{
			result = *RCast<uintptr_t*>(result);
			result += offset;
		}

		return result;
	}

	inline uintptr_t PatternScan(uintptr_t startAddr, char* pattern, uintptr_t size)
	{
		size_t patternLength = strlen(pattern);

		
		for (int i = 0; i < size; i++)
		{
			bool found = true;
			for (int j = 0; j < patternLength; j++)
			{
				if (pattern[j] != '?' && pattern[j] != *(char*)((uintptr_t)startAddr + i + j))
				{
					found = false;
					break;
				}
			}
			if (found)
			{
				return (startAddr + i);
			}
		}
		return RCast<uintptr_t>(nullptr);
	}

	PEB* GetPEB()
	{
		#ifdef _WIN64
		PEB* peb = (PEB*)__readgsqword(0x60);

		#else
		PEB* peb = (PEB*)__readfsdword(0x30);
		#endif

		return peb;
	}

	LDR_DATA_TABLE_ENTRY* GetLDREntry(std::wstring name)
	{
		LDR_DATA_TABLE_ENTRY* ldr = nullptr;

		PEB* peb = GetPEB();

		LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

		LIST_ENTRY curr = head;

		while (curr.Flink != head.Blink)
		{
			LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (mod->FullDllName.Buffer)
			{
				wchar_t* cName = mod->FullDllName.Buffer;

				if (name.compare(cName) == 0)
				{
					ldr = mod;
					break;
				}
			}
			curr = *curr.Flink;
		}
		return ldr;
	}
}