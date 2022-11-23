#pragma once

#include <Windows.h>
#include <vector>
#include "NtDefinitions.h"
#include "Utils.h"


namespace nightshade {
	namespace Internal {
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

		_PEB* GetPEB()
		{
#ifdef _WIN64
			_PEB* peb = (PEB*)__readgsqword(0x60);

#else
			_PEB* peb = (PEB*)__readfsdword(0x30);
#endif

			return peb;
		}

		_LDR_DATA_TABLE_ENTRY* GetLDREntry(std::wstring name)
		{
			_LDR_DATA_TABLE_ENTRY* ldr = nullptr;

			_PEB* peb = GetPEB();

			LIST_ENTRY head = peb->LdrData->InMemoryOrderModuleList;

			LIST_ENTRY curr = head;

			while (curr.Flink != head.Blink)
			{
				_LDR_DATA_TABLE_ENTRY* mod = (_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

				if (mod->FullDllName.Buffer)
				{
					wchar_t* cName = mod->BaseDllName.Buffer;

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
}