#pragma once
#include <Windows.h>
#include "Utils.h"

namespace nightshade {

	inline bool RelDetour32(uintptr_t src, uintptr_t dest, size_t len)
	{
		BYTE shellcode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // jmp rel
		uintptr_t relativeAddress = (dest - src) - 5;
		memset(&shellcode[1], relativeAddress, 4);
		DWORD oldProtection = 0;
		if (VirtualProtect(RCast<void*>(src), len, PAGE_EXECUTE_READWRITE, &oldProtection))
		{
			memset(RCast<void*>(src), 0x90, len);
			memcpy(RCast<void*>(src), RCast<void*>(&shellcode), 5);
			DWORD oldProtectionTemp = 0;
			if (VirtualProtect(RCast<void*>(src), len, oldProtection, &oldProtectionTemp))
			{
				return true;
			}
			else {
				LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, GetLastErrorAsString(GetLastError()));
				return false;
			}
		}
		LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, GetLastErrorAsString(GetLastError()));
		return false;
	}

	inline bool AbsDetour64(uintptr_t src, uintptr_t dest, size_t len)
	{
		BYTE shellcode[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp    QWORD PTR [rip+0x0]
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // abs addr
		memset(&shellcode[6], dest, 8);
		DWORD oldProtection = 0;
		if (VirtualProtect(RCast<void*>(src), len, PAGE_EXECUTE_READWRITE, &oldProtection))
		{
			memset(RCast<void*>(src), 0x90, len);
			memcpy(RCast<void*>(src), RCast<void*>(&shellcode), 14);
			DWORD oldProtectionTemp = 0;
			if (VirtualProtect(RCast<void*>(src), len, oldProtection, &oldProtectionTemp))
			{
				return true;
			}
			else {
				LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, GetLastErrorAsString(GetLastError()));
				return false;
			}
		}
		LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, GetLastErrorAsString(GetLastError()));
		return false;
	}

	inline uintptr_t TrampolineHook32(uintptr_t src, uintptr_t dest, size_t len)
	{
		uintptr_t trampolineCave = RCast<uintptr_t>(VirtualAlloc(nullptr, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (trampolineCave)
		{
			memcpy(RCast<void*>(trampolineCave), RCast<void*>(src), len);

			intptr_t trampRelativeAddr = (src - trampolineCave) - 5;
			BYTE shellcode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
			memset(&shellcode[1], trampRelativeAddr, 4);
			memcpy(RCast<void*>(trampolineCave + len), &shellcode, 5);

			RelDetour32(src, dest, len);
			return trampolineCave;

		}
		else {
			LOG(2, L"Unable to VirtualAlloc Trampoline Cave. Error %s", GetLastErrorAsString(GetLastError()));
		}
		return 0;
	}

	inline uintptr_t TrampolineHook64(uintptr_t src, uintptr_t dest, size_t len)
	{
		uintptr_t trampolineCave = RCast<uintptr_t>(VirtualAlloc(nullptr, len + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (trampolineCave)
		{
			memcpy(RCast<void*>(trampolineCave), RCast<void*>(src), len);
			BYTE shellcode[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp    QWORD PTR [rip+0x0]
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // abs addr
			memset(&shellcode[1], src + 14, 8);
			memcpy(RCast<void*>(trampolineCave + len), &shellcode, 14);

			AbsDetour64(src, dest, len);
			return trampolineCave;
		}
		else {
			LOG(2, L"Unable to VirtualAlloc Trampoline Cave. Error %s", GetLastErrorAsString(GetLastError()));
		}
		return 0;
	}

	inline bool NopPatch(uintptr_t dest, size_t len)
	{
		DWORD oldProtection = 0;
		if (VirtualProtect(RCast<void*>(dest), len, PAGE_EXECUTE_READWRITE, &oldProtection))
		{
			memset(RCast<void*>(dest), 0x90, len);
			DWORD oldProtectionTemp = 0;
			if (VirtualProtect(RCast<void*>(dest), len, oldProtection, &oldProtectionTemp))
			{
				return true;
			}
			else {
				LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, GetLastErrorAsString(GetLastError()));
				return false;
			}
		}
		else {
			LOG(2, L"Unable to patch memory at %08X. Error %s", dest, GetLastErrorAsString(GetLastError()));
			return false;
		}
	}

	inline uintptr_t VTableHook(uintptr_t vTableAddr, int offset, uintptr_t hookFunc)
	{
		uintptr_t funcPtr = (*RCast<uintptr_t*>(vTableAddr)) + sizeof(uintptr_t) * offset;
		uintptr_t origFuncAddr = *(RCast<uintptr_t*>(funcPtr));
		DWORD oldProtection = 0;
		if (VirtualProtect(RCast<void*>(funcPtr), funcPtr + sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtection)) {
			*(RCast<uintptr_t*>(funcPtr)) = hookFunc;
			DWORD oldProtectionTemp = 0;
			VirtualProtect(RCast<void*>(funcPtr), funcPtr + sizeof(uintptr_t), oldProtection, &oldProtectionTemp);
			return origFuncAddr;
		}
		else {
			LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", origFuncAddr, GetLastErrorAsString(GetLastError()));
		}

		return 0;
	}
}