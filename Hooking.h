#pragma once
#include <Windows.h>
#include "Utils.h"

namespace nightshade {
	namespace Hooking {

		inline bool detectJmps32(uintptr_t src);
		inline uintptr_t followJmps32(uintptr_t src);

		inline bool RestoreDetour(uintptr_t src,  const char* restoredShellcode, size_t len)
		{
			DWORD oldProtection = 0;
			if (VirtualProtect(RCast<void*>(src), len, PAGE_EXECUTE_READWRITE, &oldProtection))
			{
				memcpy(RCast<void*>(src), restoredShellcode, len);
				DWORD oldProtectionTemp = 0;
				if (VirtualProtect(RCast<void*>(src), len, oldProtection, &oldProtectionTemp))
				{
					return true;
				}
			}

			return false;
		}

		inline bool RelDetour32(uintptr_t src, uintptr_t dest, size_t len);

		inline bool RelDetour32FollowJmps(uintptr_t src, uintptr_t dest, size_t len)
		{
			if (detectJmps32(src))
			{
				LOG(2, L"Hook detected at 0x%08X.", src);
				uintptr_t followedHooks = followJmps32(src);
				LOG(1, L"Followed hook -> 0x%08X.", followedHooks);
				return RelDetour32(followedHooks, dest, len);
			}
			else {
				return RelDetour32(src, dest, len);
			}
		}

		inline bool RelDetour32(uintptr_t src, uintptr_t dest, size_t len)
		{
			BYTE shellcode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // jmp rel
			uintptr_t relativeAddress = (dest - src) - 5;
			DWORD oldProtection = 0;
			if (VirtualProtect(RCast<void*>(src), len, PAGE_EXECUTE_READWRITE, &oldProtection))
			{
				memset(RCast<void*>(src), 0x90, len);
				memcpy(RCast<void*>(src), RCast<void*>(&shellcode), 5);

				*(uintptr_t*)(src + 1) = relativeAddress;
				DWORD oldProtectionTemp = 0;
				if (VirtualProtect(RCast<void*>(src), len, oldProtection, &oldProtectionTemp))
				{
					LOG(1, L"Hooked 0x%08X -> 0x%08X. Jmp is %d bytes", src, dest, relativeAddress);
					return true;
				}
				else {
					LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", src, nightshade::Utils::GetLastErrorAsString(GetLastError()));
					return false;
				}
			}
			LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", src, nightshade::Utils::GetLastErrorAsString(GetLastError()));
			return false;
		}

		inline bool AbsDetour64(uintptr_t src, uintptr_t dest, size_t len)
		{
			BYTE shellcode[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp    QWORD PTR [rip+0x0]
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // abs addr
			DWORD oldProtection = 0;
			if (VirtualProtect(RCast<void*>(src), len, PAGE_EXECUTE_READWRITE, &oldProtection))
			{
				memset(RCast<void*>(src), 0x90, len);
				memcpy(RCast<void*>(src), RCast<void*>(&shellcode), 14);

				*(uintptr_t*)(src + 6) = dest;

				DWORD oldProtectionTemp = 0;
				if (VirtualProtect(RCast<void*>(src), len, oldProtection, &oldProtectionTemp))
				{
					LOG(1, L"Hooked 0x%08X -> 0x%08X.", src, dest);
					return true;
				}
				else {
					LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, nightshade::Utils::GetLastErrorAsString(GetLastError()));
					return false;
				}
			}
			LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, nightshade::Utils::GetLastErrorAsString(GetLastError()));
			return false;
		}

		inline bool RestoreTrampolineHook(uintptr_t src, uintptr_t trampolineCave, size_t len)
		{
			DWORD oldProtection = 0;
			if (VirtualProtect(RCast<void*>(src), len, PAGE_EXECUTE_READWRITE, &oldProtection))
			{
				memcpy(RCast<void*>(src), RCast<void*>(trampolineCave), len);
				DWORD oldProtectionTemp = 0;
				if (VirtualProtect(RCast<void*>(src), len, oldProtection, &oldProtectionTemp))
				{
					VirtualFree(RCast<void*>(trampolineCave), 0, MEM_RELEASE);
					return true;
				}
			}

			return false;
		}

		inline bool RestoreTrampolineHookFollowJmps(uintptr_t src, uintptr_t trampolineCave, size_t len)
		{
			if (detectJmps32(src))
			{
				uintptr_t followedHooks = followJmps32(src);
				return RestoreTrampolineHook(followedHooks, trampolineCave, len);
			}
			else {
				return RestoreTrampolineHook(src, trampolineCave, len);
			}

			return false;
		}

		inline uintptr_t TrampolineHook32(uintptr_t src, uintptr_t dest, size_t len);

		inline uintptr_t TrampolineHook32FollowJmps(uintptr_t src, uintptr_t dest, size_t len)
		{
			if (detectJmps32(src))
			{
				LOG(2, L"Hook detected at 0x%08X.", src);
				uintptr_t followedHooks = followJmps32(src);
				LOG(1, L"Followed hook -> 0x%08X.", followedHooks);
				return TrampolineHook32(followedHooks, dest, len);
			}
			else {
				return TrampolineHook32(src, dest, len);
			}
		}

		inline uintptr_t TrampolineHook32(uintptr_t src, uintptr_t dest, size_t len)
		{
			uintptr_t trampolineCave = RCast<uintptr_t>(VirtualAlloc(nullptr, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (trampolineCave)
			{
				memcpy(RCast<void*>(trampolineCave), RCast<void*>(src), len);

				intptr_t trampRelativeAddr = (src - trampolineCave) - 5;
				BYTE shellcode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
				memcpy(RCast<void*>(trampolineCave + len), &shellcode, 5);

				*(intptr_t*)(trampolineCave + len + 1) = trampRelativeAddr;

				if (!RelDetour32(src, dest, len))
				{
					return 0;
				}

				LOG(1, L"Created Trampoline at 0x%08X.", trampolineCave);
				return trampolineCave;

			}
			else {
				LOG(2, L"Unable to VirtualAlloc Trampoline Cave. Error %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
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

				*(uintptr_t*)(trampolineCave + len + 6) = src + 14;

				if (!AbsDetour64(src, dest, len))
				{
					VirtualFree(RCast<void*>(trampolineCave), 0, MEM_RELEASE);
					return 0;
				}

				LOG(1, L"Created Trampoline at 0x%08X.", trampolineCave);
				return trampolineCave;
			}
			else {
				LOG(2, L"Unable to VirtualAlloc Trampoline Cave. Error %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
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
					LOG(1, L"Nop patched at 0x%08X for %d bytes.", dest, len);
					return true;
				}
				else {
					LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", dest, nightshade::Utils::GetLastErrorAsString(GetLastError()));
					return false;
				}
			}
			else {
				LOG(2, L"Unable to patch memory at %08X. Error %s", dest, nightshade::Utils::GetLastErrorAsString(GetLastError()));
				return false;
			}
		}

		inline uintptr_t VTableHook(uintptr_t vTableAddr, int offset, uintptr_t hookFunc)
		{
			uintptr_t funcPtr = vTableAddr + (sizeof(uintptr_t) * offset);
			uintptr_t origFuncAddr = *(RCast<uintptr_t*>(funcPtr));
			DWORD oldProtection, oldProtectionTemp = 0;
			if (VirtualProtect(RCast<void*>(funcPtr), sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtection)) {
				*(RCast<uintptr_t*>(funcPtr)) = hookFunc;
				VirtualProtect(RCast<void*>(funcPtr), sizeof(uintptr_t), oldProtection, &oldProtectionTemp);
				LOG(1, L"VTable Hook at 0x%08X, index %d, 0x%08X -> 0x%08X", vTableAddr, offset, origFuncAddr, hookFunc);
				return origFuncAddr;
			}
			else {
				LOG(2, L"Unable to VirtualProtect memory at %08X. Error %s", funcPtr, nightshade::Utils::GetLastErrorAsString(GetLastError()));
			}

			return 0;
		}
	}
}