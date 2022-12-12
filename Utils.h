#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <ImageHlp.h>
#include <string>
#include <locale>
#include <codecvt>
#include "Types.h"
#include "Logger.h"
#include <vector>
#include "Types.h"
#include "Timer.h"
#include <locale>
#include <codecvt>
#include <algorithm>

#pragma comment(lib, "Imagehlp.lib")

#define RCast reinterpret_cast
#define SCast static_cast

#define RPM(h, addr, buffer, size, readBytes) if(!ReadProcessMemory(h, addr, buffer, size, readBytes)) { \
LOG(3, L"Unable to RPM at 0x%08X for size %d bytes. Error %s", addr, size, nightshade::Utils::GetLastErrorAsString(GetLastError()).c_str()); \
} \

#define WPM(h, addr, buffer, size, writtenBytes) if(!WriteProcessMemory(h, addr, buffer, size, writtenBytes)) { \
LOG(3, L"Unable to WPM at 0x%08X for size %d bytes. Error %s", addr, size, nightshade::Utils::GetLastErrorAsString(GetLastError()).c_str()); \
} \

namespace nightshade {
	namespace Utils {

		inline std::wstring GetLastErrorAsString(DWORD error)
		{
			if (error == 0)
				return std::wstring(L"No Error");

			std::string errorMessage = std::system_category().message(error);
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			return converter.from_bytes(errorMessage);
		}

		inline std::string WStringToCString(const std::wstring& string)
		{
			using convert_typeX = std::codecvt_utf8<wchar_t>;
			std::wstring_convert<convert_typeX, wchar_t> converter;
			return converter.to_bytes(string);
		}

		inline std::wstring CStringToWString(const std::string& string)
		{
			using convert_typeX = std::codecvt_utf8<wchar_t>;
			std::wstring_convert<convert_typeX, wchar_t> converter;
			return converter.from_bytes(string);
		}

		inline MODULEENTRY32W GetModuleEx(HANDLE hProc, std::wstring dllName)
		{
			MODULEENTRY32W modEntry = {};
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProc));
			if (hSnapshot == INVALID_HANDLE_VALUE)
			{
				LOG(3, L"Unable to create snapshot of modules for PID %d, Error: %s", GetProcessId(hProc), nightshade::Utils::GetLastErrorAsString(GetLastError()).c_str());
				return modEntry;
			}
			modEntry.dwSize = sizeof(MODULEENTRY32W);
			std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
			dllName.append(L".dll");

			DWORD moduleBase = 0;
			DWORD moduleSize = 0;
			if (!Module32FirstW(hSnapshot, &modEntry))
			{
				CloseHandle(hSnapshot);
				LOG(3, L"Unable to Module32FirstW");
				return modEntry;
			}
			do {

				std::wstring wModule(modEntry.szModule);
				std::transform(wModule.begin(), wModule.end(), wModule.begin(), ::tolower);
				if (wcscmp(wModule.c_str(), dllName.c_str()) == 0)
				{
					moduleBase = RCast<DWORD>(modEntry.modBaseAddr);
					moduleSize = modEntry.modBaseSize;
					CloseHandle(hSnapshot);
					break;
				}
			} while (Module32NextW(hSnapshot, &modEntry));
			return modEntry;
		}

		inline Architecture GetDLLArchitecture(const wchar_t* path)
		{
			LOADED_IMAGE loadedImage;
			ZeroMemory(&loadedImage, sizeof(loadedImage));
			char* pathBuffer = new char[MAX_PATH];
			size_t cSize;
			wcstombs_s(&cSize, pathBuffer, (wcslen(path) + 1) * sizeof(wchar_t), path, (wcslen(path) + 1) * sizeof(wchar_t));
			if (!MapAndLoad(pathBuffer, NULL, &loadedImage, FALSE, TRUE))
			{
				UnMapAndLoad(&loadedImage);
				return Architecture::UNKNOWN;
			}
			WORD machine = loadedImage.FileHeader->FileHeader.Machine;
			if (machine)
			{
				if (machine == IMAGE_FILE_MACHINE_I386)
				{
					UnMapAndLoad(&loadedImage);
					return Architecture::x86;
				}
				else if (machine == IMAGE_FILE_MACHINE_AMD64)
				{
					UnMapAndLoad(&loadedImage);
					return Architecture::X64;
				}
			}
			UnMapAndLoad(&loadedImage);
			return Architecture::UNKNOWN;
		}

		const wchar_t* ArchToString(Architecture arch);

		inline Architecture GetProcessArchitecture(HANDLE hProc)
		{
			BOOL IsProcWoW64;
			IsWow64Process(hProc, &IsProcWoW64);
			if (IsProcWoW64)
			{
				return Architecture::x86;
			}
			else {
				SYSTEM_INFO sysInfo = {};
				GetSystemInfo(&sysInfo);

				if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
				{
					return Architecture::X64;
				}
				else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
				{
					return Architecture::x86;
				}
			}
		}

		inline bool IsDllCompatible(Architecture dllArch, HANDLE hProc)
		{
			return GetProcessArchitecture(hProc) == dllArch;
		}

		inline bool IsDllCompatible(const wchar_t* dllPath, HANDLE hProc)
		{
			return GetDLLArchitecture(dllPath) == GetProcessArchitecture(hProc);
		}

		inline bool GetThreadsFromProcess(DWORD dwPID, std::vector<DWORD>& tIDs)
		{
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
			if (hSnapshot)
			{
				THREADENTRY32 thread;
				ZeroMemory(&thread, sizeof(THREADENTRY32));
				thread.dwSize = sizeof(thread);
				if (!Thread32First(hSnapshot, &thread))
				{
					return false;
				}
				do {
					if (thread.th32OwnerProcessID == dwPID)
					{
						tIDs.push_back(thread.th32ThreadID);
					}
				} while (Thread32Next(hSnapshot, &thread));
				CloseHandle(hSnapshot);
				return tIDs.size() > 0;
			}
			return false;
		}

		inline BOOL CALLBACK EnumWindowsCB(HWND handle, LPARAM lp)
		{
			WindowEnumData& data = *(WindowEnumData*)lp;
			DWORD dwPID;
			GetWindowThreadProcessId(handle, &dwPID);
			if (data.pid != dwPID)
			{
				return TRUE;
			}
			data.hWnd = handle;
			return FALSE;
		}

		inline const wchar_t* GetWindowTitleFromPID(DWORD dwPID)
		{
			WindowEnumData data;
			data.pid = dwPID;
			data.hWnd = 0;
			EnumWindows(EnumWindowsCB, (LPARAM)&data);

			if (data.hWnd != 0)
			{
				wchar_t* title = new wchar_t[MAX_PATH];
				GetWindowTextW(data.hWnd, title, MAX_PATH);
				return title;
			}
			else {
				return L"";
			}
		}

		inline bool IsElevatedProcess()
		{
			BOOL isElevated = false;
			HANDLE hToken = NULL;
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				TOKEN_ELEVATION tElevation;
				DWORD cbSize = sizeof(TOKEN_ELEVATION);
				if (GetTokenInformation(hToken, TokenElevation, &tElevation, sizeof(tElevation), &cbSize))
				{
					isElevated = tElevation.TokenIsElevated;
				}
			}
			if (hToken)
				CloseHandle(hToken);

			return isElevated;
		}

		inline bool AdjustPriviledges(HANDLE hProc)
		{
			HANDLE hToken = 0;
			TOKEN_PRIVILEGES tokenPriv = {};
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			{
				LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPriv.Privileges[0].Luid);
				tokenPriv.PrivilegeCount = 1;
				tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				AdjustTokenPrivileges(hToken, false, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
				CloseHandle(hToken);
			}
			return true;
		}

		inline const wchar_t* ArchToString(Architecture arch)
		{
			switch (arch)
			{
			case Architecture::X64:
				return L"X64";
			case Architecture::x86:
				return L"X86";
			case Architecture::UNKNOWN:
				return L"Unknown";
			}
		}

		inline bool detectJmps32(uintptr_t addr)
		{
			if (*((BYTE*)addr) == 0xE9)
			{
				return true;
			}

			return false;
		}

		inline uintptr_t followJmps32(uintptr_t addr)
		{
			while (*((BYTE*)addr) == 0xE9)
			{
				intptr_t jmpTo = *(intptr_t*)(addr + 1);
				addr = (addr + 5) + jmpTo;
			}

			return addr;
		}

		inline bool detectJmps32Ex(HANDLE hProc, uintptr_t addr)
		{
			BYTE byte = 0;
			RPM(hProc, RCast<void*>(addr), &byte, sizeof(byte), nullptr);
			if (byte == 0xE9)
			{
				return true;
			}

			return false;
		}

		inline uintptr_t followJmps32Ex(HANDLE hProc, uintptr_t addr)
		{
			if (GetProcessArchitecture(hProc) == Architecture::X64)
			{
				while (detectJmps32Ex(hProc, addr))
				{
					long long jmpTo = 0;
					RPM(hProc, RCast<void*>(addr + 1), &jmpTo, sizeof(jmpTo), nullptr);
					addr = (addr + 5) + jmpTo;
				}
			}
			else {
				while (detectJmps32Ex(hProc, addr))
				{
					int jmpTo = 0;
					RPM(hProc, RCast<void*>(addr + 1), &jmpTo, sizeof(jmpTo), nullptr);
					addr = (addr + 5) + jmpTo;
				}
			}
			return addr;
		}

		inline uintptr_t GetProcAddressEx(HANDLE hProc, std::wstring dllName, std::string functionName);

		inline uintptr_t GetProcAddressExH(HANDLE hProc, std::wstring dllName, std::string functionName, bool checkForHooks, bool restoreOriginal)
		{
			if (!checkForHooks)
				return GetProcAddressEx(hProc, dllName, functionName);

			uintptr_t funcAddr = GetProcAddressEx(hProc, dllName, functionName);

			if (!funcAddr)
				return 0;

			BYTE byte[5] = {};

			RPM(hProc, RCast<void*>(funcAddr), &byte, sizeof(byte), nullptr);

			if (byte[0] == 0xE9)
			{
				uintptr_t followJmps = followJmps32Ex(hProc, funcAddr);

				if (!followJmps)
				{
					LOG(3, L"Unable to follow hook.");
					return 0;
				}

				MODULEENTRY32W modEntry = GetModuleEx(hProc, dllName);
				
				if (RCast<uintptr_t>(modEntry.modBaseAddr) > followJmps || RCast<uintptr_t>(modEntry.modBaseAddr + modEntry.modBaseSize) < followJmps)
				{
					LOG(3, L"Function is hooked and jmps outside module address space. -> 0x%08X", followJmps);

					if (!restoreOriginal)
						return funcAddr;

					HMODULE hModule = GetModuleHandleW(dllName.c_str());

					if (!hModule)
					{
						LOG(3, L"Unable to get handle on %s", dllName.c_str());
						return 0;
					}

					uintptr_t ourFuncAddr = RCast<uintptr_t>(GetProcAddress(hModule, functionName.c_str()));

					
					return funcAddr;
				}
			}

			return funcAddr;
		}

		inline uintptr_t GetProcAddressEx(HANDLE hProc, std::wstring dllName, std::string functionName)
		{
			MODULEENTRY32W modEntry = GetModuleEx(hProc, dllName);
			Architecture procArch = GetProcessArchitecture(hProc);

			uintptr_t moduleBase = RCast<uintptr_t>(modEntry.modBaseAddr);
			DWORD moduleSize = modEntry.dwSize;

			if (!moduleBase || !moduleSize)
			{
				LOG(3, L"Unable to find module %s in remote process %d", dllName.c_str(), GetProcessId(hProc));
				return 0;
			}

			IMAGE_DOS_HEADER dosHeader = {};
			RPM(hProc, RCast<void*>(moduleBase), &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr);

			if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
			{
				LOG(3, L"DOS Signature of remote module %s is not correct.", dllName.c_str());
				return 0;
			}

			uintptr_t exportDirectoryVA = 0;

			if (procArch == Architecture::x86)
			{
				IMAGE_NT_HEADERS32 ntHeader = {};
				RPM(hProc, RCast<void*>(moduleBase + dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS32), nullptr);

				if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
				{
					LOG(3, L"NT Signature of remote module %s is not correct.", dllName.c_str());
					return 0;
				}

				if (!ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
				{
					LOG(3, L"Unable to read Export directory virtual address");
					return 0;
				}

				exportDirectoryVA = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}
			else {
				IMAGE_NT_HEADERS64 ntHeader = {};
				RPM(hProc, RCast<void*>(moduleBase + dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS64), nullptr);

				if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
				{
					LOG(3, L"NT Signature of remote module %s is not correct.", dllName.c_str());
					return 0;
				}

				if (!ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
				{
					LOG(3, L"Unable to read Export directory virtual address");
					return 0;
				}

				exportDirectoryVA = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}

			IMAGE_EXPORT_DIRECTORY expDirectory = {};
			RPM(hProc, RCast<void*>(moduleBase + exportDirectoryVA), &expDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr);

			uintptr_t addrOfFunc = moduleBase + expDirectory.AddressOfFunctions;
			uintptr_t addrOfNames = moduleBase + expDirectory.AddressOfNames;
			uintptr_t addrOfOrdinals = moduleBase + expDirectory.AddressOfNameOrdinals;

			WORD ordinal = 0;
			size_t len_buf = functionName.length() + 1;
			char* nameBuff = new char[len_buf];

			size_t addrLength = (procArch == Architecture::x86 ? sizeof(DWORD) : sizeof(uintptr_t));

			for (DWORD i = 0; i < expDirectory.NumberOfNames; i++)
			{
				uintptr_t rvaString = 0;
				RPM(hProc, RCast<void*>(addrOfNames + (i * addrLength)), &rvaString, addrLength, nullptr);
				RPM(hProc, RCast<void*>(moduleBase + rvaString), nameBuff, len_buf, nullptr);

				if (!lstrcmpiA(functionName.c_str(), nameBuff))
				{
					RPM(hProc, RCast<void*>(addrOfOrdinals + (i * sizeof(WORD))), &ordinal, sizeof(WORD), nullptr);
					uintptr_t funcRVA = 0;
					RPM(hProc, RCast<void*>(addrOfFunc + (ordinal * addrLength)), &funcRVA, addrLength, nullptr);
					delete[] nameBuff;
					return moduleBase + funcRVA;
				}
			}
			delete[] nameBuff;
			return 0;
		}
	}
}