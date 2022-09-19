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

#pragma comment(lib, "Imagehlp.lib")

#define RCast reinterpret_cast
#define SCast static_cast

namespace nightshade {

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

	inline bool IsDllCompatible(const wchar_t* dllPath, HANDLE hProc)
	{
		BOOL IsProcWoW64;
		IsWow64Process(hProc, &IsProcWoW64);
		Architecture dllArch = GetDLLArchitecture(dllPath);
		LOG(1, L"DLL architecture is %s", ArchToString(dllArch));
		if (IsProcWoW64)
		{
			LOG(1, L"Process is X86");
			return dllArch == Architecture::x86;
		}
		else {
			SYSTEM_INFO sysInfo;
			ZeroMemory(&sysInfo, sizeof(sysInfo));
			GetSystemInfo(&sysInfo);

			if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			{
				LOG(1, L"Process is X64");
				return dllArch == Architecture::X64;
			}
			else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			{
				LOG(1, L"Process is X86");
				return dllArch == Architecture::x86;
			}
		}
		return false;
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

	inline bool AdjustPriviledges()
	{
		HANDLE hToken;
		TOKEN_PRIVILEGES tokenPriv;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPriv.Privileges[0].Luid);
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			return AdjustTokenPrivileges(hToken, false, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
		} 
		return false;
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

	inline std::wstring GetLastErrorAsString(DWORD error)
	{
		if (error == 0)
			return std::wstring(L"No Error");

		std::string errorMessage = std::system_category().message(error);
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
		return converter.from_bytes(errorMessage);
	}
}