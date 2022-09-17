#pragma once
#include <windows.h>
#include <string>
#include <locale>
#include <codecvt>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_FAIL(Status) (((NTSTATUS)(Status)) < 0)

#pragma comment(lib, "ntdll.lib")
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(PHANDLE,ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID,BOOL, SIZE_T, SIZE_T, SIZE_T, LPVOID);

inline std::wstring GetLastErrorAsString(DWORD error)
{
	if (error == 0)
		return std::wstring(L"No Error");

	std::string errorMessage = std::system_category().message(error);
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.from_bytes(errorMessage);
}

