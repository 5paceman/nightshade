#pragma once
#include <windows.h>

#pragma comment(lib, "ntdll.lib")
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(PHANDLE,
	ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID,
	BOOL, SIZE_T, SIZE_T, SIZE_T, LPVOID);

struct NtCreateThreadExBuffer
{
	SIZE_T Size;
	SIZE_T Unknown1;
	SIZE_T Unknown2;
	PULONG Unknown3;
	SIZE_T Unknown4;
	SIZE_T Unknown5;
	SIZE_T Unknown6;
	PULONG Unknown7;
	SIZE_T Unknown8;
};

