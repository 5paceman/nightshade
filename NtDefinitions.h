#pragma once
#include <windows.h>


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_FAIL(Status) (((NTSTATUS)(Status)) < 0)

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

#pragma comment(lib, "ntdll.lib")
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(PHANDLE,ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID,BOOL, SIZE_T, SIZE_T, SIZE_T, LPVOID);

EXTERN_C NTSYSAPI NTSTATUS NTAPI LdrLoadDll(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

EXTERN_C NTSYSAPI void NTAPI RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);



