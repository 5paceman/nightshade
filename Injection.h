#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include "Types.h"
#include "Utils.h"
#include "Logger.h"
#include "NtDefinitions.h"

enum INJ_OPTIONS {
	HIJACK_HANDLE = 0x01,
	MM_SEH = 0x2,
	MM_TLS = 0x4,
	MM_CLEAR_PE = 0x8,
	MM_FAKE_PE = 0x10,
	CLOAK_THREAD = 0x20
};

typedef struct InjectionData {
	wchar_t            dllPath[MAX_PATH];
	DWORD              pID;
	DWORD              flags;
	bool               is64bit;
	InjMethod          injMethod;
	RemoteExecMethod   reMethod;
} InjectionData, * pInjectionData;

namespace nightshade {
	class Injection {
	private:
		InjectionData* m_data;

		fNtQueryInformationThread NtQueryInformationThread;
		fNtSetInformationThread NtSetInformationThread;
		fNtGetContextThread NtGetContextThread;
		fNtSetContextThread NtSetContextThread;
		fNtCreateThreadEx NtCreateThreadEx;
	public:
		Injection(InjectionData* data);
		~Injection();

	public:
		virtual bool Inject();
	private:
		virtual HANDLE GetProcHandle();
		virtual LPVOID AllocateAndWriteMemory(HANDLE hProc);
		virtual LPVOID CreateEntryPoint(LPVOID lpMemAddress, HANDLE hProc);
		virtual bool ExecuteEntryPoint(LPVOID lpEntryPoint, LPVOID lpMemAddress, HANDLE hProc);
		virtual void Cleanup(LPVOID lpEntryPoint, LPVOID lpMemAddress, HANDLE hProc);
	private:
		virtual bool REQueueAPC(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc);
		virtual bool RENtCreateThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc);
		virtual bool REHijackThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc);

		virtual bool HideThreadFromDebugger(HANDLE hThread, HANDLE hProc);
		virtual bool HideThreadStartAddress(HANDLE hThread, LPVOID lpEntryPoint, HANDLE hProc);

	};
}