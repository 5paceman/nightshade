#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include "Types.h"
#include "Utils.h"
#include "Logger.h"
#include "NtDefinitions.h"

namespace nightshade {
	class Injection {
	private:
		InjectionData* m_data;
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
		//Possibly need to do a va list here? for param
		virtual void Cleanup(LPVOID lpEntryPoint, LPVOID lpMemAddress, HANDLE hProc);
	private:
		virtual bool REQueueAPC(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc);
		virtual bool RENtCreateThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc);
		virtual bool REHijackThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc);
	};
}