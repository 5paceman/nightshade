#include "Injection.h"


nightshade::Injection::Injection(InjectionData* data)
{
	this->m_data = data;
	if (wcslen(m_data->dllPath) == 0)
	{
		LOG(1, L"DLL Path is empty.");
	}
	
}

nightshade::Injection::~Injection()
{
	
}

bool nightshade::Injection::Inject()
{
	if (IsElevatedProcess())
	{
		HANDLE hProc = GetProcHandle();
		if (hProc)
		{
			if (IsDllCompatible(m_data->dllPath, hProc))
			{
				LPVOID memoryAddress = AllocateMemory(hProc);
				if (memoryAddress)
				{
					LPVOID entryPoint = CreateEntryPoint(memoryAddress, hProc);
					if (entryPoint == NULL)
					{
						Cleanup(nullptr, memoryAddress, hProc);
						LOG(3, L"Unable to create entry point");
						return false;
					}
					LOG(1, L"Entry point is 0x%08X", entryPoint);
					bool result = ExecuteEntryPoint(entryPoint, memoryAddress, hProc);
					Cleanup(entryPoint, memoryAddress, hProc);
					return result;
				}
			}
			else {
				LOG(3, L"DLL is not compatible with process.");
				return false;
			}
		}
		else {
			LOG(3, L"Unable to get handle on process, error: %s", GetLastErrorAsString(GetLastError()).c_str());
			return false;
		}
	}
	else {
		LOG(3, L"Running as standard process, please run as administrator.");
	}
	return false;
}

HANDLE nightshade::Injection::GetProcHandle()
{
	return OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, m_data->pID);
}

LPVOID nightshade::Injection::AllocateMemory(HANDLE hProc)
{
	if (m_data->injMethod == InjMethod::IM_LoadLibraryEx)
	{
		char cPath[MAX_PATH];
		wcstombs_s(nullptr, cPath, m_data->dllPath, wcslen(m_data->dllPath));
		LPVOID lpDLLPathAddr = VirtualAllocEx(hProc, nullptr, strlen(cPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpDLLPathAddr)
		{
			LOG(1, L"Allocated Memory at 0x%08X", lpDLLPathAddr);
			size_t bytesWritten = 0;
			if (WriteProcessMemory(hProc, lpDLLPathAddr, cPath, strlen(cPath) + 1, &bytesWritten))
			{
				LOG(1, L"BytesWritten: %d", bytesWritten);
				return lpDLLPathAddr;
			}
			else {
				Cleanup(nullptr, lpDLLPathAddr, hProc);
				LOG(3, L"Unable to WriteProcessMemory");
			}
		}
		else {
			LOG(3, L"Unable to VirtualAllocEx Memory.");
		}
	}
	return 0;
}

LPVOID nightshade::Injection::CreateEntryPoint(LPVOID lpMemAddress, HANDLE hProc)
{
	if (m_data->injMethod == InjMethod::IM_LoadLibraryEx)
	{
		HMODULE hKernel32 = GetModuleHandle(L"Kernel32");
		if (hKernel32 != NULL)
		{
			LOG(1, L"Got handle on Kernel32 0x%08X", hKernel32);
			return (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
		}
		else {
			Cleanup(nullptr, lpMemAddress, hProc);
			LOG(3, L"Not able to get handle on Kernel32");
		}
	}
	else if (m_data->injMethod == InjMethod::IM_LdrLoadDll)
	{
		
	}
	return 0;
}

bool nightshade::Injection::ExecuteEntryPoint(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc)
{
	switch (m_data->reMethod)
	{
	case RemoteExecMethod::RE_QueueUserAPC:
		return REQueueAPC(lpEntryPoint, lpMemoryAddress, hProc);
	case RemoteExecMethod::RE_NtCreateThreadEx:
		return RENtCreateThread(lpEntryPoint, lpMemoryAddress, hProc);
	}
	return false;
}

void nightshade::Injection::Cleanup(LPVOID lpEntryPoint, LPVOID lpMemAddress, HANDLE hProc)
{
	if (lpEntryPoint)
	{

	}

	if (lpMemAddress)
	{
		VirtualFreeEx(hProc, lpMemAddress, 0, MEM_RELEASE);
		lpMemAddress = nullptr;
	}

	if (hProc)
	{
		CloseHandle(hProc);
	}
}

bool nightshade::Injection::REQueueAPC(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc)
{
	std::vector<DWORD> tIDs;
	if (GetThreadsFromProcess(GetProcessId(hProc), tIDs)) {
		bool didQueueAPC = false;
		for (DWORD tID : tIDs)
		{
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tID);
			if (hThread)
			{
				LOG(1, L"Opened thread and QueuedAPC");
				bool result = QueueUserAPC((PAPCFUNC)lpEntryPoint, hThread, (ULONG_PTR)lpMemoryAddress);
				if (!didQueueAPC) didQueueAPC = true;
				CloseHandle(hThread);
			}
		}
		return true;
	}
	LOG(3, L"Couldnt find any threads for process %d", GetProcessId(hProc));
	return false;
}

bool nightshade::Injection::RENtCreateThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc)
{
	if (!AdjustPriviledges())
	{
		LOG(3, L"Failed to elevate priviledges");
		return false;
	}

	HANDLE hThread;
	NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc, (LPTHREAD_START_ROUTINE)lpEntryPoint, lpMemoryAddress, FALSE, NULL, NULL, NULL, nullptr);
	if (NT_SUCCESS(status))
	{
		DWORD waitResult = WaitForSingleObject(hThread, INFINITE);
		if (waitResult == WAIT_OBJECT_0) //TODO dont infinite wait
		{
			DWORD returnValue;
			if (GetExitCodeThread(hThread, &returnValue))
			{
				LOG(1, L"Remote thread returned 0x%08X", returnValue);
			}
			return true;
		}
		else {
			LOG(2, L"Couldnt wait for thread to terminate. Thread wait returned %d, DLL possibly injected.", waitResult);
		}
	}
	else {
		LOG(3, L"Unable to create thread with NtCreateThreadEx. NTSTATUS: 0x%08X \nError: %s", status, GetLastErrorAsString(GetLastError()).c_str());
	}
	return false;
}

bool nightshade::Injection::REHijackThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc)
{
	return false;
}
