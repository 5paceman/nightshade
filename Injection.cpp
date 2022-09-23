#include "Injection.h"
#include "Shellcode.h"


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
				LPVOID memoryAddress = AllocateAndWriteMemory(hProc);
				if (memoryAddress)
				{
					LOG(1, L"lParam data is 0x%08X", memoryAddress);
					LPVOID entryPoint = CreateEntryPoint(memoryAddress, hProc);
					if (entryPoint == NULL)
					{
						Cleanup(nullptr, memoryAddress, hProc);
						LOG(3, L"Unable to create entry point");
						return false;
					}
					LOG(1, L"Entry point is 0x%08X", entryPoint);
					bool result = ExecuteEntryPoint(entryPoint, memoryAddress, hProc);
					if (m_data->reMethod == RemoteExecMethod::RE_NtCreateThreadEx)
						Cleanup(entryPoint, memoryAddress, hProc);
					else
						Cleanup(entryPoint, nullptr, hProc);
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

LPVOID nightshade::Injection::AllocateAndWriteMemory(HANDLE hProc)
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
	else if (m_data->injMethod == InjMethod::IM_LdrLoadDll)
	{
		LDR_LOAD_DLL_DATA data{ 0 };
		data.pLdrLoadDll = LdrLoadDll;
		data.pRtlInitUnicodeString = RtlInitUnicodeString;
		
		LPVOID dllName = VirtualAllocEx(hProc, nullptr, (wcslen(m_data->dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (dllName)
		{
			if (WriteProcessMemory(hProc, dllName, m_data->dllPath, (wcslen(m_data->dllPath) + 1) * sizeof(wchar_t), nullptr)) {
				data.dllName = RCast<const wchar_t*>(dllName);
				LOG(1, L"Dll Name at 0x%08X", dllName);
				LPVOID dataStructAddr = VirtualAllocEx(hProc, nullptr, sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (dataStructAddr)
				{
					if (WriteProcessMemory(hProc, dataStructAddr, &data, sizeof(data), nullptr))
					{
						return dataStructAddr;
					}
					else {
						LOG(3, L"Unable to Write Process memory, Error %s", GetLastErrorAsString(GetLastError()));
						delete& data;
						return 0;
					}
				}
				else {
					LOG(3, L"Unable to Virtual Alloc memory");
					delete& data;
					return 0;
				}
			}
			else {
				LOG(3, L"Unable to Write Process memory, Error %s", GetLastErrorAsString(GetLastError()));
				delete& data;
				return 0;
			}
		}
		else {
			LOG(3, L"Unable to Virtual Alloc memory");
			delete& data;
			return 0;
		}
	}
	else if (m_data->injMethod == InjMethod::IM_ManualMap)
	{
		BYTE* pSrcData = nullptr;
		IMAGE_DOS_HEADER* pOldDOSHeader = nullptr;
		IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
		BYTE* pTargetBase = nullptr;

		std::ifstream dllFile(m_data->dllPath, std::ios::binary | std::ios::ate);
		if (dllFile.fail())
		{
			LOG(3, L"Unable to load DLL file. %08X", (DWORD)dllFile.rdstate());
			return 0;
		}

		auto fileSize = dllFile.tellg();
		if (fileSize < 0x1000)
		{
			LOG(3, L"Invalid file size");
			dllFile.close();
			return 0;
		}

		pSrcData = new BYTE[SCast<UINT_PTR>(fileSize)];
		if (!pSrcData)
		{
			LOG(3, L"Memory allocation failed for loading DLL.");
			dllFile.close();
			return 0;
		}
		
		dllFile.seekg(0, std::ios::beg);
		dllFile.read(RCast<char*>(pSrcData), fileSize);
		dllFile.close();

		if (RCast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) // "MZ"
		{
			LOG(3, L"Invalid File type.");
			delete[] pSrcData;
			return 0;
		}
		pOldDOSHeader = RCast<IMAGE_DOS_HEADER*>(pSrcData);
		pOldNtHeader = RCast<IMAGE_NT_HEADERS*>(pSrcData + pOldDOSHeader->e_lfanew);
		pOldOptHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		pTargetBase = RCast<BYTE*>(VirtualAllocEx(hProc, RCast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			pTargetBase = RCast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (!pTargetBase)
			{
				LOG(3, L"Failed to allocate memory in remote process.Error: %s", GetLastErrorAsString(GetLastError()));
				delete[] pSrcData;
				return 0;
			}
		}

		MANUAL_MAPPING_DATA data{ 0 };
		data.pGetProcAddress = RCast<f_GetProcAddress>(GetProcAddress);
		data.pLoadLibraryA = LoadLibraryA;

		auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; i++, pSectionHeader++)
		{
			if (pSectionHeader->SizeOfRawData)
			{
				if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
				{
					LOG(3, L"Unable to WriteProcessMemory. Error: %s", GetLastErrorAsString(GetLastError()));
					delete[] pSrcData;
					VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
					return 0;
				}
			}
		}

		memcpy(pSrcData, &data, sizeof(data));
		WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

		delete[] pSrcData;

		return pTargetBase;
	}

	return 0;
}

LPVOID nightshade::Injection::CreateEntryPoint(LPVOID lpMemAddress, HANDLE hProc)
{
	if (m_data->injMethod == InjMethod::IM_LoadLibraryEx)
	{
		HMODULE hKernel32 = GetModuleHandle("Kernel32");
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
		LPVOID pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode)
		{
			LOG(3, L"Failed to allocate memory in remote process. Error: %s", GetLastErrorAsString(GetLastError()));
			Cleanup(nullptr, lpMemAddress, hProc);
			return 0;
		}

		if (WriteProcessMemory(hProc, pShellcode, LdrLoadDllShellcode, 0x52 * 1.5, nullptr)) { //0x52 is the exact size of the compiled function, we'll pad with 1.5x bytes
			return pShellcode;
		}
	}
	else if (m_data->injMethod == InjMethod::IM_ManualMap)
	{
		LPVOID pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode)
		{
			LOG(3, L"Failed to allocate memory in remote process. Error: %s", GetLastErrorAsString(GetLastError()));
			Cleanup(nullptr, lpMemAddress, hProc);
			return 0;
		}

		if(WriteProcessMemory(hProc, pShellcode, ManualMapShellcode, 0x1C8 * 1.5, nullptr)) { //0x1C8 is the exact size of the compiled function, we'll pad with 1.5x bytes
			return pShellcode;
		}
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
		return didQueueAPC;
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
