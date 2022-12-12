#include "Injection.h"
#include "Shellcode.h"


nightshade::Injection::Injection(InjectionData* data)
{
	this->m_data = data;
	if (wcslen(m_data->dllPath) == 0)
	{
		LOG(1, L"DLL Path is empty.");
	}
	
	NtQueryInformationThread = nightshade::Utils::GetNTFunc<fNtQueryInformationThread>("NtQueryInformationThread");
	NtSetInformationThread = nightshade::Utils::GetNTFunc<fNtSetInformationThread>("NtSetInformationThread");
	NtGetContextThread = nightshade::Utils::GetNTFunc<fNtGetContextThread>("NtGetContextThread");
	NtSetContextThread = nightshade::Utils::GetNTFunc<fNtSetContextThread>("NtSetContextThread");
	NtCreateThreadEx = nightshade::Utils::GetNTFunc<fNtCreateThreadEx>("NtCreateThreadEx");

	if (!NtQueryInformationThread || !NtSetInformationThread || !NtGetContextThread || !NtSetContextThread || !NtCreateThreadEx)
	{
		LOG(3, L"Unable to get ntdll functions. Functionality may be limited.");
	}
}

nightshade::Injection::~Injection()
{
	
}

bool nightshade::Injection::Inject()
{
	if (nightshade::Utils::IsElevatedProcess())
	{
		HANDLE hProc = GetProcHandle();
		if (hProc)
		{
			Architecture arch = nightshade::Utils::GetDLLArchitecture(m_data->dllPath);
			m_data->is64bit = (arch == Architecture::X64);
			if (nightshade::Utils::IsDllCompatible(arch, hProc))
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
			LOG(3, L"Unable to get handle on process, error: %s", nightshade::Utils::GetLastErrorAsString(GetLastError()).c_str());
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
	return OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, m_data->pID);
}

LPVOID nightshade::Injection::AllocateAndWriteMemory(HANDLE hProc)
{
	if (m_data->injMethod == InjMethod::IM_LoadLibraryEx)
	{
		LPVOID lpDLLPathAddr = VirtualAllocEx(hProc, nullptr, sizeof(m_data->dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpDLLPathAddr)
		{
			LOG(1, L"Allocated Memory at 0x%08X", lpDLLPathAddr);
			SIZE_T bytesWritten = 0;
			if (WriteProcessMemory(hProc, lpDLLPathAddr, m_data->dllPath, sizeof(m_data->dllPath), &bytesWritten))
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
		uintptr_t LdrLoadDllPtr = nightshade::Utils::GetProcAddressEx(hProc, L"ntdll", "LdrLoadDll");
		uintptr_t RtlInitUnicodeStringPtr = nightshade::Utils::GetProcAddressEx(hProc, L"ntdll", "RtlInitUnicodeString");
		if (LdrLoadDllPtr == 0 || RtlInitUnicodeStringPtr == 0)
		{
			LOG(3, L"Unable to get func ptrs for LdrLoadDll data.");
			return 0;
		}
		data.pLdrLoadDll = RCast<f_LdrLoadDll>(LdrLoadDllPtr);
		data.pRtlInitUnicodeString = RCast<f_RtlInitUnicodeString>(RtlInitUnicodeStringPtr);
		
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
						LOG(3, L"Unable to Write Process memory, Error %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
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
				LOG(3, L"Unable to Write Process memory, Error %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
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
				LOG(3, L"Failed to allocate memory in remote process.Error: %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
				delete[] pSrcData;
				return 0;
			}
		}
		

		if (!m_data->is64bit)
		{
			MANUAL_MAPPING_DATA32 data{ 0 };
			data.flags = m_data->flags;
			data.pGetProcAddress = nightshade::Utils::GetProcAddressEx(hProc, L"Kernel32", "GetProcAddress");
			data.pLoadLibraryA = nightshade::Utils::GetProcAddressEx(hProc, L"Kernel32", "LoadLibraryA");
			memcpy(pSrcData, &data, sizeof(data));
		}
#ifdef _WIN64
		else {
			MANUAL_MAPPING_DATA64 data{ 0 };
			data.flags = m_data->flags;
			data.pGetProcAddress = nightshade::Utils::GetProcAddressEx(hProc, L"Kernel32", "GetProcAddress");
			data.pLoadLibraryA = nightshade::Utils::GetProcAddressEx(hProc, L"Kernel32", "LoadLibraryA");
			data.pRtlAddFunctionTable = nightshade::Utils::GetProcAddressEx(hProc, L"Kernel32", "RtlAddFunctionTable");
			memcpy(pSrcData, &data, sizeof(data));
		}
#endif
		

		auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; i++, pSectionHeader++)
		{
			if (pSectionHeader->SizeOfRawData)
			{
				if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
				{
					LOG(3, L"Unable to WriteProcessMemory. Error: %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
					delete[] pSrcData;
					VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
					return 0;
				}
			}
		}

		
		WriteProcessMemory(hProc, pTargetBase, pSrcData, pOldNtHeader->OptionalHeader.SizeOfHeaders, nullptr);
		LOG(1, L"DLL Mapped in at 0x%08X for 0x%08X bytes.", pTargetBase, fileSize);
		delete[] pSrcData;

		return pTargetBase;
	}

	return 0;
}


LPVOID nightshade::Injection::CreateEntryPoint(LPVOID lpMemAddress, HANDLE hProc)
{
	if (m_data->injMethod == InjMethod::IM_LoadLibraryEx)
	{
		uintptr_t LoadLibraryAPtr = nightshade::Utils::GetProcAddressEx(hProc, L"Kernel32", "LoadLibraryW");
		if (LoadLibraryAPtr != 0) {
			return RCast<LPVOID>(LoadLibraryAPtr);
		}
		else {
			Cleanup(nullptr, lpMemAddress, hProc);
			LOG(3, L"Not able to get func addr for LoadLibraryW");
		}
	}
	else if (m_data->injMethod == InjMethod::IM_LdrLoadDll)
	{
		LPVOID pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode)
		{
			LOG(3, L"Failed to allocate memory in remote process. Error: %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
			Cleanup(nullptr, lpMemAddress, hProc);
			return 0;
		}

		if (WriteProcessMemory(hProc, pShellcode, m_data->is64bit ? x64LdrLoadDllShellcode : x32LdrLoadDllShellcode, m_data->is64bit ? sizeof(x64LdrLoadDllShellcode) : sizeof(x32LdrLoadDllShellcode), nullptr)) {
			return pShellcode;
		}
	}
	else if (m_data->injMethod == InjMethod::IM_ManualMap)
	{
		LPVOID pShellcode = VirtualAllocEx(hProc, nullptr, m_data->is64bit ? sizeof(x64ManualMapShellcode) : sizeof(x32ManualMapShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode)
		{
			LOG(3, L"Failed to allocate memory in remote process. Error: %s", nightshade::Utils::GetLastErrorAsString(GetLastError()));
			Cleanup(nullptr, lpMemAddress, hProc);
			return 0;
		}

		if (WriteProcessMemory(hProc, pShellcode, m_data->is64bit ? x64ManualMapShellcode : x32ManualMapShellcode, m_data->is64bit ? sizeof(x64ManualMapShellcode) : sizeof(x32ManualMapShellcode), nullptr)) {
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
	if (nightshade::Utils::GetThreadsFromProcess(GetProcessId(hProc), tIDs)) {
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

struct NtCreateThreadExBuffer
{
	SIZE_T Size;
	SIZE_T Unknown1;
	SIZE_T Unknown2;
	PULONG Unknown3;
	void* Unknown4;
	SIZE_T Unknown5;
	SIZE_T Unknown6;
	PULONG Unknown7;
	void* Unknown8;
};

bool nightshade::Injection::RENtCreateThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc)
{
	if (!nightshade::Utils::AdjustPriviledges(hProc))
	{
		LOG(3, L"Failed to elevate priviledges");
		return false;
	}

	HANDLE hThread;

	NtCreateThreadExBuffer ntbuffer;

	memset(&ntbuffer, 0, sizeof(ntbuffer));
	ULONG temp0[2];
	ULONG temp1;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = sizeof(temp0);
	ntbuffer.Unknown3 = temp0;
	ntbuffer.Unknown4 = nullptr;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = sizeof(temp1);
	ntbuffer.Unknown7 = &temp1;
	ntbuffer.Unknown8 = nullptr;

	NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc, (m_data->flags & CLOAK_THREAD) ? 0 : lpEntryPoint, lpMemoryAddress, (m_data->flags & CLOAK_THREAD) ? 0x1 : NULL /* Suspended */, 0, 0, 0, nullptr);
	if (NT_SUCCESS(status))
	{
		if (m_data->flags & CLOAK_THREAD)
		{
			if (HideThreadFromDebugger(hThread, hProc))
			{
				LOG(1, L"Sucessfully hidden thread from debugger.");
			}
			else {
				LOG(2, L"Unable to hide thread from debugger. Skipping...");
			}

			if (HideThreadStartAddress(hThread, lpEntryPoint, hProc))
			{
				LOG(1, L"Sucessfully hidden start address for thread.");
			}
			else {
				LOG(3, L"Unable to hide start address for thread.");
				return false;
			}
			ResumeThread(hThread);
		}
		DWORD waitResult = WaitForSingleObject(hThread, INFINITE);
		if (waitResult == WAIT_OBJECT_0) //TODO dont infinite wait
		{
			DWORD returnValue = 0;
			if (GetExitCodeThread(hThread, &returnValue))
			{
				LOG(1, L"Remote thread returned 0x%08X", returnValue);
			}
			CloseHandle(hThread);
			return true;
		}
		else {
			LOG(2, L"Couldnt wait for thread to terminate. Thread wait returned %d, DLL possibly injected.", waitResult);
		}
	}
	else {
		LOG(3, L"Unable to create thread with NtCreateThreadEx. NTSTATUS: 0x%08X", status);
	}
	return false;
}

bool nightshade::Injection::REHijackThread(LPVOID lpEntryPoint, LPVOID lpMemoryAddress, HANDLE hProc)
{
	return false;
}

bool nightshade::Injection::HideThreadFromDebugger(HANDLE hThread, HANDLE hProc)
{
	NTSTATUS status = NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);
	return NT_SUCCESS(status);
}

bool nightshade::Injection::HideThreadStartAddress(HANDLE hThread, LPVOID lpEntryPoint, HANDLE hProc)
{
	fNtQueryInformationThread fQIT = nightshade::Utils::GetNTFunc<fNtQueryInformationThread>("NtQueryInformationThread");
	fNtSetInformationThread fSIT = nightshade::Utils::GetNTFunc<fNtSetInformationThread>("NtSetInformationThread");
	fNtGetContextThread fGCT = nightshade::Utils::GetNTFunc<fNtGetContextThread>("NtGetContextThread");
	fNtSetContextThread fSCT = nightshade::Utils::GetNTFunc<fNtSetContextThread>("NtSetContextThread");

	if (!m_data->is64bit)
	{
		WOW64_CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_ALL;
		NTSTATUS status = NtQueryInformationThread(hThread, ThreadWow64Context, &ctx, sizeof(ctx), nullptr);

		if (NT_FAIL(status))
		{
			LOG(2, L"Unable to get WOW64_CONTEXT with NtQueryInformationThread");
			return false;
		}

		ctx.Eax = RCast<DWORD>(lpEntryPoint);

		status = NtSetInformationThread(hThread, ThreadWow64Context, &ctx, sizeof(ctx));

		return NT_SUCCESS(status);
	}
#ifdef _WIN64
	else {
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_ALL;
		NTSTATUS status = NtGetContextThread(hThread, &ctx);

		if (NT_FAIL(status))
		{
			LOG(2, L"Unable to get CONTEXT with NtQueryInformationThread");
			return false;
		}

		ctx.Rax = RCast<DWORD64>(lpEntryPoint);

		status = NtSetContextThread(hThread, &ctx);

		return NT_SUCCESS(status);
	}
#endif
	return false;
}

