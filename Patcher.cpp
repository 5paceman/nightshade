#include "Patcher.h"
#include "Utils.h"

nightshade::Patcher::Patcher(uintptr_t addr, const char* shellcode, size_t size)
{
	m_size = size;
	m_addr = addr;
	m_shellcode = shellcode;
	m_savedBytes = new char[size];
	m_hasPatched = false;
	memcpy(m_savedBytes, RCast<void*>(m_addr), m_size);

}

nightshade::Patcher::~Patcher()
{
	delete[] m_savedBytes;

}

bool nightshade::Patcher::patch()
{
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	if (VirtualQuery(RCast<void*>(m_addr), &memInfo, sizeof(memInfo)))
	{
		if (memInfo.Protect & PAGE_GUARD || memInfo.Protect == PAGE_NOACCESS)
			return false;

		DWORD oldProtect, tempProtect;
		if (VirtualProtect(RCast<void*>(m_addr), m_size, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			memcpy(RCast<void*>(m_addr), m_shellcode, m_size);
			m_hasPatched = true;
			if (VirtualProtect(RCast<void*>(m_addr), m_size, oldProtect, &tempProtect))
			{
				LOG(1, L"Patched at 0x%08X.", m_addr);
				return true;
			}
			else {
				LOG(2, L"Patched at 0x%08X however unable to restore page protection.", m_addr);
				return true;
			}
		}
	}
	
	LOG(2, L"Unable to VirtualQuery at 0x%08X.", m_addr);
	return false;
}

bool nightshade::Patcher::restore()
{
	DWORD oldProtect, tempProtect;
	if (VirtualProtect(RCast<void*>(m_addr), m_size, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		memcpy(RCast<void*>(m_addr), m_savedBytes, m_size);
		m_hasPatched = false;
		if (VirtualProtect(RCast<void*>(m_addr), m_size, oldProtect, &tempProtect))
		{
			return true;
		}
		else {
			LOG(2, L"Restored patch at 0x%08X however unable to restore page protection.");
			return true;
		}
	}
	return false;
}

const char* nightshade::Patcher::getShellcode()
{
	return m_shellcode;
}

size_t nightshade::Patcher::size()
{
	return m_size;
}
