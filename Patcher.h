#pragma once
#include <Windows.h>

namespace nightshade {
	class Patcher {
	public:
		Patcher(uintptr_t addr, const char* shellcode, size_t size);
		~Patcher();

	public:
		bool patch();
		bool restore();
		const char* getShellcode();
		size_t size();

	private:
		uintptr_t m_addr;
		char* m_savedBytes;
		const char* m_shellcode;
		size_t m_size;
		bool m_hasPatched;
	};
}