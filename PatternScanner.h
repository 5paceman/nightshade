#pragma once
#include "Logger.h"
#include "Utils.h"

#include <windows.h>
#include <vector>
#include <map>

namespace nightshade {

	class PatternScanner {
	public:
		PatternScanner(uintptr_t addr, size_t scanSize);
		~PatternScanner();

	public:
		void addPattern(const char* patternID, const char* pattern, size_t length);
		void scan();
		uintptr_t getResult(const char* patternID);

	public:
		void clearResults();
		void clearUnsolved();
		size_t solvedSize();
		size_t unsolvedSize();

	private:
		struct Pattern {
			const char* pattern;
			size_t length;
		};

	private:
		std::map<std::string, Pattern> m_unsolvedPatterns;
		std::map<std::string, uintptr_t> m_solvedPatterns;
		uintptr_t m_startAddress;
		size_t m_scanSize;

	

	};
}