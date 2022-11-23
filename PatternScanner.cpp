#include "PatternScanner.h"


nightshade::PatternScanner::PatternScanner(uintptr_t addr, size_t scanSize)
{
	m_startAddress = addr;
	m_scanSize = scanSize;
}

nightshade::PatternScanner::~PatternScanner()
{
	m_unsolvedPatterns.clear();
	m_solvedPatterns.clear();
}

void nightshade::PatternScanner::addPattern(const char* patternID, const char* pattern, size_t length)
{
	Pattern patternData = {};
	patternData.length = length;
	patternData.pattern = pattern;
	m_unsolvedPatterns.emplace(patternID, patternData);
}

void nightshade::PatternScanner::scan()
{
	LOG(1, L"Starting pattern scan, starting at 0x%08X with scan size of %d bytes...", m_startAddress, m_scanSize);
	nightshade::Utils::Timer timer;
	timer.start();
	for (uintptr_t i = m_startAddress; i < (m_startAddress + m_scanSize); i++)
	{
		if (m_unsolvedPatterns.size() == 0)
			break;


		for (auto it = m_unsolvedPatterns.cbegin(); it != m_unsolvedPatterns.cend(); )
		{
			
			bool found = true;
			for (int j = 0; j < it->second.length; j++)
			{
				if (it->second.pattern[j] != '?' && it->second.pattern[j] != '\x00' && it->second.pattern[j] != *(char*)((uintptr_t)i + j))
				{
					found = false; 
					break;
				}
			}

			if (found)
			{
				LOG(1, L"Solved pattern '%s' -> 0x%08X", nightshade::Utils::CStringToWString(it->first).c_str(), i);
				m_solvedPatterns.emplace(it->first, i);
				it = m_unsolvedPatterns.erase(it);
			}
			else {
				it++;
			}
		}
	}

	for (auto it = m_unsolvedPatterns.begin(); it != m_unsolvedPatterns.end(); it++)
	{
		LOG(1, L"Unsolved pattern '%s'", nightshade::Utils::CStringToWString(it->first));
	}
	LOG(1, L"Scan completed in %ldms. %d\\%d solved patterns.", timer.stop(), solvedSize(), (solvedSize() + unsolvedSize()));
}

uintptr_t nightshade::PatternScanner::getResult(const char* patternID)
{
	auto element = m_solvedPatterns.find(patternID);
	if (element == m_solvedPatterns.end())
		return 0;

	return element->second;
}

void nightshade::PatternScanner::clearResults()
{
	m_solvedPatterns.clear();
}

void nightshade::PatternScanner::clearUnsolved()
{
	m_unsolvedPatterns.clear();
}

size_t nightshade::PatternScanner::solvedSize()
{
	return m_solvedPatterns.size();
}

size_t nightshade::PatternScanner::unsolvedSize()
{
	return m_unsolvedPatterns.size();
}
