#pragma once
#include <chrono>

namespace nightshade {
	namespace Utils {
		class Timer {
		public:
			Timer() = default;

			void start()
			{
				m_startClock = std::chrono::steady_clock::now();
			}

			long long stop()
			{
				std::chrono::time_point<std::chrono::steady_clock> endClock = std::chrono::steady_clock::now();
				std::chrono::milliseconds difference = std::chrono::duration_cast<std::chrono::milliseconds>(endClock - m_startClock);
				return difference.count();
			}

		private:
			std::chrono::time_point<std::chrono::steady_clock> m_startClock;
		};
	}
}