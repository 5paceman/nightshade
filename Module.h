#pragma once
#include <WinUser.h>
#include "PatternScanner.h"
#include "Logger.h"

namespace nightshade {
	class HModule {
	public:
		HModule() {};
		~HModule() {};

	public:
		virtual const char* getName() = 0;
		virtual int getKeybind() = 0;
		
	public:
		virtual void onPreInit(nightshade::PatternScanner& patternScanner) = 0;
		virtual void onPostInit(nightshade::PatternScanner& patternScanner) = 0;
		virtual void onEnable() = 0;
		virtual void onDisable() = 0;
		virtual void onDraw() = 0;
		virtual void onUpdate() = 0;

		void toggle()
		{
			LOG(1, L"Toggled %s from: %s to: %s", "", this->m_enabled ? L"true" : L"false", !this->m_enabled ? L"true" : L"false");
			this->m_enabled = !this->m_enabled;
			if (this->m_enabled)
				this->onEnable();
			else
				this->onDisable();
		}

		bool isEnabled()
		{
			return this->m_enabled;
		}
	protected:
		bool m_enabled = false;

	};
}