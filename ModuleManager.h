#pragma once
#include <vector>
#include "Module.h"


namespace nightshade {
	class ModuleManager {
	private:
		std::vector<std::shared_ptr<HModule>> modules;


	public:
		void addModule(std::shared_ptr<HModule> mod)
		{
			modules.push_back(mod);
		}

		bool isModEnabled(const char* modName)
		{
			for (auto it = modules.begin(); it != modules.end(); it++)
			{
				if (strcmp(it->get()->getName(), modName) == 0)
				{
					return it->get()->isEnabled();
				}
			}
		}

		void onPreInit(nightshade::PatternScanner& patternScanner)
		{
			for (auto it = modules.begin(); it != modules.end(); it++)
			{
				it->get()->onPreInit(patternScanner);
			}
		}

		void onPostInit(nightshade::PatternScanner& patternScanner)
		{
			for (auto it = modules.begin(); it != modules.end(); it++)
			{
				it->get()->onPostInit(patternScanner);
			}
		}

		void onDraw()
		{
			for (auto it = modules.begin(); it != modules.end(); it++)
			{
				it->get()->onDraw();
			}
		}

		void onUpdate()
		{
			for (auto it = modules.begin(); it != modules.end(); it++)
			{
				if (GetAsyncKeyState(it->get()->getKeybind()))
					it->get()->toggle();

				it->get()->onUpdate();
			}
		}

		int getModuleCount()
		{
			return modules.size();
		}

		void clear()
		{
			modules.clear();
		}

		std::vector<std::shared_ptr<HModule>>::iterator begin()
		{
			return modules.begin();
		}

		std::vector<std::shared_ptr<HModule>>::iterator end()
		{
			return modules.end();
		}

		std::vector<std::shared_ptr<HModule>>::const_iterator begin() const
		{
			return modules.begin();
		}

		std::vector<std::shared_ptr<HModule>>::const_iterator end() const
		{
			return modules.end();
		}
	};
}