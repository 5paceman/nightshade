#pragma once
#include <functional>
#include <vector>
#include <ostream>

#include <Windows.h>
#include <iostream>

#define LOG(i, a, ...) Logger::getInstance().Log(i, a, __VA_ARGS__)

class Logger {
private:
	Logger() {}

	Logger(const Logger&) = delete;
	Logger& operator= (const Logger&) = delete;

public:
	std::vector<std::function<void(const wchar_t*)>> callbacks;

public:
	static Logger& getInstance()
	{
		static Logger instance;
		return instance;
	}

	void registerLogCallback(std::function<void(const wchar_t*)> callback)
	{
		callbacks.push_back(callback);
	}

	BOOL AllocateConsole()
	{
		bool hasAllocConsole = false;
		hasAllocConsole = AllocConsole();
		if (!hasAllocConsole)
		{
			FreeConsole();
			hasAllocConsole = AllocConsole();
		}
		
		if(hasAllocConsole){
			FILE* f;
			freopen_s(&f, "CONOUT$", "w", stdout);

			registerCout();
		}

		return hasAllocConsole;
	}

	void registerCout()
	{
		auto consoleCallback = [](const wchar_t* msg) {
			std::wcout << msg << std::endl;
		};
		this->registerLogCallback(consoleCallback);
	}

	void Log(int level, const wchar_t* message, ...)
	{
		va_list va;
		wchar_t formattedMessage[400];
		va_start(va, message);
		vswprintf(formattedMessage, 400, message, va);
		va_end(va, message);
		std::wstring msg(formattedMessage);
		
		switch (level)
		{
		case 1:
			msg.insert(0, L"[!] ");
			break;
		case 2:
			msg.insert(0, L"[!!] ");
			break;
		case 3:
			msg.insert(0, L"[!!!] ");
		}

		for (std::function<void(const wchar_t*)> callback : callbacks)
		{
			callback(msg.c_str());
		}
	}

	void PrintLogo(const wchar_t* gameName)
	{
		const wchar_t* logo[] = {
			L"    _   ___       __    __       __              __   ",
			L"   / | / (_)___ _/ /_  / /______/ /_  ____ _____/ /__ ",
			L"  /  |/ / / __ `/ __ \\/ __/ ___/ __ \\/ __ `/ __  / _ \\",
			L" / /|  / / /_/ / / / / /_(__  ) / / / /_/ / /_/ /  __/",
			L"/_/ |_/_/\\__, /_/ /_/\\__/____/_/ /_/\\__,_/\\__,_/\\___/ ",
			L"        /____/                                        ",
			L"                                                      "
		};

		for (int i = 0; i < 7; i++)
		{
			LOG(0, logo[i]);
		}
		LOG(0, L"  Game: %s  By: 5paceman\n", gameName);
	}
};