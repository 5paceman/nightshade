#pragma once
#include <functional>
#include <vector>
#include <ostream>

#include <Windows.h>
#include <format>
#include <format>

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
			msg.insert(0, L"[INFO] ");
			break;
		case 2:
			msg.insert(0, L"[WARNING] ");
			break;
		case 3:
			msg.insert(0, L"[ERROR] ");
		}

		for (std::function<void(const wchar_t*)> callback : callbacks)
		{
			callback(msg.c_str());
		}
	}
};