#pragma once
#include <Windows.h>


enum class InjMethod {
	IM_LoadLibraryEx,
	IM_LdrLoadDll,
	IM_ManualMap,
	IM_NONE
};

struct WindowEnumData
{
	DWORD pid;
	HWND hWnd;
};

enum class RemoteExecMethod {
	RE_NtCreateThreadEx,
	RE_HijackThread,
	RE_QueueUserAPC,
	RE_NONE
};

enum class Architecture {
	X64,
	x86,
	UNKNOWN
};

struct Vector2 {
	float x, y;
};

struct Vector3 {
	float x, y, z;
};

struct Vector4 {
	float x, y, z, w;
};