#pragma once
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>
#include "Utils.h"

#pragma comment(lib, "dinput8.lib")
#pragma comment(lib, "dxguid.lib")

#define NS_DI_GET_DEVICE_DATA_INDEX 10
#define NS_DI_GET_DEVICE_DATA_INDEX 12
#define NS_DS_CREATE_DEVICE_INDEX 2

#define NS_DS_STEAM_GET_DEVICE_DATA_BYTES 6
#define NS_DS_GET_DEVICE_DATA_BYTES 5

#define NS_DS_KB_DELAY 2

typedef HRESULT(WINAPI* f_GetDeviceData)(IDirectInputDevice8*, DWORD cbObjectData, LPDIDEVICEOBJECTDATA rgdod, LPDWORD pdwInOut, DWORD dwFlags);
f_GetDeviceData origDeviceData = nullptr;

namespace nightshade {
	namespace DInput {
		inline bool GetDInputVTable(void** vTable, size_t size)
		{
			HINSTANCE hInst = (HINSTANCE)GetModuleHandle(NULL);
			IDirectInput8* pDirectInput = NULL;

			HRESULT result = DirectInput8Create(hInst, DIRECTINPUT_VERSION, IID_IDirectInput8, (LPVOID*)&pDirectInput, NULL);
			if (result != DI_OK)
			{
				LOG(2, L"Unable to create IDirectInput8, Error: %ld", result);
				return false;
			}

			LOG(1, L"IDirectInput8 VTable -> 0x%08X", *RCast<void***>(pDirectInput));
			memcpy(vTable, *RCast<void***>(pDirectInput), size);
			pDirectInput->Release();
			return true;

			return false;
		}

		inline uintptr_t GetDInputDeviceVTableAddr()
		{
			HINSTANCE hInst = (HINSTANCE)GetModuleHandle(NULL);
			IDirectInput8* pDirectInput = NULL;

			HRESULT result = DirectInput8Create(hInst, DIRECTINPUT_VERSION, IID_IDirectInput8, (LPVOID*)&pDirectInput, NULL);
			if (result != DI_OK)
			{
				LOG(2, L"Unable to create IDirectInputDevice8, Error: %ld", result);
				return false;
			}

			LPDIRECTINPUTDEVICE8  lpdiKeyboard;
			result = pDirectInput->CreateDevice(GUID_SysKeyboard, &lpdiKeyboard, NULL);
			if (result != DI_OK)
			{
				LOG(2, L"Unable to create IDirectInputDevice8, Error: %ld", result);
				pDirectInput->Release();
				return false;
			}
			uintptr_t vTableAddr = *RCast<uintptr_t*>(lpdiKeyboard);
			LOG(1, L"IDirectInputDevice8 VTable -> 0x%08X", vTableAddr);
			return vTableAddr;
		}

		inline bool GetDInputDeviceVTable(void** vTable, size_t size)
		{
			HINSTANCE hInst = (HINSTANCE)GetModuleHandle(NULL);
			IDirectInput8* pDirectInput = NULL;

			HRESULT result = DirectInput8Create(hInst, DIRECTINPUT_VERSION, IID_IDirectInput8, (LPVOID*)&pDirectInput, NULL);
			if (result != DI_OK)
			{
				LOG(2, L"Unable to create IDirectInputDevice8, Error: %ld", result);
				return false;
			}

			LPDIRECTINPUTDEVICE8  lpdiKeyboard;
			result = pDirectInput->CreateDevice(GUID_SysKeyboard, &lpdiKeyboard, NULL);
			if (result != DI_OK)
			{
				LOG(2, L"Unable to create IDirectInputDevice8, Error: %ld", result);
				pDirectInput->Release();
				return false;
			}

			LOG(1, L"IDirectInputDevice8 VTable -> 0x%08X", *RCast<void***>(lpdiKeyboard));
			memcpy(vTable, *RCast<void***>(lpdiKeyboard), size);
			return true;
		}

		DWORD lastTime = 0;

		inline bool canPollKeyboard(LPDIDEVICEOBJECTDATA device)
		{
			if (lastTime == 0)
			{
				lastTime = device->dwTimeStamp;
				return true;
			}
			
			bool result = (lastTime + NS_DS_KB_DELAY) <= device->dwTimeStamp;
			if (result)
			{
				lastTime = device->dwTimeStamp;
			}
			return result;

		}

		inline Vector2 getMousePosition(LPDIDEVICEOBJECTDATA device, LPDWORD pdwInOut)
		{
			Vector2 result = {};
			for (DWORD d = 0; d < *pdwInOut; d++)
			{
				if (LOBYTE(device[d].dwData) > 0)
				{
					if (device[d].dwOfs == DIMOFS_X)
					{
						result.x = device[d].dwData;
					}
					else if (device[d].dwOfs == DIMOFS_Y)
					{
						result.y = device[d].dwData;
					}
				}
			}
			return result;
		}

		inline bool isKeyPressed(DWORD key, LPDIDEVICEOBJECTDATA device, LPDWORD pdwInOut)
		{
			bool result = false;
			for (DWORD d = 0; d < *pdwInOut; d++)
			{
				if (LOBYTE(device[d].dwData) > 0)
				{
					if (device[d].dwOfs == key)
					{
						result = true;
					}
				}
			}

			return result;
		}
	}
}