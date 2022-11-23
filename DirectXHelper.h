#pragma once
#include <d3d9.h>
#include <D3D11.h>
#include "Utils.h"

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3d11.lib")

#define NS_DX_END_SCENE_BYTES 7
#define NS_DX_PRESENT_BYTES 5
#define NS_DX_STEAM_PRESENT_BYTES 6

#define NS_DX_ENDSCENE_INDEX 42
#define NS_DX_PRESENT_INDEX 17


typedef HRESULT(_stdcall* f_EndScene)(IDirect3DDevice9* pDevice);
f_EndScene origEndscene = nullptr;

typedef HRESULT(_stdcall* f_Present)(IDirect3DDevice9* pDevice, const RECT* pSourceRect, const RECT* pDestRect, HWND hDestWindowOverride, const RGNDATA* pDirtyRegion);
f_Present origPresent = nullptr;

namespace nightshade {
	namespace DX {
		static HWND window;

		inline BOOL CALLBACK EnumWindowsCallback(HWND handle, LPARAM lParam)
		{
			DWORD wndProcId;
			GetWindowThreadProcessId(handle, &wndProcId);

			if (GetCurrentProcessId() != wndProcId)
				return TRUE; // skip to next window

			window = handle;
			return FALSE; // window found abort search
		}

		inline HWND GetProcessWindow()
		{
			window = NULL;
			EnumWindows(EnumWindowsCallback, NULL);
			return window;
		}

		inline bool GetD3D9DeviceVTable(void** vTable, size_t size)
		{
			IDirect3D9* pD3D = Direct3DCreate9(D3D_SDK_VERSION);
			if (!pD3D)
				return false;

			IDirect3DDevice9* pDummyDevice = nullptr;

			D3DPRESENT_PARAMETERS d3dPP = { 0 };
			d3dPP.Windowed = false;
			d3dPP.SwapEffect = D3DSWAPEFFECT_DISCARD;
			d3dPP.hDeviceWindow = GetProcessWindow();

			HRESULT deviceCreated = pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, d3dPP.hDeviceWindow, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &d3dPP, &pDummyDevice);

			if (deviceCreated != S_OK)
			{
				d3dPP.Windowed = true;
				HRESULT deviceCreated = pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, d3dPP.hDeviceWindow, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &d3dPP, &pDummyDevice);

				if (deviceCreated != S_OK)
				{
					pD3D->Release();
					return false;
				}
			}
			LOG(1, L"D3D9 Device VTable -> 0x%08X", *RCast<void***>(pDummyDevice));
			memcpy(vTable, *RCast<void***>(pDummyDevice), size);

			pDummyDevice->Release();
			pD3D->Release();
			return true;
		}

		inline bool GetD3D11DeviceAndSwapChainVTable(void** deviceVTable, size_t deviceSize, void** swapChainVTable, size_t swapChainSize)
		{
			IDXGISwapChain* dummySwapChain;
			ID3D11Device* dummyDevice;
			ID3D11DeviceContext* dummyDeviceContext;

			DXGI_SWAP_CHAIN_DESC scDesc = { 0 };
			scDesc.BufferDesc.RefreshRate.Numerator = 0;
			scDesc.BufferDesc.RefreshRate.Denominator = 1;
			scDesc.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
			scDesc.SampleDesc.Count = 1;
			scDesc.SampleDesc.Quality = 0;
			scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
			scDesc.BufferCount = 1;
			scDesc.OutputWindow = GetProcessWindow();
			scDesc.Windowed = true;

			HRESULT result = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_SINGLETHREADED, NULL, 0, D3D11_SDK_VERSION, &scDesc, &dummySwapChain, &dummyDevice, nullptr, &dummyDeviceContext);
			if (result != S_OK)
			{
				scDesc.Windowed = false;
				result = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_SINGLETHREADED, NULL, 0, D3D11_SDK_VERSION, &scDesc, &dummySwapChain, &dummyDevice, nullptr, &dummyDeviceContext);
				if (result != S_OK)
				{
					return false;
				}
			}

			memcpy(deviceVTable, *RCast<void***>(dummyDevice), deviceSize);
			memcpy(swapChainVTable, *RCast<void***>(dummySwapChain), swapChainSize);


			dummySwapChain->Release();
			dummyDevice->Release();
			dummyDeviceContext->Release();
			return true;
		}
	}
}