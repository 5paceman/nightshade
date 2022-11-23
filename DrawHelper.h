#pragma once
#include <d3d9.h>
#include <D3D11.h>
#include <iostream>

#pragma comment(lib, "d3d9.lib")


#ifndef _WIN64
#include <d3dx9.h>
#include <D3DX11.h>
#pragma comment(lib, "d3dx9.lib")
#pragma comment(lib, "d3dx11.lib")

#endif

namespace nightshade{
#ifndef _WIN64
	class D3D9Draw
	{
	public:
        static void DrawString(int x, int y, DWORD color, DWORD Format, LPD3DXFONT pFont, const wchar_t* string);
        static void DrawStringVA(int x, int y, DWORD color, DWORD Format, LPD3DXFONT pFont, const char* string, ...);
        static void DrawString(int x, int y, DWORD color, DWORD Format, LPD3DXFONT pFont, const char* string);
        static void DrawShadowedString(int x, int y, DWORD color, LPD3DXFONT pFont, const char* string);
        static void DrawCShadowedString(int x, int y, DWORD color, LPD3DXFONT pFont, const char* string);
        static int GetTextWidth(const wchar_t* szText, LPD3DXFONT pFont);
        static int GetTextHeight(const wchar_t* szText, LPD3DXFONT pFont);
        static void Line(LPDIRECT3DDEVICE9 d3Dev, float x1, float y1, float x2, float y2, float width, bool antialias, D3DCOLOR color);
        static void Box(LPDIRECT3DDEVICE9 d3Dev, float x, float y, float w, float h, float linewidth, D3DCOLOR color);
        static void BorderedBox(LPDIRECT3DDEVICE9 d3Dev, float x, float y, float w, float h, float width, D3DCOLOR boxColor, D3DCOLOR borderColor);
        static void BoxFilled(LPDIRECT3DDEVICE9 d3Dev, float x, float y, float w, float h, D3DCOLOR color);
	};
#endif
    class D3D11Draw
    {

    };
}