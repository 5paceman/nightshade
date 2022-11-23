#include "DrawHelper.h"
#ifndef _WIN64


void nightshade::D3D9Draw::DrawString(int x, int y, DWORD color, DWORD Format, LPD3DXFONT pFont, const wchar_t* string)
{
    RECT FontPos = { x, y, x + 120, y + 16 };
    pFont->DrawTextW(NULL, string, wcslen(string), &FontPos, Format, color);
}

void nightshade::D3D9Draw::DrawStringVA(int x, int y, DWORD color, DWORD Format, LPD3DXFONT pFont, const char* string, ...)
{
    va_list va;
    char formattedMessage[400];
    va_start(va, string);
    vsnprintf(formattedMessage, 400, string, va);
    va_end(va, message);
    DrawString(x, y, color, Format, pFont, formattedMessage);
}

void nightshade::D3D9Draw::DrawString(int x, int y, DWORD color, DWORD Format, LPD3DXFONT pFont, const char* string)
{
    RECT FontPos = { x, y, x + 120, y + 16 };
    pFont->DrawText(NULL, string, strlen(string), &FontPos, Format, color);
}

void nightshade::D3D9Draw::DrawShadowedString(int x, int y, DWORD color, LPD3DXFONT pFont, const char* string)
{
    D3D9Draw::DrawString(x + 1, y + 1, D3DCOLOR_ARGB(200, 25, 25, 25), DT_NOCLIP, pFont, string);
    D3D9Draw::DrawString(x, y, color, DT_NOCLIP, pFont, string);
}

void nightshade::D3D9Draw::DrawCShadowedString(int x, int y, DWORD color, LPD3DXFONT pFont, const char* string)
{
    D3D9Draw::DrawString(x + 1, y + 1, D3DCOLOR_ARGB(200, 25, 25, 25), DT_CENTER, pFont, string);
    D3D9Draw::DrawString(x, y, color, DT_CENTER, pFont, string);
}

int nightshade::D3D9Draw::GetTextWidth(const wchar_t* szText, LPD3DXFONT pFont)
{
    RECT rcRect = { 0,0,0,0 };
    pFont->DrawTextW(NULL, szText, -1, &rcRect, DT_CALCRECT, D3DCOLOR_XRGB(0, 0, 0));

    return rcRect.right - rcRect.left;
}

int nightshade::D3D9Draw::GetTextHeight(const wchar_t* szText, LPD3DXFONT pFont)
{
    RECT rcRect = { 0,0,0,0 };
    pFont->DrawTextW(NULL, szText, -1, &rcRect, DT_CALCRECT, D3DCOLOR_XRGB(0, 0, 0));

    return rcRect.right - rcRect.left;
}

void nightshade::D3D9Draw::BoxFilled(LPDIRECT3DDEVICE9 d3Dev, float x, float y, float w, float h, D3DCOLOR color)
{
    struct Vertex
    {
        float x, y, z, ht;
        DWORD Color;
    }
    V[4] = { {x, y + h, 0.0f, 0.0f, color}, { x, y, 0.0f, 0.0f, color }, { x + w, y + h, 0.0f, 0.0f, color }, { x + w, y, 0.0f, 0.0f, color } };
    d3Dev->SetTexture(0, NULL);
    d3Dev->SetPixelShader(0);
    d3Dev->SetFVF(D3DFVF_XYZRHW | D3DFVF_DIFFUSE);
    d3Dev->SetRenderState(D3DRS_ALPHABLENDENABLE, true);
    d3Dev->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    d3Dev->SetRenderState(D3DRS_ZENABLE, FALSE);
    d3Dev->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
    d3Dev->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, V, sizeof(Vertex));
    return;
}

void nightshade::D3D9Draw::Line(LPDIRECT3DDEVICE9 d3Dev, float x1, float y1, float x2, float y2, float width, bool antialias, D3DCOLOR color)
{
    ID3DXLine* m_Line;

    D3DXCreateLine(d3Dev, &m_Line);
    D3DXVECTOR2 line[] = { D3DXVECTOR2(x1, y1), D3DXVECTOR2(x2, y2) };
    m_Line->SetWidth(width);
    if (antialias)
        m_Line->SetAntialias(1);
    m_Line->Begin();
    m_Line->Draw(line, 2, color);
    m_Line->End();
    m_Line->Release();
}

void nightshade::D3D9Draw::Box(LPDIRECT3DDEVICE9 d3Dev, float x, float y, float w, float h, float linewidth, D3DCOLOR color)
{
    if (linewidth == 0 || linewidth == 1)
    {
        BoxFilled(d3Dev, x, y, w, 1, color);             // Top
        BoxFilled(d3Dev, x, y + h - 1, w, 1, color);         // Bottom
        BoxFilled(d3Dev, x, y + 1, 1, h - 2 * 1, color);       // Left
        BoxFilled(d3Dev, x + w - 1, y + 1, 1, h - 2 * 1, color);   // Right
    }
    else
    {
        BoxFilled(d3Dev, x, y, w, linewidth, color);                                     // Top
        BoxFilled(d3Dev, x, y + h - linewidth, w, linewidth, color);                         // Bottom
        BoxFilled(d3Dev, x, y + linewidth, linewidth, h - 2 * linewidth, color);               // Left
        BoxFilled(d3Dev, x + w - linewidth, y + linewidth, linewidth, h - 2 * linewidth, color);   // Right
    }
}


void nightshade::D3D9Draw::BorderedBox(LPDIRECT3DDEVICE9 d3Dev, float x, float y, float w, float h, float width, D3DCOLOR boxColor, D3DCOLOR borderColor)
{
    BoxFilled(d3Dev, x, y, w, h, boxColor);
    Box(d3Dev, x - width, y - width, w + 2 * width, h + width, width, borderColor);
}

#endif