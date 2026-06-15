#pragma once

#include <windows.h>

// Minimal CWnd layout for MFC API interop (HWND at +0x1c matches TViewNativeWindow).
class CWnd {
public:
  char pad_00[0x1c];
  HWND m_hWnd;
};
