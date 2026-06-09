#pragma once

typedef unsigned int u32;
typedef void* hwnd_t;
typedef u32 hmenu_t;

extern "C" u32 __stdcall SendMessageA(hwnd_t hWnd, u32 msg, u32 wParam, int lParam);
extern "C" u32 __stdcall CheckMenuItem(hmenu_t hMenu, u32 itemId, u32 flags);

class CCmdUI {
public:
  void SetCheck(u32 checked_state);
};
