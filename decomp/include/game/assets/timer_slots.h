#pragma once

#include "game/mfc.h"

// Ten-slot Win32 timer registry used by audio; a callback returning 0 kills its timer.

typedef bool(__cdecl* TimerSlotCallback)();

void CALLBACK TimerSlotProc(HWND hwnd, UINT msg, UINT idEvent, DWORD dwTime);
