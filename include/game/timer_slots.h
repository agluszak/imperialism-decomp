#pragma once

#include "game/mfc.h"

// A tiny 10-slot Win32 timer registry used by the audio subsystem. Each slot holds a
// callback and a live timer id; the shared TIMERPROC (0x5e0460) dispatches WM_TIMER by
// mapping the timer id back to its slot (id = slot + 0xa000) and kills the timer when the
// callback returns 0 ("done").

// Slot callback: returns non-zero to keep the timer running, 0 to have the dispatcher stop
// and clear the slot. The dispatcher tests AL, so this is an actual byte result rather than
// the old undefined4 placeholder.
typedef char(__cdecl* TimerSlotCallback)();

// The registry globals (g_timerSlotCallbacks @0x006a5cf8, g_timerSlotIds @0x006a5c98,
// g_timerDispatchSuppressAssert @0x006a5d24) are declared in game/global_data_tables.h.

// 0x005e0460 — WM_TIMER dispatcher shared by all slots (passed as the TIMERPROC).
void CALLBACK DispatchWAssetMgrPeriodicCallbackAndStopInactiveTimerSlot(HWND hwnd, UINT msg,
                                                                        UINT idEvent, DWORD dwTime);
