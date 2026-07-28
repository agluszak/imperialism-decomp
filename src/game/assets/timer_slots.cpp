#include "game/assets/timer_slots.h"

#include "game/globals/global_types.h"
#include "game/globals/assets_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

TimerSlotCallback g_timerSlotCallbacks[10]; // 0x006a5cf8
UINT g_timerSlotIds[10];                    // 0x006a5c98
int g_timerDispatchSuppressAssert;          // 0x006a5d24

// FUNCTION: IMPERIALISM 0x005e0460
void CALLBACK DispatchWAssetMgrPeriodicCallbackAndStopInactiveTimerSlot(HWND hwnd, UINT msg,
                                                                        UINT idEvent,
                                                                        DWORD dwTime) {
  (void)hwnd;
  (void)msg;
  (void)dwTime;
  int slot = static_cast<int>(idEvent) - 0xa000;
  if (slot < 0 || slot >= 10 || g_timerSlotCallbacks[slot] == NULL) {
    if (g_timerDispatchSuppressAssert == 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\WAssetMgr.cpp", 0x263);
    }
    return;
  }

  if (g_timerSlotCallbacks[slot]() == 0) {
    CWnd* mainWnd;
    if (AfxGetThread() == NULL) {
      mainWnd = NULL;
    } else {
      mainWnd = AfxGetThread()->GetMainWnd();
    }
    ::KillTimer(mainWnd->m_hWnd, g_timerSlotIds[slot]);
    g_timerSlotIds[slot] = 0;
    g_timerSlotCallbacks[slot] = NULL;
  }
}
