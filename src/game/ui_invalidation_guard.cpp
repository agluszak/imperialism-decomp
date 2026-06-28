#include "game/ui_invalidation_guard.h"

#include "game/mfc.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x004868c0
int __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode) {
  (void)nTaskPumpMode;
  MSG msg;
  bool continueIdle = true;
  LONG idleCount = 0;
  do {
    if (PeekMessageA(&msg, nullptr, 0, 0, PM_NOREMOVE) != 0) {
      break;
    }
    CWinThread* thread = AfxGetThread();
    if (thread == nullptr || !thread->OnIdle(idleCount)) {
      continueIdle = false;
    }
    idleCount = idleCount + 1;
  } while (continueIdle);

  CWinThread* thread = AfxGetThread();
  if (thread == nullptr) {
    return 0;
  }
  if (thread->IsIdleMessage(&msg)) {
    return 1;
  }
  return static_cast<int>(thread->PumpMessage());
}

// FUNCTION: IMPERIALISM 0x0049d620
undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
  return 0;
}
