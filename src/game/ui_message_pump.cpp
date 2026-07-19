#include "game/ui_message_pump.h"

#include "game/mfc.h"

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
