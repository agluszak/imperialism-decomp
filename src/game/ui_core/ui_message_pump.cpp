#include "game/ui_core/ui_message_pump.h"

#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x004868c0
int __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode) {
  (void)nTaskPumpMode;
  MSG msg;
  int continueIdle = 1;
  LONG idleCount = 0;
  do {
    if (PeekMessageA(&msg, nullptr, 0, 0, PM_NOREMOVE) != 0) {
      break;
    }
    LONG currentIdleCount = idleCount;
    ++idleCount;
    if (AfxGetApp()->OnIdle(currentIdleCount) == 0) {
      continueIdle = 0;
    }
  } while (continueIdle);

  if (AfxGetApp()->IsIdleMessage(&msg) != 0) {
    return 1;
  }
  return static_cast<int>(AfxGetApp()->PumpMessage());
}
