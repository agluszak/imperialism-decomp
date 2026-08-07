#include "game/ui_core/ui_message_pump.h"

#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x004868c0
char __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode) {
  (void)nTaskPumpMode;
  MSG msg;
  int continueIdle = 1;
  LONG idleCount = 0;
  while (continueIdle != 0 && PeekMessageA(&msg, nullptr, 0, 0, PM_NOREMOVE) == 0) {
    LONG currentIdleCount = idleCount;
    ++idleCount;
    if (AfxGetApp()->OnIdle(currentIdleCount) == 0) {
      continueIdle = 0;
    }
  }

  if (AfxGetApp()->PumpMessage() == 0) {
    return AfxGetApp()->ExitInstance();
  }
  return 1;
}
