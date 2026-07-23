#include "game/ui_core/ui_timing.h"

#include "game/mfc.h"

#include <mmsystem.h>

// FUNCTION: IMPERIALISM 0x00493200
void BusyWaitUntilShiftedTickDeadline(int tickCount, int* deadline) {
  *deadline = static_cast<int>(timeGetTime() >> 4) + tickCount;
  while (static_cast<int>(timeGetTime() >> 4) < *deadline) {
  }
}

// FUNCTION: IMPERIALISM 0x005c3b40
void WaitForSixteenthSecondTicks(int tickCount) {
  BusyWaitUntilShiftedTickDeadline(tickCount, &tickCount);
}
