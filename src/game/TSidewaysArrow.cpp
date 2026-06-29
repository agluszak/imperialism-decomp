#include "game/TSidewaysArrow.h"

#include "decomp_types.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_widget_thunks.h"

extern "C" char g_pClassDescTSidewaysArrow = 0;

undefined4 GetTickCountDiv16(void);

// FUNCTION: IMPERIALISM 0x00583bd0
void TSidewaysArrow::HandleTradeArrowAutoRepeatTickAndDispatch(int repeatState, void* arg8,
                                                               void* argC, void* dispatchArg,
                                                               void* arg14) {
  reinterpret_cast<TControl*>(this)->DispatchPictureResourceCommand(repeatState, arg8, argC, arg14);

  if (repeatState == 2) {
    return;
  }

  typedef unsigned int(__cdecl * GetTickCountDiv16Proc)(void);
  unsigned int tick = reinterpret_cast<GetTickCountDiv16Proc>(GetTickCountDiv16)();
  if (tick < (unsigned int)(repeatDeadlineTick + 5)) {
    return;
  }

  tick = reinterpret_cast<GetTickCountDiv16Proc>(GetTickCountDiv16)();
  repeatDeadlineTick = (int)tick;
  if (repeatState == 0) {
    repeatDeadlineTick = (int)tick + 10;
  }

  if (this->PointInBoundsAndActionable(reinterpret_cast<CPoint*>(dispatchArg)) == '\0') {
    return;
  }

  if (this->controlTag == kControlTagRght) {
    this->DispatchEvent(100, 0, 0);
    return;
  }

  this->DispatchEvent(0x65, this, 0);
}
