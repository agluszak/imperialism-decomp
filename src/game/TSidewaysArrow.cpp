#include "game/TSidewaysArrow.h"

#include "decomp_types.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_widget_thunks.h"

IMPLEMENT_DYNCREATE(TSidewaysArrow, TUpDownPictureButton)

undefined4 GetTickCountDiv16(void);

// FUNCTION: IMPERIALISM 0x00583bd0
void TSidewaysArrow::DispatchPictureResourceCommand(int eventType, void* eventSender,
                                                    void* eventDataA, void* eventDataB) {
  TControl::DispatchPictureResourceCommand(eventType, eventSender, eventDataA, eventDataB);

  if (eventType == 2) {
    return;
  }

  typedef unsigned int(__cdecl * GetTickCountDiv16Proc)(void);
  unsigned int tick = reinterpret_cast<GetTickCountDiv16Proc>(GetTickCountDiv16)();
  if (tick < (unsigned int)(repeatDeadlineTick + 5)) {
    return;
  }

  tick = reinterpret_cast<GetTickCountDiv16Proc>(GetTickCountDiv16)();
  repeatDeadlineTick = (int)tick;
  if (eventType == 0) {
    repeatDeadlineTick = (int)tick + 10;
  }

  if (this->PointInBoundsAndActionable(reinterpret_cast<CPoint*>(eventDataB)) == '\0') {
    return;
  }

  if (this->controlTag == kControlTagRght) {
    this->DispatchEvent(100, 0, 0);
    return;
  }

  this->DispatchEvent(0x65, this, 0);
}
