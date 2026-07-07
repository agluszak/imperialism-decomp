#include "game/TSidewaysArrow.h"

#include "decomp_types.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_widget_thunks.h"

// SYNTHETIC: IMPERIALISM 0x00583a90
// TSidewaysArrow::CreateObject

// SYNTHETIC: IMPERIALISM 0x00583b30
// TSidewaysArrow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSidewaysArrow, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x00583b50
TSidewaysArrow::TSidewaysArrow() : TUpDownPictureButton() {
  repeatDeadlineTick = 0;
}

#include "game/startup_helpers.h"

// FUNCTION: IMPERIALISM 0x00583bd0
void TSidewaysArrow::DispatchPictureResourceCommand(int eventType, void* eventSender,
                                                    void* eventDataA, void* eventDataB,
                                                    int commandFlag) {
  TUpDownPictureButton::DispatchPictureResourceCommand(eventType, eventSender, eventDataA, eventDataB,
                                                       commandFlag);

  if (eventType == 2) {
    return;
  }

  unsigned int tick = GetTickCountDiv16();
  if (tick < (unsigned int)(repeatDeadlineTick + 5)) {
    return;
  }

  tick = GetTickCountDiv16();
  repeatDeadlineTick = (int)tick;
  if (eventType == 0) {
    repeatDeadlineTick = (int)tick + 10;
  }

  CPoint* point = static_cast<CPoint*>(eventDataB);
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (this->controlTag == kControlTagRght) {
    this->DispatchEvent(100, this, nullptr);
    return;
  }

  this->DispatchEvent(101, this, nullptr);
}

// SYNTHETIC: IMPERIALISM 0x00583b80
// TSidewaysArrow::`scalar deleting destructor'
