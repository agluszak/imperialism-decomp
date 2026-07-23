#include "game/ui_screens/TSidewaysArrow.h"
#include "game/ui_tags_common.h"

#include "decomp_types.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x00583a90
// TSidewaysArrow::CreateObject

// SYNTHETIC: IMPERIALISM 0x00583b30
// TSidewaysArrow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSidewaysArrow, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x00583b50
TSidewaysArrow::TSidewaysArrow() : TUpDownPictureButton() {
  repeatDeadlineTick = 0;
}

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583bd0
void TSidewaysArrow::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, unsigned char commandFlag) {
  TUpDownPictureButton::TrackMouse(phase, startPoint, previousPoint, currentPoint, commandFlag);

  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int tick = GetTickCountDiv16();
  if (tick < (unsigned int)(repeatDeadlineTick + 5)) {
    return;
  }

  tick = GetTickCountDiv16();
  repeatDeadlineTick = (int)tick;
  if (phase == kTrackPhaseBegin) {
    repeatDeadlineTick = (int)tick + 10;
  }

  CPoint* point = &currentPoint;
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (this->controlTag == kControlTagRght) {
    this->HandleEvent(100, this, nullptr);
    return;
  }

  this->HandleEvent(101, this, nullptr);
}

// SYNTHETIC: IMPERIALISM 0x00583b80
// TSidewaysArrow::`scalar deleting destructor'
