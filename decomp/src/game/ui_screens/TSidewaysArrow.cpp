#include "game/ui_screens/TSidewaysArrow.h"
#include "game/ui_tags_common.h"

#include "decomp_types.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"

IMPLEMENT_DYNCREATE(TSidewaysArrow, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x00583b50
TSidewaysArrow::TSidewaysArrow() {
  repeatDeadlineTick = 0;
}

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583bd0
void TSidewaysArrow::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, bool commandFlag) {
  TUpDownPictureButton::TrackMouse(phase, startPoint, previousPoint, currentPoint, commandFlag);

  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int tick = GetTickCountDiv16();
  if (tick < static_cast<unsigned int>(repeatDeadlineTick + 5)) {
    return;
  }

  tick = GetTickCountDiv16();
  repeatDeadlineTick = static_cast<int>(tick);
  if (phase == kTrackPhaseBegin) {
    repeatDeadlineTick = static_cast<int>(tick) + 10;
  }

  CPoint* point = &currentPoint;
  if (!PointInBoundsAndActionable(point)) {
    return;
  }

  if (controlTag == kControlTagRght) {
    HandleEvent(100, this, NULL);
    return;
  }

  HandleEvent(101, this, NULL);
}
