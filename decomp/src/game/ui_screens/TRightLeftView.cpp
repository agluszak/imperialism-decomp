#include "game/ui_screens/TRightLeftView.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TControl.h"

IMPLEMENT_DYNCREATE(TRightLeftView, TControl)

// FUNCTION: IMPERIALISM 0x00583f30
TRightLeftView::TRightLeftView() : TControl(), repeatTick(0) {}

// FUNCTION: IMPERIALISM 0x00583f90
TRightLeftView::~TRightLeftView() {}

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583fb0
void TRightLeftView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, bool commandFlag) {
  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < static_cast<unsigned int>(repeatTick + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  repeatTick = now;
  if (phase == kTrackPhaseBegin) {
    repeatTick = now + 10;
  }

  CPoint* point = &currentPoint;
  if (!PointInBoundsAndActionable(point)) {
    return;
  }

  if (controlTag == kControlTagRght) {
    HandleEvent(100, this, NULL);
  } else {
    HandleEvent(101, this, NULL);
  }
}
