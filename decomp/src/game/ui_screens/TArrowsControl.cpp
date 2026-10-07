#include "game/ui_screens/TArrowsControl.h"

IMPLEMENT_DYNCREATE(TArrowsControl, TPicture)

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583970
TArrowsControl::TArrowsControl() : nextRepeatTick(0) {}

// FUNCTION: IMPERIALISM 0x005839d0
TArrowsControl::~TArrowsControl() {}

// FUNCTION: IMPERIALISM 0x005839f0
void TArrowsControl::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, bool commandFlag) {
  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < static_cast<unsigned int>(nextRepeatTick + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  nextRepeatTick = now;
  if (phase == kTrackPhaseBegin) {
    nextRepeatTick = now + 10;
  }

  CPoint* point = &currentPoint;
  if (!PointInBoundsAndActionable(point)) {
    return;
  }

  if (point->y <= frameHeight / 2) {
    HandleEvent(100, this, NULL);
  } else {
    HandleEvent(101, this, NULL);
  }
}
