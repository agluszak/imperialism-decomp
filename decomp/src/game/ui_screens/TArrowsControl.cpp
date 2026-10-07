#include "game/ui_screens/TArrowsControl.h"

IMPLEMENT_DYNCREATE(TArrowsControl, TPicture)

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583970
TArrowsControl::TArrowsControl() : TPicture(), nextRepeatTick(0) {}

// FUNCTION: IMPERIALISM 0x005839d0
TArrowsControl::~TArrowsControl() {}

// FUNCTION: IMPERIALISM 0x005839f0
void TArrowsControl::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, bool commandFlag) {
  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < (unsigned int)(this->nextRepeatTick + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  this->nextRepeatTick = now;
  if (phase == kTrackPhaseBegin) {
    this->nextRepeatTick = now + 10;
  }

  CPoint* point = &currentPoint;
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (point->y <= this->frameHeight / 2) {
    this->HandleEvent(100, this, NULL);
  } else {
    this->HandleEvent(101, this, NULL);
  }
}
