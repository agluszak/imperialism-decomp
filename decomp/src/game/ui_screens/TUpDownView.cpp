#include "game/ui_screens/TUpDownView.h"

IMPLEMENT_DYNCREATE(TUpDownView, TControl)

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583d50
TUpDownView::TUpDownView() : TControl(), repeatTick(0) {}

// FUNCTION: IMPERIALISM 0x00583db0
TUpDownView::~TUpDownView() {}

// FUNCTION: IMPERIALISM 0x00583dd0
void TUpDownView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                             CPoint& currentPoint, bool commandFlag) {
  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < (unsigned int)(this->repeatTick + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  this->repeatTick = now;
  if (phase == kTrackPhaseBegin) {
    this->repeatTick = now + 10;
  }

  CPoint* point = &currentPoint;
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (point->y <= this->frameHeight / 2) {
    this->HandleEvent(100, this, nullptr);
  } else {
    this->HandleEvent(101, this, nullptr);
  }
}
