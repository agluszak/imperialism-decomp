#include "game/ui_screens/TUpDownView.h"

IMPLEMENT_DYNCREATE(TUpDownView, TControl)

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583d50
TUpDownView::TUpDownView() : repeatTick(0) {}

// FUNCTION: IMPERIALISM 0x00583db0
TUpDownView::~TUpDownView() {}

// FUNCTION: IMPERIALISM 0x00583dd0
void TUpDownView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
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

  if (point->y <= frameHeight / 2) {
    HandleEvent(100, this, NULL);
  } else {
    HandleEvent(101, this, NULL);
  }
}
