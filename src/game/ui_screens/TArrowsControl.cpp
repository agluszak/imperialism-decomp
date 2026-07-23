#include "game/ui_screens/TArrowsControl.h"
// SYNTHETIC: IMPERIALISM 0x005838b0
// TArrowsControl::CreateObject

// SYNTHETIC: IMPERIALISM 0x00583950
// TArrowsControl::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArrowsControl, TPicture)

#include "game/gfx/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583970
TArrowsControl::TArrowsControl() : TPicture(), timingDword90(0) {}

// SYNTHETIC: IMPERIALISM 0x005839a0
// TArrowsControl::`scalar deleting destructor'
TArrowsControl::~TArrowsControl() {}

// FUNCTION: IMPERIALISM 0x005839f0
void TArrowsControl::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, unsigned char commandFlag) {
  (void)startPoint;
  (void)previousPoint;
  (void)commandFlag;
  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < (unsigned int)(this->timingDword90 + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  this->timingDword90 = now;
  if (phase == kTrackPhaseBegin) {
    this->timingDword90 = now + 10;
  }

  CPoint* point = &currentPoint;
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (point->y <= this->frameHeight38 / 2) {
    this->HandleEvent(100, this, nullptr);
  } else {
    this->HandleEvent(101, this, nullptr);
  }
}
