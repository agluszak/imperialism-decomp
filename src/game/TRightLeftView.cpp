#include "game/TRightLeftView.h"
#include "game/TControl.h"
// SYNTHETIC: IMPERIALISM 0x00583e70
// TRightLeftView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00583f10
// TRightLeftView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRightLeftView, TControl)

// SYNTHETIC: IMPERIALISM 0x00583f60
// TRightLeftView::`scalar deleting destructor'
TRightLeftView::~TRightLeftView() {}

#include "game/TAmbitApplication.h"
#include "game/ui_tags_common.h"

// FUNCTION: IMPERIALISM 0x00583f30
TRightLeftView::TRightLeftView() : TControl(), timingDword84(0) {}

// FUNCTION: IMPERIALISM 0x00583fb0
void TRightLeftView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, unsigned char commandFlag) {
  (void)startPoint;
  (void)previousPoint;
  (void)commandFlag;
  if (phase == kTrackPhaseEnd) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < (unsigned int)(this->timingDword84 + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  this->timingDword84 = now;
  if (phase == kTrackPhaseBegin) {
    this->timingDword84 = now + 10;
  }

  CPoint* point = &currentPoint;
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (this->controlTag == kControlTagRght) {
    this->HandleEvent(100, this, nullptr);
  } else {
    this->HandleEvent(101, this, nullptr);
  }
}
