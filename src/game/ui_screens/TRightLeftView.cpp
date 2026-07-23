#include "game/ui_screens/TRightLeftView.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TControl.h"
// SYNTHETIC: IMPERIALISM 0x00583e70
// TRightLeftView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00583f10
// TRightLeftView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRightLeftView, TControl)

// FUNCTION: IMPERIALISM 0x00583f30
TRightLeftView::TRightLeftView() : TControl(), timingDword84(0) {}

// SYNTHETIC: IMPERIALISM 0x00583f60
// TRightLeftView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00583f90
TRightLeftView::~TRightLeftView() {}

#include "game/gfx/TAmbitApplication.h"

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
