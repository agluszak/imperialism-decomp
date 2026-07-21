#include "game/TUpDownView.h"
// SYNTHETIC: IMPERIALISM 0x00583c90
// TUpDownView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00583d30
// TUpDownView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUpDownView, TControl)

#include "game/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583d50
TUpDownView::TUpDownView() : TControl(), timingDword84(0) {}

// SYNTHETIC: IMPERIALISM 0x00583d80
// TUpDownView::`scalar deleting destructor'
TUpDownView::~TUpDownView() {}

// FUNCTION: IMPERIALISM 0x00583dd0
void TUpDownView::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                                 void* pEventDataA, void* pEventDataB,
                                                 int nCommandFlag) {
  (void)pEventSender;
  (void)pEventDataA;
  (void)nCommandFlag;
  if (nEventType == 2) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < (unsigned int)(this->timingDword84 + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  this->timingDword84 = now;
  if (nEventType == 0) {
    this->timingDword84 = now + 10;
  }

  CPoint* point = static_cast<CPoint*>(pEventDataB);
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (point->y <= this->frameHeight38 / 2) {
    this->HandleEvent(100, this, nullptr);
  } else {
    this->HandleEvent(101, this, nullptr);
  }
}
