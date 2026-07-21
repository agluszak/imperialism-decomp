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

// FUNCTION: IMPERIALISM 0x00583f30
TRightLeftView::TRightLeftView() : TControl(), timingDword84(0) {}

// FUNCTION: IMPERIALISM 0x00583fb0
void TRightLeftView::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
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

  if (this->controlTag == 0x72676874) {
    this->HandleEvent(100, this, nullptr);
  } else {
    this->HandleEvent(101, this, nullptr);
  }
}
