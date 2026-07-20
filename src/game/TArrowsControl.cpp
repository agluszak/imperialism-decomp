#include "game/TArrowsControl.h"
// SYNTHETIC: IMPERIALISM 0x005838b0
// TArrowsControl::CreateObject

// SYNTHETIC: IMPERIALISM 0x00583950
// TArrowsControl::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArrowsControl, TPicture)

#include "game/TAmbitApplication.h"

// FUNCTION: IMPERIALISM 0x00583970
TArrowsControl::TArrowsControl() : TPicture(), timingDword90(0) {}

// SYNTHETIC: IMPERIALISM 0x005839a0
// TArrowsControl::`scalar deleting destructor'
TArrowsControl::~TArrowsControl() {}

// FUNCTION: IMPERIALISM 0x005839f0
void TArrowsControl::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                                    void* pEventDataA, void* pEventDataB,
                                                    int nCommandFlag) {
  (void)pEventSender;
  (void)pEventDataA;
  (void)nCommandFlag;
  if (nEventType == 2) {
    return;
  }

  unsigned int ticks = GetTickCountDiv16();
  if (ticks < (unsigned int)(this->timingDword90 + 5)) {
    return;
  }

  unsigned int now = GetTickCountDiv16();
  this->timingDword90 = now;
  if (nEventType == 0) {
    this->timingDword90 = now + 10;
  }

  CPoint* point = static_cast<CPoint*>(pEventDataB);
  if (!this->PointInBoundsAndActionable(point)) {
    return;
  }

  if (point->y <= this->frameHeight38 / 2) {
    this->DispatchEvent(100, this, nullptr);
  } else {
    this->DispatchEvent(101, this, nullptr);
  }
}
