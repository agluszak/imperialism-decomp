#include "game/TRightLeftView.h"
#include "game/TControl.h"

// FUNCTION: IMPERIALISM 0x00583f10
CRuntimeClass* TRightLeftView::GetRuntimeClass() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00583f60
// TRightLeftView::`scalar deleting destructor'
TRightLeftView::~TRightLeftView() {}

// FUNCTION: IMPERIALISM 0x00583f30
TRightLeftView* TRightLeftView::ConstructTRightLeftViewBaseState() {
  TControl::TControl();
  *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x84) = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x00583fb0
void TRightLeftView::DispatchPictureResourceCommand(int nEventType, void * pEventSender, void * pEventDataA, void * pEventDataB) {
}
