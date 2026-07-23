#include "game/navy_ui/TDisappearingButton.h"
// SYNTHETIC: IMPERIALISM 0x00568b20
// TDisappearingButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00568ba0
// TDisappearingButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDisappearingButton, TPicture)

// FUNCTION: IMPERIALISM 0x00568bc0
TDisappearingButton::TDisappearingButton() {}

// SYNTHETIC: IMPERIALISM 0x00568bf0
// TDisappearingButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00568c20
TDisappearingButton::~TDisappearingButton() {}

// FUNCTION: IMPERIALISM 0x00568c40
void TDisappearingButton::HiliteState(unsigned char fEnabledState, unsigned char fRefreshNow) {
  if (controlState64 != fEnabledState) {
    controlState64 = fEnabledState;
    SetEnabled(fEnabledState == 0, true);
    if (fRefreshNow) {
      DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00568c90
void TDisappearingButton::DrawImmediate() {
  CRect bounds;
  RedrawWindow(nativeWindow50->m_hWnd, GetQDExtent(&bounds), NULL, RDW_INVALIDATE | RDW_UPDATENOW);
}
