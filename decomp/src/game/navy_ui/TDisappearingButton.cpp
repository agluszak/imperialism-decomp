#include "game/navy_ui/TDisappearingButton.h"

IMPLEMENT_DYNCREATE(TDisappearingButton, TPicture)

// FUNCTION: IMPERIALISM 0x00568bc0
TDisappearingButton::TDisappearingButton() {}

// FUNCTION: IMPERIALISM 0x00568c20
TDisappearingButton::~TDisappearingButton() {}

// FUNCTION: IMPERIALISM 0x00568c40
void TDisappearingButton::HiliteState(unsigned char fEnabledState, bool fRefreshNow) {
  if (controlState != fEnabledState) {
    controlState = fEnabledState;
    Show(fEnabledState == 0, true);
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
