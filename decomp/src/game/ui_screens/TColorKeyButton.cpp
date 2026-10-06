#include "game/ui_screens/TColorKeyButton.h"
#include "game/ui_core/TWindow.h"

IMPLEMENT_DYNCREATE(TColorKeyButton, TColorKeyPicture)

// FUNCTION: IMPERIALISM 0x00571f70
TColorKeyButton::TColorKeyButton() {}

// FUNCTION: IMPERIALISM 0x00571fd0
TColorKeyButton::~TColorKeyButton() {}

// FUNCTION: IMPERIALISM 0x00571ff0
void TColorKeyButton::HiliteState(unsigned char fEnabledState, bool fRefreshNow) {
  if (controlState != fEnabledState) {
    controlState = fEnabledState;
    short pictureId =
        fEnabledState ? static_cast<short>(glyphBase + 1) : static_cast<short>(glyphBase - 1);
    SetPictureRsrcID(pictureId, true);
    if (fRefreshNow) {
      DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00572060
void TColorKeyButton::DrawImmediate() {
  GetWindow()->ForceRedraw();
}
