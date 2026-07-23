#include "game/TColorKeyButton.h"
#include "game/TWindow.h"
// SYNTHETIC: IMPERIALISM 0x00571ed0
// TColorKeyButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00571f50
// TColorKeyButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TColorKeyButton, TColorKeyPicture)

// FUNCTION: IMPERIALISM 0x00571f70
TColorKeyButton::TColorKeyButton() {}

// SYNTHETIC: IMPERIALISM 0x00571fa0
// TColorKeyButton::`scalar deleting destructor'
TColorKeyButton::~TColorKeyButton() {}

// FUNCTION: IMPERIALISM 0x00571ff0
void TColorKeyButton::HiliteState(unsigned char fEnabledState, unsigned char fRefreshNow) {
  if (controlState64 != fEnabledState) {
    controlState64 = fEnabledState;
    short pictureId =
        fEnabledState ? static_cast<short>(glyphBase84 + 1) : static_cast<short>(glyphBase84 - 1);
    SetPictureResourceIdAndRefresh(pictureId, true);
    if (fRefreshNow) {
      DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00572060
void TColorKeyButton::DrawImmediate() {
  GetWindow()->ForceRedraw();
}
