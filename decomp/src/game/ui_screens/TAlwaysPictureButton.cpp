#include "game/ui_screens/TAlwaysPictureButton.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TAlwaysPictureButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x005709f0
TAlwaysPictureButton::TAlwaysPictureButton() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// FUNCTION: IMPERIALISM 0x00570a50
TAlwaysPictureButton::~TAlwaysPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570a70
void TAlwaysPictureButton::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  if (static_cast<unsigned char>(enabledState) != this->controlState64) {
    this->controlState64 = enabledState;
    short pictureId;
    if (enabledState == 0) {
      pictureId = this->glyphBase84 + 100;
    } else {
      pictureId = this->glyphBase84 - 100;
    }
    this->SetPictureResourceIdAndRefresh(pictureId, true);
    if (refreshNow) {
      this->DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00570ae0
void TAlwaysPictureButton::Select(bool isPressed, bool notifyParent) {
  this->Show(isPressed, notifyParent);
}
