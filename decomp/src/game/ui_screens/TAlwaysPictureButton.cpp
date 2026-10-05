#include "game/ui_screens/TAlwaysPictureButton.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TAlwaysPictureButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x005709f0
TAlwaysPictureButton::TAlwaysPictureButton() : TPictureButton() {}


// FUNCTION: IMPERIALISM 0x00570a50
TAlwaysPictureButton::~TAlwaysPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570a70
void TAlwaysPictureButton::HiliteState(unsigned char enabledState, bool refreshNow) {
  if (static_cast<unsigned char>(enabledState) != this->controlState64) {
    this->controlState64 = enabledState;
    short pictureId;
    if (enabledState == 0) {
      pictureId = this->glyphBase84 + 100;
    } else {
      pictureId = this->glyphBase84 - 100;
    }
    this->SetPictureRsrcID(pictureId, true);
    if (refreshNow) {
      this->DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00570ae0
void TAlwaysPictureButton::Select(bool isPressed, bool notifyParent) {
  this->Show(isPressed, notifyParent);
}
