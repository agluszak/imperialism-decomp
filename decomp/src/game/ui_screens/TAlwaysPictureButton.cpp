#include "game/ui_screens/TAlwaysPictureButton.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TAlwaysPictureButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x005709f0
TAlwaysPictureButton::TAlwaysPictureButton() : TPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570a50
TAlwaysPictureButton::~TAlwaysPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570a70
void TAlwaysPictureButton::HiliteState(unsigned char enabledState, bool refreshNow) {
  if (static_cast<unsigned char>(enabledState) != controlState) {
    controlState = enabledState;
    short pictureId;
    if (enabledState == 0) {
      pictureId = glyphBase + 100;
    } else {
      pictureId = glyphBase - 100;
    }
    SetPictureRsrcID(pictureId, true);
    if (refreshNow) {
      DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00570ae0
void TAlwaysPictureButton::Select(bool isPressed, bool notifyParent) {
  Show(isPressed, notifyParent);
}
