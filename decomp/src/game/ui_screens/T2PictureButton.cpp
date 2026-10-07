#include "game/ui_screens/T2PictureButton.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(T2PictureButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x00570bb0
T2PictureButton::T2PictureButton() : TPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570c10
T2PictureButton::~T2PictureButton() {}

// FUNCTION: IMPERIALISM 0x00570c30
void T2PictureButton::SetAvailability(char isAvailable, char refreshNow) {
  short pictureId = glyphBase;
  short alternatePictureId = controlValue;
  if ((isAvailable == 1 && pictureId > controlValue) ||
      (isAvailable == 0 && pictureId < controlValue)) {
    SetPictureRsrcID(alternatePictureId, false);
    controlValue = pictureId;
    ViewEnable(isAvailable, false);
    Show(!isAvailable, refreshNow);
  }
}
