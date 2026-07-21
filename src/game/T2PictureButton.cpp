#include "game/T2PictureButton.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00570b10
// T2PictureButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x00570b90
// T2PictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(T2PictureButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x00570bb0
T2PictureButton::T2PictureButton() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00570be0
// T2PictureButton::`scalar deleting destructor'

T2PictureButton::~T2PictureButton() {}

// FUNCTION: IMPERIALISM 0x00570c30
void T2PictureButton::SetAvailability(char isAvailable, char refreshNow) {
  short pictureId = glyphBase84;
  short alternatePictureId = static_cast<short>(controlValue3c);
  if ((isAvailable == 1 && pictureId > controlValue3c) ||
      (isAvailable == 0 && pictureId < controlValue3c)) {
    SetPictureResourceIdAndRefresh(alternatePictureId, false);
    controlValue3c = pictureId;
    SetState(isAvailable, false);
    SetEnabled(!isAvailable, refreshNow);
  }
}
