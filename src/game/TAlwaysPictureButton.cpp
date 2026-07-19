#include "game/TAlwaysPictureButton.h"
#include "game/mfc.h"


// SYNTHETIC: IMPERIALISM 0x00570950
// TAlwaysPictureButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x005709d0
// TAlwaysPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAlwaysPictureButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x005709f0
TAlwaysPictureButton::TAlwaysPictureButton() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00570a20
// TAlwaysPictureButton::`scalar deleting destructor'
TAlwaysPictureButton::~TAlwaysPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570a70
void TAlwaysPictureButton::SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) {
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
      this->IsSelected();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00570ae0
void TAlwaysPictureButton::Select(bool isPressed, bool notifyParent) {
  this->SetEnabled(isPressed, notifyParent);
}
