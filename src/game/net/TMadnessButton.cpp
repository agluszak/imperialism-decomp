#include "game/net/TMadnessButton.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"

// SYNTHETIC: IMPERIALISM 0x0043d720
// TMadnessButton::`scalar deleting destructor'
TMadnessButton::~TMadnessButton() {}
// SYNTHETIC: IMPERIALISM 0x0054ea30
// TMadnessButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054ead0
// TMadnessButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMadnessButton, TCzechBox)

TMadnessButton::TMadnessButton() {}

// FUNCTION: IMPERIALISM 0x0054eaf0
void TMadnessButton::DoPostCreate(int arg) {
  TCzechBox::DoPostCreate(arg);
  initialPictureId = glyphBase84;
  TCzechBox::SetState(1, 0);
}

// FUNCTION: IMPERIALISM 0x0054eb30
void TMadnessButton::CheckTheLook(unsigned char refreshNow) {
  int pictureId = initialPictureId;
  if (!IsEnabled()) {
    pictureId += 4;
  } else {
    if (!IsOn()) {
      pictureId += 2;
    }
    if (controlState64 != 0) {
      pictureId++;
    }
  }

  if (glyphBase84 != pictureId) {
    SetPictureResourceIdAndRefresh(static_cast<short>(pictureId), false);
    if (refreshNow) {
      CRect bounds;
      QueryContentBounds(&bounds);
      ScopedMapQuickDrawContext drawContext(this);
      Draw(&bounds);
    }
  }
}
