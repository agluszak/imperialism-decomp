#include "game/ui_screens/TRadioPictureButton.h"
#include "game/ui_core/TControl.h"

IMPLEMENT_DYNCREATE(TRadioPictureButton, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x005717c0
TRadioPictureButton::TRadioPictureButton() : TUpDownPictureButton() {
  this->eventNumber60 = 0xc;
  this->reserved94 = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// FUNCTION: IMPERIALISM 0x00571830
TRadioPictureButton::~TRadioPictureButton() {}

// FUNCTION: IMPERIALISM 0x00571850
void TRadioPictureButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
  case 0xc:
    if (controlState64 == 0) {
      SetRadioState(true, 0);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  case kControlCommandHiliteOn:
    SetRadioState(true, 0);
    return;
  case kControlCommandHiliteOff:
    SetRadioState(false, 0);
    return;
  default:
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x005718f0
void TRadioPictureButton::SetRadioState(bool state, unsigned char refreshNow) {
  if (IsEnabled()) {
    HiliteState(state, refreshNow);
  }
}
