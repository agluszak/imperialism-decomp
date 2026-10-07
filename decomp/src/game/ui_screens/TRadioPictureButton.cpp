#include "game/ui_screens/TRadioPictureButton.h"
#include "game/ui_core/TControl.h"

IMPLEMENT_DYNCREATE(TRadioPictureButton, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x005717c0
TRadioPictureButton::TRadioPictureButton() : TUpDownPictureButton() {
  this->eventNumber = 0xc;
  this->reserved94 = 0;
}

// FUNCTION: IMPERIALISM 0x00571830
TRadioPictureButton::~TRadioPictureButton() {}

// FUNCTION: IMPERIALISM 0x00571850
void TRadioPictureButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
  case 0xc:
    if (controlState == 0) {
      SetState(true, false);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  case kControlCommandHiliteOn:
    SetState(true, false);
    return;
  case kControlCommandHiliteOff:
    SetState(false, false);
    return;
  default:
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x005718f0
void TRadioPictureButton::SetState(bool state, bool refreshNow) {
  if (IsEnabled()) {
    HiliteState(state, refreshNow);
  }
}
