#include "game/ui_screens/TRadioPictureButton.h"
#include "game/ui_core/TControl.h"
// SYNTHETIC: IMPERIALISM 0x00571700
// TRadioPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005717a0
// TRadioPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRadioPictureButton, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x005717c0
TRadioPictureButton::TRadioPictureButton() : TUpDownPictureButton() {
  this->eventNumber60 = 0xc;
  this->reserved94 = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00571800
// TRadioPictureButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00571830
TRadioPictureButton::~TRadioPictureButton() {}

// FUNCTION: IMPERIALISM 0x00571850
void TRadioPictureButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    if (controlState64 == 0) {
      SetRadioState(1, 0);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != kControlCommandHiliteOn) {
    if (commandId != kControlCommandHiliteOff) {
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }
    SetRadioState(0, 0);
    return;
  }
  SetRadioState(1, 0);
}

// FUNCTION: IMPERIALISM 0x005718f0
void TRadioPictureButton::SetRadioState(unsigned char state, unsigned char refreshNow) {
  if (IsEnabled()) {
    HiliteState(state, refreshNow);
  }
}
