#include "game/ui_screens/TOnOffRadioButton.h"

#include "game/ui_core/TControl.h"
// SYNTHETIC: IMPERIALISM 0x00571930
// TOnOffRadioButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005719d0
// TOnOffRadioButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOnOffRadioButton, TPictureButton)

// Original store order after the vptr write: eventNumber60 = 0xc (overriding the
// TControl ctor's 1), then byte state94 = 0. The timingWord92 store visible at
// 0x5719f8 is the inlined TPictureButton ctor.
// FUNCTION: IMPERIALISM 0x005719f0
TOnOffRadioButton::TOnOffRadioButton() : TPictureButton() {
  eventNumber60 = 0xc;
  state94 = 0;
}

// SYNTHETIC: IMPERIALISM 0x00571a30
// TOnOffRadioButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00571a60
TOnOffRadioButton::~TOnOffRadioButton() {}

// FUNCTION: IMPERIALISM 0x00571a80
void TOnOffRadioButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
  case 0xc:
    if (controlState64 == 0) {
      SetState(static_cast<unsigned char>(1), static_cast<unsigned char>(1));
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  case 0x1f:
    SetState(static_cast<unsigned char>(1), static_cast<unsigned char>(1));
    return;
  case 0x20:
    SetState(static_cast<unsigned char>(0), static_cast<unsigned char>(1));
    return;
  default:
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00571b20
void TOnOffRadioButton::SetState(unsigned char on, unsigned char drawImmediate) {
  if (IsEnabled() != 0) {
    HiliteState(on, drawImmediate);
  }
}
