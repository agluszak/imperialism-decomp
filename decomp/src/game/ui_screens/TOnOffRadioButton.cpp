#include "game/ui_screens/TOnOffRadioButton.h"

#include "game/ui_core/TControl.h"

IMPLEMENT_DYNCREATE(TOnOffRadioButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x005719f0
TOnOffRadioButton::TOnOffRadioButton() : TPictureButton() {
  eventNumber60 = 0xc;
  state94 = 0;
}

// FUNCTION: IMPERIALISM 0x00571a60
TOnOffRadioButton::~TOnOffRadioButton() {}

// FUNCTION: IMPERIALISM 0x00571a80
void TOnOffRadioButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
  case 0xc:
    if (controlState64 == 0) {
      SetState(true, true);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  case 0x1f:
    SetState(true, true);
    return;
  case 0x20:
    SetState(false, true);
    return;
  default:
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00571b20
void TOnOffRadioButton::SetState(bool on, bool drawImmediate) {
  if (IsEnabled() != 0) {
    HiliteState(on, drawImmediate);
  }
}
