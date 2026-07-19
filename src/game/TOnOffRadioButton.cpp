#include "game/TOnOffRadioButton.h"

#include "game/TControl.h"
// SYNTHETIC: IMPERIALISM 0x00571930
// TOnOffRadioButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005719d0
// TOnOffRadioButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOnOffRadioButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x005719f0
TOnOffRadioButton::TOnOffRadioButton() {}

// SYNTHETIC: IMPERIALISM 0x00571a30
// TOnOffRadioButton::`scalar deleting destructor'
TOnOffRadioButton::~TOnOffRadioButton() {}

// FUNCTION: IMPERIALISM 0x00571a80
void TOnOffRadioButton::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
    case 0xc:
      if (controlState64 == 0) {
        OrphanCallChain_C2_I16_00571b20(1, 1);
      }
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
    case 0x1f:
      OrphanCallChain_C2_I16_00571b20(1, 1);
      return;
    case 0x20:
      OrphanCallChain_C2_I16_00571b20(0, 1);
      return;
    default:
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
  }
}

// FUNCTION: IMPERIALISM 0x00571b20
undefined TOnOffRadioButton::OrphanCallChain_C2_I16_00571b20(undefined4 param_1, undefined4 param_2) {
  return 0;
}
