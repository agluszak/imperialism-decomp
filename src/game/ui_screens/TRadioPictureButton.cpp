#include "game/ui_screens/TRadioPictureButton.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_core/TControl.h"
// SYNTHETIC: IMPERIALISM 0x00571700
// TRadioPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005717a0
// TRadioPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRadioPictureButton, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x005717c0
TRadioPictureButton::TRadioPictureButton() : TUpDownPictureButton() {
  this->timingWord92 = 7000;
  this->eventNumber60 = 0xc;
  this->reserved94 = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00571800
// TRadioPictureButton::`scalar deleting destructor'

TRadioPictureButton::~TRadioPictureButton() {}

// FUNCTION: IMPERIALISM 0x00571850
void TRadioPictureButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    if (controlState64 == 0) {
      reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(1, 0);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != kControlCommandHiliteOn) {
    if (commandId != kControlCommandHiliteOff) {
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }
    reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(0, 0);
    return;
  }
  reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(1, 0);
}

// FUNCTION: IMPERIALISM 0x005718f0
undefined TRadioPictureButton::OrphanCallChain_C2_I16_005718f0(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  return 0;
}
