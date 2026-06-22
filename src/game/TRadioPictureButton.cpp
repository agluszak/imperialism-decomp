#include "game/TRadioPictureButton.h"
#include "game/TAmtBar.h"
#include "game/TControl.h"

// FUNCTION: IMPERIALISM 0x005717a0
CRuntimeClass* TRadioPictureButton::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005717c0
TRadioPictureButton::TRadioPictureButton() : TUpDownPictureButton() {
  this->timingWord92 = 7000;
  this->hasCommandTagResource = 0xc;
  this->field94 = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00571800
// TRadioPictureButton::`scalar deleting destructor'

TRadioPictureButton::~TRadioPictureButton() {}

// FUNCTION: IMPERIALISM 0x005718f0
undefined TRadioPictureButton::OrphanCallChain_C2_I16_005718f0(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00571850
void TRadioPictureButton::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    if (commandTagResourceByte == 0) {
      reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(1, 0);
    }
    TControl::HandleEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != 0x1f) {
    if (commandId != 0x20) {
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
    }
    reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(0, 0);
    return;
  }
  reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(1, 0);
}
