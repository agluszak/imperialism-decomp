#include "game/TRadioPictureButton.h"

// FUNCTION: IMPERIALISM 0x005717a0
CRuntimeClass* TRadioPictureButton::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005717c0
TRadioPictureButton::TRadioPictureButton() : TPictureButton() {
  this->timingWord92 = 7000;
  this->hasCommandTagResource = 0xc;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x94) = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00571800
// TRadioPictureButton::`scalar deleting destructor'

TRadioPictureButton::~TRadioPictureButton() {}

// FUNCTION: IMPERIALISM 0x005718f0
undefined TRadioPictureButton::OrphanCallChain_C2_I16_005718f0() {
  return 0;
}

undefined TRadioPictureButton::ForwardEngineerDialogCommandToChildSlot40() { return 0; }
