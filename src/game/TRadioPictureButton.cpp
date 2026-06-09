#include "game/TRadioPictureButton.h"

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
