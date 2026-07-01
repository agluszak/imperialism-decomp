#include "game/T2PictureButton.h"
#include "game/mfc.h"


// FUNCTION: IMPERIALISM 0x00570b10
T2PictureButton* __cdecl CreateT2PictureButtonInstance(void) {
  return new T2PictureButton();
}
// SYNTHETIC: IMPERIALISM 0x00570b90
// T2PictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(T2PictureButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x00570bb0
T2PictureButton::T2PictureButton() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00570be0
// T2PictureButton::`scalar deleting destructor'

T2PictureButton::~T2PictureButton() {}

// FUNCTION: IMPERIALISM 0x00570c30
undefined T2PictureButton::OrphanCallChain_C3_I43_00570c30() {
  return 0;
}
