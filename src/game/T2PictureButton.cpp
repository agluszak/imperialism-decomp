#include "game/T2PictureButton.h"
#include "game/mfc.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x0065e568
CRuntimeClass g_pClassDescT2PictureButton = {nullptr, 0, 0, nullptr, nullptr};
}


// FUNCTION: IMPERIALISM 0x00570b10
T2PictureButton* __cdecl CreateT2PictureButtonInstance(void) {
  return new T2PictureButton();
}

// FUNCTION: IMPERIALISM 0x00570b90
CRuntimeClass* T2PictureButton::GetRuntimeClass() const {
  return &g_pClassDescT2PictureButton;
}

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
