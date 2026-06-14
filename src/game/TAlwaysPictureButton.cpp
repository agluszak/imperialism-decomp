#include "game/TAlwaysPictureButton.h"
#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x0065e550
CRuntimeClass g_pClassDescTAlwaysPictureButton = {0};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00570950
TAlwaysPictureButton* __cdecl CreateTAlwaysPictureButtonInstance(void) {
  return new TAlwaysPictureButton();
}

// FUNCTION: IMPERIALISM 0x005709d0
CRuntimeClass* TAlwaysPictureButton::GetRuntimeClass() {
  return &g_pClassDescTAlwaysPictureButton;
}

// FUNCTION: IMPERIALISM 0x005709f0
TAlwaysPictureButton::TAlwaysPictureButton() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00570a20
// TAlwaysPictureButton::`scalar deleting destructor'
