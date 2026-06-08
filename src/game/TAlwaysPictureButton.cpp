#include "game/TAlwaysPictureButton.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x65e550
char g_pClassDescTAlwaysPictureButton;

} // namespace

// FUNCTION: IMPERIALISM 0x00570950
TAlwaysPictureButton* __cdecl CreateTAlwaysPictureButtonInstance(void) {
  return new TAlwaysPictureButton();
}

// FUNCTION: IMPERIALISM 0x005709d0
void* __cdecl GetTAlwaysPictureButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTAlwaysPictureButton);
}

// FUNCTION: IMPERIALISM 0x005709f0
TAlwaysPictureButton::TAlwaysPictureButton() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00570a20
// TAlwaysPictureButton::`scalar deleting destructor'
