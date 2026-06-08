#include "game/T2PictureButton.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x65e568
char g_pClassDescT2PictureButton;

} // namespace

// FUNCTION: IMPERIALISM 0x00570b10
T2PictureButton* __cdecl CreateT2PictureButtonInstance(void) {
  return new T2PictureButton();
}

// FUNCTION: IMPERIALISM 0x00570b90
void* __cdecl GetT2PictureButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescT2PictureButton);
}

// FUNCTION: IMPERIALISM 0x00570bb0
T2PictureButton::T2PictureButton() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00570be0
// T2PictureButton::`scalar deleting destructor'

T2PictureButton::~T2PictureButton() {}

