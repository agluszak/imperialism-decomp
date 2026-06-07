#include "game/TPictureButton.h"

unsigned int __cdecl thunk_ConstructPictureResourceEntryBase(void) {
  return 0; // Fake implementation to satisfy linker for ghidra autogen files
}

// FUNCTION: IMPERIALISM 0x0048efc0
TPictureButton::TPictureButton() : TControl() {}

TPictureButton::~TPictureButton() {}
