#include "game/TPlacard.h"

int g_pClassDescTPlacard;

// FUNCTION: IMPERIALISM 0x0058b960
void* __cdecl CreateTPlacardInstance(void) {
  return new TPlacard();
}

// FUNCTION: IMPERIALISM 0x0058b9f0
void* __cdecl GetTPlacardClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTPlacard);
}

// FUNCTION: IMPERIALISM 0x0058ba10
TPlacard::TPlacard() : TPictureButton() {
  this->glyph90 = 0;
}

// FUNCTION: IMPERIALISM 0x0058ba40
TPlacard::~TPlacard() {
}
