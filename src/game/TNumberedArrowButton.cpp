// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"
#include "game/TNumberedArrowButton.h"
int g_pClassDescTNumberedArrowButton;

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058c1e0
TNumberedArrowButton* __cdecl CreateTNumberedArrowButtonInstance(void) {
  return new TNumberedArrowButton();
}

// FUNCTION: IMPERIALISM 0x0058c280
void* __cdecl GetTNumberedArrowButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTNumberedArrowButton);
}

// FUNCTION: IMPERIALISM 0x0058c2a0
TNumberedArrowButton::TNumberedArrowButton() : TControl(), value84(0), value86(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058c2e0
// TNumberedArrowButton::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

TNumberedArrowButton::~TNumberedArrowButton() {}

