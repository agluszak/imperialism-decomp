// Manual decompilation file.

#include "game/TStaticText.h"

#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>
CRuntimeClass g_pClassDescTStaticText = {nullptr, 0, 0, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x0048F710
void* __cdecl CreateTStaticTextInstance(void) {
  return new TStaticText();
}

// MFC RTTI slot 0x00 override: return this class's CRuntimeClass descriptor (0x649678).
// FUNCTION: IMPERIALISM 0x0048F870
CRuntimeClass* TStaticText::GetRuntimeClass() {
  return &g_pClassDescTStaticText;
}

// FUNCTION: IMPERIALISM 0x0048F890
TStaticText::TStaticText()
    : TControl(), text(), field88((void*)0xffffffff), field8C(0), field90(0) {
  hasCommandTagResource = 13;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0048f9a0
// TStaticText::`scalar deleting destructor'

TStaticText::~TStaticText() {}
