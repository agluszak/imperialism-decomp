// Manual decompilation file.

#include "game/TStaticText.h"
#include "game/ui_widget_shared.h"

int g_pClassDescTStaticText;

// FUNCTION: IMPERIALISM 0x0048F710
void* __cdecl CreateTStaticTextInstance(void) {
  return new TStaticText();
}

// FUNCTION: IMPERIALISM 0x0048F870
void* __cdecl GetTStaticTextClassNamePointer(void) {
  return &g_pClassDescTStaticText;
}

void* TStaticText::GetTEventHandlerClassNamePointer() {
  return GetTStaticTextClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x0048F890
TStaticText::TStaticText()
    : TControl(), text(), field88((void*)0xffffffff), field8C(0), field90(0) {
  hasCommandTagResource = 13;
}

// FUNCTION: IMPERIALISM 0x0048FC30
TStaticText::~TStaticText() {}
