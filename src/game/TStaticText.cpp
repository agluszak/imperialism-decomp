// Manual decompilation file.

#include "game/TStaticText.h"
#include "game/ui_widget_shared.h"

int g_pClassDescTStaticText;

// GHIDRA_FUNCTION IMPERIALISM 0x0048F710
void * __cdecl CreateTStaticTextInstance(void) {
  return new TStaticText();
}

// GHIDRA_FUNCTION IMPERIALISM 0x0048F870
void * __cdecl GetTStaticTextClassNamePointer(void) {
  return &g_pClassDescTStaticText;
}

// GHIDRA_FUNCTION IMPERIALISM 0x0048F890
TStaticText::TStaticText()
    : TControl(),
      field84(),
      field16_0x88((void*)0xffffffff),
      field17_0x8c(0),
      field18_0x90(0) {
}

// GHIDRA_FUNCTION IMPERIALISM 0x0048FC30
TStaticText::~TStaticText() {
}
