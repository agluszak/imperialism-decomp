#include "game/TInfoBarText.h"

#include <cstring>

void __cdecl BuildUiTextStyleDescriptor(void* styleDescriptor, int unused, int arg2, int stylePrimary);
undefined4 thunk_MapUiThemeCodeToStyleFlags(void);

// SYNTHETIC: IMPERIALISM 0x004293c0
// TInfoBarText::`scalar deleting destructor'
TInfoBarText::~TInfoBarText() {}
// SYNTHETIC: IMPERIALISM 0x005b65a0
// TInfoBarText::CreateObject

IMPLEMENT_DYNCREATE(TInfoBarText, TDeluxeText)

TInfoBarText::TInfoBarText() {}

// FUNCTION: IMPERIALISM 0x005b66b0
undefined TInfoBarText::ConstructTInfoBarTextBaseState(RECT* layoutRect) {
  RECT* cachedLayout = reinterpret_cast<RECT*>(reinterpret_cast<char*>(this) + 0xa4);
  if (EqualRect(layoutRect, cachedLayout) == 0) {
    CopyRect(cachedLayout, layoutRect);
    CString textArg;
    WrapperFor_thunk_UpdateTextEntrySharedStringIfChanged_At005b6480(
        reinterpret_cast<undefined4>(&textArg));
    RecenterTextFromMeasuredWidthAndMaybeInvalidate(1);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6770
undefined TInfoBarText::DestructTInfoBarTextAndMaybeFree() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6810
undefined TInfoBarText::OrphanCallChain_C1_I05_005b6810() {
  InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6840
undefined TInfoBarText::InitializeMapHintTextStyleAndThemeFlags(int stylePrimary,
                                                                int styleSecondary) {
  unsigned char styleDescriptor[16];
  memset(&styleDescriptor, 0, sizeof(styleDescriptor));
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, stylePrimary);
  ConstructTMapKeyBaseState_Impl(&styleDescriptor, 0);
  OrphanCallChain_C1_I09_0048ff70(0, static_cast<char>(-1));
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;
  cursorThemeCode98 = reinterpret_cast<int(__cdecl*)(int, void*)>(thunk_MapUiThemeCodeToStyleFlags)(
      styleSecondary, &styleDescriptor);
  cursorThemeCode9c = reinterpret_cast<int(__cdecl*)(int, void*)>(thunk_MapUiThemeCodeToStyleFlags)(
      stylePrimary, &styleDescriptor);
  fieldA0 = 1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6930
void TInfoBarText::Free() {
}
