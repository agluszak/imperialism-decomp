#include "game/TInfoBarText.h"

#include <cstring>

#include "game/quickdraw_rendering.h"

void __cdecl BuildUiTextStyleDescriptor(void* styleDescriptor, int unused, int arg2, int themeCode);

// SYNTHETIC: IMPERIALISM 0x004293c0
// TInfoBarText::`scalar deleting destructor'
TInfoBarText::~TInfoBarText() {}
// SYNTHETIC: IMPERIALISM 0x005b65a0
// TInfoBarText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b6690
// TInfoBarText::GetRuntimeClass

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
  // Original (0x5b6840): builds the descriptor from styleSecondary (stylePrimary is
  // genuinely unused), forwards it to slot 0x79, clears the theme code via slot 0x71
  // with (-1, no-refresh), then maps the descriptor's stored theme word and
  // styleSecondary through MapUiThemeCodeToStyleFlags out-params (the previous port
  // consumed nonexistent return values with swapped arguments).
  (void)stylePrimary;
  int styleDescriptor[4];
  styleDescriptor[0] = 0;
  styleDescriptor[1] = 0;
  styleDescriptor[2] = 0;
  styleDescriptor[3] = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, styleSecondary);
  ConstructTMapKeyBaseState_Impl(&styleDescriptor, 0);
  SetTextThemeCodeAndMaybeRefresh(static_cast<short>(-1), 0);
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;
  int mappedFlags = 0;
  MapUiThemeCodeToStyleFlags(static_cast<short>(styleDescriptor[0]), &mappedFlags);
  cursorThemeCode98 = mappedFlags;
  MapUiThemeCodeToStyleFlags(static_cast<short>(styleSecondary), &mappedFlags);
  cursorThemeCode9c = mappedFlags;
  fieldA0 = 1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6930
void TInfoBarText::Free() {}
