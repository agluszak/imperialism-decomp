#include "game/TInfoBarText.h"

// SYNTHETIC: IMPERIALISM 0x004293c0
// TInfoBarText::`scalar deleting destructor'
TInfoBarText::~TInfoBarText() {}
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
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6840
undefined TInfoBarText::InitializeMapHintTextStyleAndThemeFlags() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b6930
void TInfoBarText::Free() {
}
