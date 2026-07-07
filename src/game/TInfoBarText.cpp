#include "game/TInfoBarText.h"

#include <cstring>

#include "game/TCursorControlPanel.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x004293c0
// TInfoBarText::`scalar deleting destructor'
TInfoBarText::~TInfoBarText() {}
// SYNTHETIC: IMPERIALISM 0x005b65a0
// TInfoBarText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b6690
// TInfoBarText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoBarText, TDeluxeText)

// FUNCTION: IMPERIALISM 0x00429330
TInfoBarText::TInfoBarText()
    : TDeluxeText(), cursorThemeCode98(0), cursorThemeCode9c(0), fieldA0(0) {}

// FUNCTION: IMPERIALISM 0x005b66b0
void TInfoBarText::SetTextAndLayoutRect(CString text, RECT* layoutRect) {
  // Original signature carries the text by value (the previous port dropped it and
  // pushed a fresh empty CString instead).
  if (EqualRect(layoutRect, &layoutRectA4) == 0) {
    layoutRectA4.left = layoutRect->left;
    layoutRectA4.top = layoutRect->top;
    layoutRectA4.right = layoutRect->right;
    layoutRectA4.bottom = layoutRect->bottom;
    UpdateTextEntrySharedString(&text);
    RecenterTextFromMeasuredWidthAndMaybeInvalidate(1);
  }
}

// Clear the text-entry layout rect and push an empty shared string, then recenter.
// FUNCTION: IMPERIALISM 0x005b6770
void TInfoBarText::ClearTextAndLayoutRect() {
  CString text;
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;
  UpdateTextEntrySharedString(&text);
  RecenterTextFromMeasuredWidthAndMaybeInvalidate(1);
}

// FUNCTION: IMPERIALISM 0x005b6810
void TInfoBarText::OrphanCallChain_C1_I05_005b6810() {
  InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
}

// FUNCTION: IMPERIALISM 0x005b6840
void TInfoBarText::InitializeMapHintTextStyleAndThemeFlags(int stylePrimary, int styleSecondary) {
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
  ConstructTMapKeyBaseState_Impl(styleDescriptor, 0);
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
}

// Detach from the shared cursor-info-panel global before the generic view teardown;
// an empty body here left the node attached and looped the parent's Free-until-empty walk.
// FUNCTION: IMPERIALISM 0x005b6930
void TInfoBarText::Free() {
  if (g_pCursorControlPanel == this) {
    g_pCursorControlPanel = 0;
  }
  TView::Free();
}
