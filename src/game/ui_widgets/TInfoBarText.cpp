#include "game/TInfoBarText.h"

#include <cstring>

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004293c0
// TInfoBarText::`scalar deleting destructor'
TInfoBarText::~TInfoBarText() {}
// SYNTHETIC: IMPERIALISM 0x005b65a0
// TInfoBarText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b6690
// TInfoBarText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoBarText, TDeluxeText)

// FUNCTION: IMPERIALISM 0x00429330
TInfoBarText::TInfoBarText() : TDeluxeText() {}

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
    CenterVertically(1);
  }
}

// Clear the text-entry layout rect and push an empty shared string, then recenter.
// FUNCTION: IMPERIALISM 0x005b6770
void TInfoBarText::ClearTextAndLayoutRect(int) {
  CString text;
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;
  UpdateTextEntrySharedString(&text);
  CenterVertically(1);
}

// FUNCTION: IMPERIALISM 0x005b6810
void TInfoBarText::OrphanCallChain_C1_I05_005b6810() {
  InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
}

// FUNCTION: IMPERIALISM 0x005b6840
void TInfoBarText::InitializeMapHintTextStyleAndThemeFlags(int stylePrimary, int styleSecondary) {
  TextStyle styleDescriptor = {0, 0, 0, 0};
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, styleSecondary);
  SetTextStyle(styleDescriptor, 0);
  SetTextAlignmentAndMaybeRefresh(static_cast<short>(-1), 0);
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;
  COLORREF mappedFlags = 0;
  ResolveUiThemeColor(static_cast<short>(stylePrimary), &mappedFlags);
  textColor98 = mappedFlags;
  ResolveUiThemeColor(static_cast<short>(styleSecondary), &mappedFlags);
  shadowTextColor9C = mappedFlags;
  dropShadowEnabledA0 = true;
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
