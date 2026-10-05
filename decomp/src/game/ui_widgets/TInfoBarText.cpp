#include "game/ui_widgets/TInfoBarText.h"

#include <cstring>

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00429330
TInfoBarText::TInfoBarText() : TDeluxeText() {}

// FUNCTION: IMPERIALISM 0x004293f0
TInfoBarText::~TInfoBarText() {}

IMPLEMENT_DYNCREATE(TInfoBarText, TDeluxeText)

// FUNCTION: IMPERIALISM 0x005b66b0
void TInfoBarText::SetTextAndLayoutRect(CString text, RECT* layoutRect) {
  if (EqualRect(layoutRect, &layoutRectA4) == 0) {
    layoutRectA4.left = layoutRect->left;
    layoutRectA4.top = layoutRect->top;
    layoutRectA4.right = layoutRect->right;
    layoutRectA4.bottom = layoutRect->bottom;
    UpdateTextEntrySharedString(&text);
    CenterVertically(true);
  }
}

// IFuzzySet the text-entry layout rect and push an empty shared string, then recenter.
// FUNCTION: IMPERIALISM 0x005b6770
void TInfoBarText::ClearTextAndLayoutRect(int) {
  CString text;
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;
  UpdateTextEntrySharedString(&text);
  CenterVertically(true);
}

// FUNCTION: IMPERIALISM 0x005b6810
void TInfoBarText::Reset() {
  InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
}

// FUNCTION: IMPERIALISM 0x005b6840
void TInfoBarText::InitializeMapHintTextStyleAndThemeFlags(int stylePrimary, int styleSecondary) {
  TextStyle styleDescriptor = {0, 0, 0, 0};
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, styleSecondary);
  SetTextStyle(styleDescriptor, false);
  SetJustification(static_cast<short>(-1), false);
  layoutRectA4.left = 0;
  layoutRectA4.top = 0;
  layoutRectA4.right = 0;
  layoutRectA4.bottom = 0;
  COLORREF mappedFlags = 0;
  ResolveUiThemeColor(static_cast<short>(stylePrimary), &mappedFlags);
  textColor98 = mappedFlags;
  ResolveUiThemeColor(static_cast<short>(styleSecondary), &mappedFlags);
  shadowTextColor = mappedFlags;
  dropShadowEnabledA0 = true;
}

// FUNCTION: IMPERIALISM 0x005b6930
void TInfoBarText::Free() {
  if (g_pCursorControlPanel == this) {
    g_pCursorControlPanel = 0;
  }
  TView::Free();
}
