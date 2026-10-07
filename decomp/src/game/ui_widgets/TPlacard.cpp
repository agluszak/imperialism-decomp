#include "game/ui_widgets/TPlacard.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/ui_core/TControl.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TPlacard, TPicture)

// FUNCTION: IMPERIALISM 0x0058ba10
TPlacard::TPlacard() {
  this->glyph = 0;
}

// FUNCTION: IMPERIALISM 0x0058ba90
TPlacard::~TPlacard() {}

// FUNCTION: IMPERIALISM 0x0058bab0
void TPlacard::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  if (glyph == 0) {
    Show(0, 1);
    return;
  }
  Show(1, 1);
}

// FUNCTION: IMPERIALISM 0x0058bb50
bool TPlacard::SetValue(short value, bool refreshNow) {
  if (value != glyph) {
    if (value == 0) {
      Show(0, refreshNow);
    } else if (glyph == 0) {
      Show(1, refreshNow);
    }
    glyph = value;
    if (refreshNow) {
      RECT rect;
      rect.top = frameHeight - 0xc;
      rect.left = static_cast<short>((frameWidth / 2) - 10);
      rect.right = rect.left + 0x14;
      rect.bottom = frameHeight - 1;
      RECT invalidRect;
      CopyRect(&invalidRect, &rect);
      InvalidateCityDialogRectRegion(&invalidRect, 1);
    }
  }
  return glyph != 0;
}

// FUNCTION: IMPERIALISM 0x0058bc60
void TPlacard::Draw(RECT* rectBuffer) {
  CString valueText;
  COLORREF textColor = 0;
  COLORREF shadowColor = 0;
  TPicture::Draw(rectBuffer);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);

  valueText.Format(g_szDecimalFormat, glyph);

  short textX;
  if (glyph < 10) {
    textX = static_cast<short>(frameWidth / 2 - 2);
  } else if (glyph < 100) {
    textX = static_cast<short>(frameWidth / 2 - 6);
  } else {
    textX = static_cast<short>(frameWidth / 2 - 10);
  }

  ResolveUiThemeColor(0x2b6c, &textColor);
  ResolveUiThemeColor(0x2b67, &shadowColor);

  short textY = frameHeight - 2;
  SetQuickDrawColorAndSyncGlobals(shadowColor);
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(textX + 1),
                                          static_cast<short>(textY + 1));
  DrawTextWithCachedQuickDrawStyleState(&valueText);

  SetQuickDrawColorAndSyncGlobals(textColor);
  SetQuickDrawTextOriginWithContextOffset(textX, textY);
  DrawTextWithCachedQuickDrawStyleState(&valueText);
  SetQuickDrawFillColor(0);
}
