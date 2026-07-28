#include "game/ui_widgets/TPlacard.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/ui_core/TControl.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x0058b960
// TPlacard::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058b9f0
// TPlacard::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPlacard, TPicture)

// FUNCTION: IMPERIALISM 0x0058ba10
TPlacard::TPlacard() : TPicture() {
  this->glyph90 = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058ba40
// TPlacard::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058ba90
TPlacard::~TPlacard() {}

// FUNCTION: IMPERIALISM 0x0058bab0
void TPlacard::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  if (glyph90 == 0) {
    SetState(0, 1);
    return;
  }
  SetState(1, 1);
}

// FUNCTION: IMPERIALISM 0x0058bb50
bool TPlacard::SetValue(short value, bool refreshNow) {
  if (value != glyph90) {
    if (value == 0) {
      SetState(0, refreshNow);
    } else if (glyph90 == 0) {
      SetState(1, refreshNow);
    }
    glyph90 = value;
    if (refreshNow) {
      RECT rect;
      rect.top = frameHeight38 - 0xc;
      rect.left = static_cast<short>((frameWidth34 / 2) - 10);
      rect.right = rect.left + 0x14;
      rect.bottom = frameHeight38 - 1;
      InvalidateCityDialogRectRegion(&rect, 1);
    }
  }
  return glyph90 != 0;
}

// FUNCTION: IMPERIALISM 0x0058bc60
void TPlacard::Draw(RECT* rectBuffer) {
  union ThemeColorStorage {
    COLORREF packedValue;
    unsigned char channels[4];
  };

  CString valueText;
  ThemeColorStorage textColor;
  ThemeColorStorage shadowColor;
  textColor.channels[0] = 0;
  textColor.channels[1] = 0;
  textColor.channels[2] = 0;
  textColor.channels[3] = 0;
  shadowColor.channels[0] = 0;
  shadowColor.channels[1] = 0;
  shadowColor.channels[2] = 0;
  shadowColor.channels[3] = 0;
  TPicture::Draw(rectBuffer);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);

  valueText.Format(g_szDecimalFormat, glyph90);

  short textX;
  if (glyph90 < 10) {
    textX = static_cast<short>(frameWidth34 / 2 - 2);
  } else if (glyph90 < 100) {
    textX = static_cast<short>(frameWidth34 / 2 - 6);
  } else {
    textX = static_cast<short>(frameWidth34 / 2 - 10);
  }

  ResolveUiThemeColor(0x2b6c, &textColor.packedValue);
  ResolveUiThemeColor(0x2b67, &shadowColor.packedValue);

  short textY = static_cast<short>(frameHeight38 - 2);
  SetQuickDrawColorAndSyncGlobals(shadowColor.packedValue);
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(textX + 1),
                                          static_cast<short>(textY + 1));
  DrawTextWithCachedQuickDrawStyleState(&valueText);

  SetQuickDrawColorAndSyncGlobals(textColor.packedValue);
  SetQuickDrawTextOriginWithContextOffset(textX, textY);
  DrawTextWithCachedQuickDrawStyleState(&valueText);
  SetQuickDrawFillColor(0);
}
