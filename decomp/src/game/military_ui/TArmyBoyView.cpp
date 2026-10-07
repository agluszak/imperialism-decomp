#include "game/military_ui/TArmyBoyView.h"

#include "game/battle_report_records.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004aeb80
TArmyBoyView::~TArmyBoyView() {}

IMPLEMENT_DYNCREATE(TArmyBoyView, TView)

// FUNCTION: IMPERIALISM 0x004aebc0
void TArmyBoyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  short level = battleDetail->stockOrRequired;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x17);
  CString nameString(battleDetail->nameBuffer);
  DrawTextWithCachedQuickDrawStyleState(&nameString);
  SetQuickDrawFillColor(0);

  short barLength = level / 0x19 + 1;
  if (barLength > 0x14) {
    barLength = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short barSpriteRow = (barLength < 5) ? 0x1a : ((barLength > 0xe) ? 10 : 18);
  RECT srcRect = {0, barSpriteRow, barLength * 4 - 1, barSpriteRow + 7};
  RECT dstRect = {0x43, 0x1f, barLength * 4 + 0x42, 0x26};

  if (level < 1) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(1, 0xc, 0x2b67);
    CString trainingText;
    g_pSimMgr->GetString(0x273c, (level == -86) ? 0x20 : 0x1f, &trainingText);
    short trainingWidth = MeasureTextExtentWithCachedQuickDrawStyle(&trainingText);
    SetQuickDrawTextOriginWithContextOffset(0x6a - trainingWidth / 2, 0x26);
    DrawTextWithCachedQuickDrawStyleState(&trainingText);
  } else {
    TQuickDrawBlitSurface* iconStripSurface = g_pMacViewMgr->atlas694[0]->GetBlitSurface();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
  }

  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x41, 0x21);
  DrawCenteredGuideLineOnMapDc(0x41, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x21);

  short xpPercent = battleDetail->strengthBucket;
  short barWidth = xpPercent * 0xb;
  if (xpPercent % 100 > 0x31) {
    barWidth += 5;
  }
  if (barWidth != 0) {
    TQuickDrawBlitSurface* iconStripSurface = g_pMacViewMgr->atlas694[0]->GetBlitSurface();
    RECT srcRect = {0, 0, barWidth, 10};
    RECT dstRect = {0x94, 0x1f, barWidth + 0x94, 0x29};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    SetQuickDrawStrokeColor(0x13);
  }
}
