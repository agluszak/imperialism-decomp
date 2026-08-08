#include "game/military_ui/TArmyBoyView.h"

#include "game/battle_report_records.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004aeb50
// TArmyBoyView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004aeb80
TArmyBoyView::~TArmyBoyView() {}
// SYNTHETIC: IMPERIALISM 0x004aeae0
// TArmyBoyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004aeba0
// TArmyBoyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyBoyView, TView)

// FUNCTION: IMPERIALISM 0x004aebc0
void TArmyBoyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  short level = battleDetail60->stockOrRequired;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x17);
  CString nameString(battleDetail60->nameBuffer);
  DrawTextWithCachedQuickDrawStyleState(&nameString);
  SetQuickDrawFillColor(0);

  short sVar1 = level / 0x19 + 1;
  if (sVar1 > 0x14) {
    sVar1 = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short sVar2 = (sVar1 < 5) ? 0x1a : ((sVar1 > 0xe) ? 10 : 18);
  RECT srcRect = {0, sVar2, sVar1 * 4 - 1, sVar2 + 7};
  RECT dstRect = {0x43, 0x1f, sVar1 * 4 + 0x42, 0x26};

  if (level < 1) {
    // Untrained unit: draw the localized "in training" string centered. String group
    // 0x273c, index 0x20 for the sentinel level -86 (fresh recruit) else 0x1f.
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

  short xpPercent = battleDetail60->strengthBucket;
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
