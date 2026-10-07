#include "game/navy/TShip.h"
#include "game/military_ui/TNavyBoyView.h"

#include "game/battle_report_records.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004af070
TNavyBoyView::~TNavyBoyView() {}

IMPLEMENT_DYNCREATE(TNavyBoyView, TView)

// FUNCTION: IMPERIALISM 0x004af0b0
void TNavyBoyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6a);
  CString finalLabel;
  CString unusedLabel;
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b6a, 3);

  CString typeNames[14];
  CString* blankCursor = typeNames;
  int blankCount = 3;
  do {
    *blankCursor = CString(g_szEmptyString);
    ++blankCursor;
  } while (--blankCount != 0);
  g_pSimMgr->GetString(0x2760, 0, &typeNames[3]);
  g_pSimMgr->GetString(0x2760, 1, &typeNames[4]);
  g_pSimMgr->GetString(0x2760, 2, &typeNames[7]);
  g_pSimMgr->GetString(0x2760, 3, &typeNames[8]);
  g_pSimMgr->GetString(0x2760, 4, &typeNames[9]);
  typeNames[10] = CString(g_szEmptyString);
  g_pSimMgr->GetString(0x2760, 5, &typeNames[11]);
  g_pSimMgr->GetString(0x2760, 6, &typeNames[12]);
  g_pSimMgr->GetString(0x2760, 6, &typeNames[13]);

  short kindId = battleDetail->resourceType;
  finalLabel = typeNames[kindId];
  finalLabel += s_szSpaceSeparator + CString(battleDetail->nameBuffer);

  SetQuickDrawTextOriginWithContextOffset(0x50, 0x18);
  DrawTextWithCachedQuickDrawStyleState(&finalLabel);

  short levelDivisor = TShip::GetTypeHullPoints(battleDetail->resourceType);
  short level = battleDetail->stockOrRequired;
  short barLength = (level * 0x14) / levelDivisor + 1;
  if (barLength > 0x14) {
    barLength = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short barSpriteRow = (barLength < 5) ? 0x1a : ((barLength > 0xe) ? 10 : 18);
  RECT srcRect = {0, barSpriteRow, barLength * 4 - 1, barSpriteRow + 7};
  RECT dstRect = {0x52, 0x1e, barLength * 4 + 0x51, 0x25};

  if (level > 0) {
    TQuickDrawBlitSurface* iconStripSurface =
        g_pMacViewMgr->tileOverlayStripWorlds[0]->GetBlitSurface();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
  } else {
    // Untrained unit: draw the localized "in training" string centered.
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(1, 0xc, 0x2b67);
    CString trainingText;
    g_pSimMgr->GetString(0x273c, 0x1b, &trainingText);
    short trainingWidth = MeasureTextExtentWithCachedQuickDrawStyle(&trainingText);
    SetQuickDrawTextOriginWithContextOffset(0x88 - trainingWidth / 2, 0x25);
    DrawTextWithCachedQuickDrawStyleState(&trainingText);
  }

  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x50, 0x20);
  DrawCenteredGuideLineOnMapDc(0x50, 0x26);
  DrawCenteredGuideLineOnMapDc(0xa2, 0x26);
  DrawCenteredGuideLineOnMapDc(0xa2, 0x20);
}
