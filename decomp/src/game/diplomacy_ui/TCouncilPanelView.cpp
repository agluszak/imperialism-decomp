#include "game/diplomacy_ui/TCouncilPanelView.h"

#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00430520
TCouncilPanelView::TCouncilPanelView() {
  diplomacyMapView = 0;
}

// FUNCTION: IMPERIALISM 0x004305a0
TCouncilPanelView::~TCouncilPanelView() {}

IMPLEMENT_DYNCREATE(TCouncilPanelView, TPanelView)

// FUNCTION: IMPERIALISM 0x004fb030
void TCouncilPanelView::Draw(RECT* rectBuffer) {
  CString titleTemplate;
  CString scratchText;
  CString rowText;

  short centerX = frameWidth / 2;

  ApplyTextStyle(0, 0x12, 0x2b68);

  COLORREF styleShadow = 0;
  COLORREF styleForeground = 0;
  ResolveUiThemeColor(0x2b6b, &styleShadow);
  ResolveUiThemeColor(0x2b68, &styleForeground);

  if (g_pDiplomacyTurnStateManager->congressLeadership.chairmanNationSlot == -1) {
    g_pSimMgr->GetString(0x2733, 0x34, &rowText);
    short width = MeasureText(&rowText);
    short x = centerX - width / 2;
    SetQuickDrawColorAndSyncGlobals(styleForeground);
    SetQuickDrawTextOriginWithContextOffset(x + 1, 0x25);
    DrawTextWithCachedQuickDrawStyleState(&rowText);
    SetQuickDrawColorAndSyncGlobals(styleShadow);
    SetQuickDrawTextOriginWithContextOffset(x, 0x24);
    DrawTextWithCachedQuickDrawStyleState(&rowText);
    return;
  }

  g_pSimMgr->GetString(0x2733, 0x35, &titleTemplate);
  int decadeYear = (static_cast<short>(g_pSimMgr->economicTurn / 4) / 10) * 10 + 0x717;
  scratchText.Format(g_szDecimalFormat, decadeYear);
  scanBracketExpressions(g_pSimMgr, &rowText, static_cast<LPCSTR>(titleTemplate),
                         static_cast<LPCSTR>(scratchText));
  short titleWidth = MeasureText(&rowText);
  short titleX = centerX - titleWidth / 2;
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(titleX + 1, 0x25);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(titleX, 0x24);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  ApplyTextStyle(0, 0xe, 0x2b68);

  // Row A: the chairman nation and its support count.
  g_apTerrainTypeDescriptorTable[g_pDiplomacyTurnStateManager->congressLeadership
                                     .chairmanNationSlot]
      ->FormatOverlayTerrainLabelText(&rowText);
  rowText += s_szColonSeparator;
  short rowAWidth = MeasureText(&rowText);
  short rowALabelX = centerX - rowAWidth;
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(rowALabelX + 1, 0x3d);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(rowALabelX, 0x3c);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  scratchText.Format(g_szDecimalFormat,
                     g_pDiplomacyTurnStateManager->congressSupport.chairmanSupportCount);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(centerX + 5, 0x3d);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(centerX + 4, 0x3c);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);

  // Row B: the counterpart nation and its support count.
  g_apTerrainTypeDescriptorTable[g_pDiplomacyTurnStateManager->congressLeadership
                                     .counterpartNationSlot]
      ->FormatOverlayTerrainLabelText(&rowText);
  rowText += s_szColonSeparator;
  short rowBWidth = MeasureText(&rowText);
  short rowBLabelX = centerX - rowBWidth;
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(rowBLabelX + 1, 0x4d);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(rowBLabelX, 0x4c);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  scratchText.Format(g_szDecimalFormat,
                     g_pDiplomacyTurnStateManager->congressSupport.counterpartSupportCount);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(centerX + 5, 0x4d);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(centerX + 4, 0x4c);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);

  // Row C: a generic label (GetString 0x2733/0x36) and the neutral count.
  g_pSimMgr->GetString(0x2733, 0x36, &rowText);
  short rowCWidth = MeasureText(&rowText);
  short rowCLabelX = centerX - rowCWidth;
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(rowCLabelX + 1, 0x5d);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(rowCLabelX, 0x5c);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  scratchText.Format(g_szDecimalFormat, g_pDiplomacyTurnStateManager->congressSupport.neutralCount);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(centerX + 5, 0x5d);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(centerX + 4, 0x5c);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
}
