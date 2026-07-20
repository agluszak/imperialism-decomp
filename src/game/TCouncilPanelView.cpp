#include "game/TCouncilPanelView.h"

#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x00430570
// TCouncilPanelView::`scalar deleting destructor'
TCouncilPanelView::~TCouncilPanelView() {}
// SYNTHETIC: IMPERIALISM 0x004faf80
// TCouncilPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fb010
// TCouncilPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCouncilPanelView, TPanelView)

TCouncilPanelView::TCouncilPanelView() {}

// Council panel header: when no summit is in session (selectedSourceNationSlot784 ==
// -1), draws a single centered "no session" message (GetString 0x2733/0x34). Otherwise
// draws a bracket-expanded "Congress of <decade>" title, then 3 "label: value" rows:
// the chairman nation + selectionFlagsA788, the counterpart nation +
// selectionFlagsB78a, and a generic label (GetString 0x2733/0x36) + selectionFlagsC78c.
// Every label/value is drawn twice (theme 0x2b68 color at +1,+1 then theme 0x2b6b
// color at +0,+0), matching the drop-shadow idiom used across this UI family.
// FUNCTION: IMPERIALISM 0x004fb030
void TCouncilPanelView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  CString titleTemplate;
  CString scratchText;
  CString rowText;

  short centerX = static_cast<short>(this->frameWidth34 / 2);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0x12, 0x2b68);

  int styleShadow = 0;
  int styleForeground = 0;
  MapUiThemeCodeToStyleFlags(0x2b6b, &styleShadow);
  MapUiThemeCodeToStyleFlags(0x2b68, &styleForeground);

  if (g_pDiplomacyTurnStateManager->selectedSourceNationSlot784 == -1) {
    g_pSimMgr->GetString(0x2733, 0x34, &rowText);
    short width = MeasureTextExtentWithCachedQuickDrawStyle(&rowText);
    short x = static_cast<short>(centerX - width / 2);
    SetQuickDrawColorAndSyncGlobals(styleForeground);
    SetQuickDrawTextOriginWithContextOffset(x + 1, 0x25);
    DrawTextWithCachedQuickDrawStyleState(&rowText);
    SetQuickDrawColorAndSyncGlobals(styleShadow);
    SetQuickDrawTextOriginWithContextOffset(x, 0x24);
    DrawTextWithCachedQuickDrawStyleState(&rowText);
    return;
  }

  g_pSimMgr->GetString(0x2733, 0x35, &titleTemplate);
  int decadeYear = (static_cast<short>(g_pSimMgr->quarterGateTick2c / 4) / 10) * 10 + 0x717;
  scratchText.Format(g_szDecimalFormat, decadeYear);
  scanBracketExpressions(g_pSimMgr, &rowText, static_cast<LPCSTR>(titleTemplate),
                         static_cast<LPCSTR>(scratchText));
  short titleWidth = MeasureTextExtentWithCachedQuickDrawStyle(&rowText);
  short titleX = static_cast<short>(centerX - titleWidth / 2);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(titleX + 1, 0x25);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(titleX, 0x24);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);

  // Row A: chairman nation (selectedSourceNationSlot784) + its selectionFlagsA788.
  g_apTerrainTypeDescriptorTable[g_pDiplomacyTurnStateManager->selectedSourceNationSlot784]
      ->FormatOverlayTerrainLabelText(&rowText);
  rowText += s_szColonSeparator_00696b10;
  short rowAWidth = MeasureTextExtentWithCachedQuickDrawStyle(&rowText);
  short rowALabelX = static_cast<short>(centerX - rowAWidth);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(rowALabelX + 1, 0x3d);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(rowALabelX, 0x3c);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  scratchText.Format(g_szDecimalFormat, g_pDiplomacyTurnStateManager->selectionFlagsA788);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(centerX + 5, 0x3d);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(centerX + 4, 0x3c);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);

  // Row B: counterpart nation (selectedTargetNationSlot786) + its selectionFlagsB78a.
  g_apTerrainTypeDescriptorTable[g_pDiplomacyTurnStateManager->selectedTargetNationSlot786]
      ->FormatOverlayTerrainLabelText(&rowText);
  rowText += s_szColonSeparator_00696b10;
  short rowBWidth = MeasureTextExtentWithCachedQuickDrawStyle(&rowText);
  short rowBLabelX = static_cast<short>(centerX - rowBWidth);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(rowBLabelX + 1, 0x4d);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(rowBLabelX, 0x4c);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  scratchText.Format(g_szDecimalFormat, g_pDiplomacyTurnStateManager->selectionFlagsB78a);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(centerX + 5, 0x4d);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(centerX + 4, 0x4c);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);

  // Row C: generic label (GetString 0x2733/0x36) + selectionFlagsC78c.
  g_pSimMgr->GetString(0x2733, 0x36, &rowText);
  short rowCWidth = MeasureTextExtentWithCachedQuickDrawStyle(&rowText);
  short rowCLabelX = static_cast<short>(centerX - rowCWidth);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(rowCLabelX + 1, 0x5d);
  DrawTextWithCachedQuickDrawStyleState(&rowText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(rowCLabelX, 0x5c);
  DrawTextWithCachedQuickDrawStyleState(&rowText);

  scratchText.Format(g_szDecimalFormat, g_pDiplomacyTurnStateManager->selectionFlagsC78c);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(centerX + 5, 0x5d);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(centerX + 4, 0x5c);
  DrawTextWithCachedQuickDrawStyleState(&scratchText);
}
