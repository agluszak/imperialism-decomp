#include "game/trade_ui/TTradeTotalsView.h"

#include "game/ui_screens/CString.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005c1a80
// TTradeTotalsView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c1af0
// TTradeTotalsView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeTotalsView, TView)

// FUNCTION: IMPERIALISM 0x005c1b10
TTradeTotalsView::TTradeTotalsView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x005c1b40
// TTradeTotalsView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005c1b70
TTradeTotalsView::~TTradeTotalsView() {}

// FUNCTION: IMPERIALISM 0x005c1bd0
void TTradeTotalsView::Draw(RECT* rectBuffer) {
  CString strA;
  CString strB;
  CString strC;

  TGreatPower* nation = g_apNationStates[nationSlot];

  g_pSimMgr->GetString(0x2740, 0x17, &strA);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b6b);
  COLORREF style1;
  COLORREF style2;
  ResolveUiThemeColor(0x2b6b, &style1);
  ResolveUiThemeColor(0x2b6c, &style2);
  SetQuickDrawColorAndSyncGlobals(style2);
  SetQuickDrawTextOriginWithContextOffset(10, 18);
  DrawTextWithCachedQuickDrawStyleState(&strA);
  SetQuickDrawColorAndSyncGlobals(style1);
  SetQuickDrawTextOriginWithContextOffset(9, 17);
  DrawTextWithCachedQuickDrawStyleState(&strA);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b6a);

  g_pSimMgr->GetString(0x2740, 0x18, &strA);
  SetQuickDrawTextOriginWithContextOffset(8, 0x1e);
  DrawTextWithCachedQuickDrawStyleState(&strA);
  g_pSimMgr->NumToCurrency(nation->budgetPoolBase, &strA);
  SetQuickDrawTextOriginWithContextOffset(0x80, 0x1e);
  DrawTextWithCachedQuickDrawStyleState(&strA);

  g_pSimMgr->GetString(0x2740, 0x19, &strA);
  SetQuickDrawTextOriginWithContextOffset(8, 0x2a);
  DrawTextWithCachedQuickDrawStyleState(&strA);
  g_pSimMgr->NumToCurrency(nation->budgetPoolDelta, &strA);
  SetQuickDrawTextOriginWithContextOffset(nation->budgetPoolDelta >= 0 ? 0x80 : 0x7c, 0x2a);
  DrawTextWithCachedQuickDrawStyleState(&strA);

  g_pSimMgr->GetString(0x2740, 0x1d, &strA);
  SetQuickDrawTextOriginWithContextOffset(8, 0x36);
  DrawTextWithCachedQuickDrawStyleState(&strA);
  g_pSimMgr->NumToCurrency(-nation->militaryExpenses960, &strA);
  SetQuickDrawTextOriginWithContextOffset(nation->militaryExpenses960 <= 0 ? 0x80 : 0x7c, 0x36);
  DrawTextWithCachedQuickDrawStyleState(&strA);

  g_pSimMgr->GetString(0x2740, 0x1a, &strA);
  int y = 0x42;
  SetQuickDrawTextOriginWithContextOffset(8, y);
  DrawTextWithCachedQuickDrawStyleState(&strA);
  g_pSimMgr->NumToCurrency(nation->SumAidAllocationMatrixAllCells(), &strA);
  SetQuickDrawTextOriginWithContextOffset(0x80, y);
  DrawTextWithCachedQuickDrawStyleState(&strA);

  if (nation->pressureCounter > 0) {
    g_pSimMgr->GetString(0x2740, 0x1c, &strB);
    strC.Format(g_szDecimalFormat, static_cast<int>(nation->escalationCounter));
    scanBracketExpressions(g_pSimMgr, &strA, static_cast<LPCSTR>(strB), static_cast<LPCSTR>(strC));
    y = 0x4e;
    SetQuickDrawTextOriginWithContextOffset(8, y);
    DrawTextWithCachedQuickDrawStyleState(&strA);
    g_pSimMgr->NumToCurrency(-nation->pendingCommitmentCost, &strA);
    SetQuickDrawTextOriginWithContextOffset(nation->pendingCommitmentCost <= 0 ? 0x80 : 0x7c, y);
    DrawTextWithCachedQuickDrawStyleState(&strA);
  }

  y += 2;
  SetQuickDrawTextOriginWithContextOffset(8, y);
  DrawCenteredGuideLineOnMapDc(static_cast<short>(frameWidth34 - 8), static_cast<short>(y));

  g_pSimMgr->NumToCurrency(nation->ComputeRemainingDiplomacyAidBudget(), &strA);
  short remainingX;
  if (nation->ComputeRemainingDiplomacyAidBudget() < 0) {
    g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x33);
    y += 0xc;
    remainingX = 0x7c;
  } else {
    y += 0xc;
    remainingX = 0x80;
  }
  SetQuickDrawTextOriginWithContextOffset(remainingX, y);
  DrawTextWithCachedQuickDrawStyleState(&strA);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b6a);
  g_pSimMgr->GetString(0x2740, 0x1b, &strB);
  g_pSimMgr->NumToCurrency(nation->diplomacyBudgetBase / 100, &strC);
  scanBracketExpressions(g_pSimMgr, &strA, static_cast<LPCSTR>(strB),
                         g_cstrTradeTotalsBalanceSubstitution0066DB50);

  y += 0xc;
  SetQuickDrawTextOriginWithContextOffset(8, y);
  DrawTextWithCachedQuickDrawStyleState(&strA);
  SetQuickDrawTextOriginWithContextOffset(0x80, y);
  DrawTextWithCachedQuickDrawStyleState(&strC);

  SetQuickDrawFillColorFromPaletteIndex(0);
}
