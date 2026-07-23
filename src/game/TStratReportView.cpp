// TStratReportView wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TStratReportView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

#include "game/TCountry.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"
#include "game/quickdraw_rendering.h"

#include <new>

IMPLEMENT_DYNCREATE(TStratReportView, TView)

// SYNTHETIC: IMPERIALISM 0x0058e330
// TStratReportView::CreateObject

// FUNCTION: IMPERIALISM 0x0058e3c0
TStratReportView::TStratReportView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x0058e3f0
// TStratReportView::`scalar deleting destructor'
TStratReportView::~TStratReportView() {}

// Draws the battle-outcome header: fills the background, then "Battle of <location>",
// "Winner: <country>" with its per-unit-type counts, and "Loser: <country>" with its.
// FUNCTION: IMPERIALISM 0x0058e460
void TStratReportView::Draw(RECT* rectBuffer) {
  SetQuickDrawFillColor(0xffffff);
  FillRectWithQuickDrawBrushAndContextOffset(rectBuffer);

  CString lineBuffer;
  CString countText;
  CString sideName;
  CString locationName;

  SetQuickDrawFillColor(0);
  SetQuickDrawTextFont(3);
  SetQuickDrawTextFace(1);
  SetQuickDrawTextSize(0xa);
  SetQuickDrawTextOriginWithContextOffset(0xc, 0x40);

  g_pGlobalMapState->AssignCityRecordDisplayName(battleOutcome->location, &locationName);
  lineBuffer = "Battle of " + locationName;
  DrawTextWithCachedQuickDrawStyleState(&lineBuffer);

  g_apTerrainTypeDescriptorTable[battleOutcome->winnerId]->FormatOverlayTerrainLabelText(&sideName);
  lineBuffer = "Winner: " + sideName;
  SetQuickDrawTextOriginWithContextOffset(0xc, 0x50);
  DrawTextWithCachedQuickDrawStyleState(&lineBuffer);

  int y = 0x60;
  int i;
  SetQuickDrawTextFace(0);
  for (i = 0; i < 30; ++i) {
    if (battleOutcome->winnerCounts[i] != 0) {
      g_pSimMgr->GetString(0x2717, (short)i, &sideName);
      countText.Format(g_szDecimalFormat, battleOutcome->winnerCounts[i]);
      lineBuffer = countText + " " + sideName;
      SetQuickDrawTextOriginWithContextOffset(0xc, (short)y);
      DrawTextWithCachedQuickDrawStyleState(&lineBuffer);
      y += 0x10;
    }
  }

  SetQuickDrawTextFace(1);
  y += 0x10;
  g_apTerrainTypeDescriptorTable[battleOutcome->loserId]->FormatOverlayTerrainLabelText(&sideName);
  lineBuffer = "Loser: " + sideName;
  SetQuickDrawTextOriginWithContextOffset(0xc, (short)y);
  DrawTextWithCachedQuickDrawStyleState(&lineBuffer);
  y += 0x10;

  SetQuickDrawTextFace(0);
  for (i = 0; i < 30; ++i) {
    if (battleOutcome->loserCounts[i] != 0) {
      g_pSimMgr->GetString(0x2717, (short)i, &sideName);
      countText.Format(g_szDecimalFormat, battleOutcome->loserCounts[i]);
      lineBuffer = countText + " " + sideName;
      SetQuickDrawTextOriginWithContextOffset(0xc, (short)y);
      DrawTextWithCachedQuickDrawStyleState(&lineBuffer);
      y += 0x10;
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x0058e3a0
// TStratReportView::GetRuntimeClass
