#include "game/military_ui/TBattleUnitsView.h"
#include "game/core/CString.h"
#include "game/military_ui/TBatRepDetLine.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00430b50
TBattleUnitsView::TBattleUnitsView() {
  secondaryUnitAtlas = 0;
}

// FUNCTION: IMPERIALISM 0x00430bb0
TBattleUnitsView::~TBattleUnitsView() {}

IMPLEMENT_DYNCREATE(TBattleUnitsView, TMilitaryPageView)

// FUNCTION: IMPERIALISM 0x004b06f0
void TBattleUnitsView::StuffValues(BattleRecord& battleRecord, int participantIndex) {
  switch (battleRecord.reportKind04) {
  case kMapContextReportLandBattle:
  case kMapContextReportPreemptedLandBattle:
  case kMapContextReportUncontestedTakeover:
    primaryUnitAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdb8);
    break;
  case kMapContextReportSeaBattle:
    primaryUnitAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdb8);
    secondaryUnitAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdba);
    break;
  case kMapContextReportMerchantInterception:
    primaryUnitAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdbb);
    secondaryUnitAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdba);
    break;
  }

  CString unusedTextA;
  CString unusedTextB;
  int detailCount = battleRecord.childCount24a[participantIndex];
  for (int detailIndex = 0; detailIndex < detailCount; ++detailIndex) {
    TBatRepDetLine* line = new TBatRepDetLine;
    int lineBounds[2] = {0xec, 0x31};
    line->SetLineDataRowAndBounds(0, 0, lineBounds);
    line->battleRecord10 = &battleRecord;
    line->battleDetail = &battleRecord.sideChildRecords[participantIndex][detailIndex];
    AddOrderedEntry(line);
  }

  visibleColumnCount = 1;
  BuildPageLayout();
  ShowPage(1);
}

// FUNCTION: IMPERIALISM 0x004b0900
void TBattleUnitsView::Close() {
  TMilitaryPageView::Close();
  if (primaryUnitAtlas != 0) {
    g_pDisplayMgr->RemoveGWorld(primaryUnitAtlas);
  }
  if (secondaryUnitAtlas != 0) {
    g_pDisplayMgr->RemoveGWorld(secondaryUnitAtlas);
  }
}
