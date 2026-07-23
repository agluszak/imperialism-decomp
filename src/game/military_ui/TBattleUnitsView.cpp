#include "game/military_ui/TBattleUnitsView.h"
#include "game/ui_screens/CString.h"
#include "game/military_ui/TBatRepDetLine.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x00430b80
// TBattleUnitsView::`scalar deleting destructor'
TBattleUnitsView::~TBattleUnitsView() {}
// SYNTHETIC: IMPERIALISM 0x004b0630
// TBattleUnitsView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b06d0
// TBattleUnitsView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBattleUnitsView, TMilitaryPageView)

TBattleUnitsView::TBattleUnitsView() {}

// FUNCTION: IMPERIALISM 0x004b06f0
void TBattleUnitsView::StuffValues(BattleRecord* battleRecord, int participantIndex) {
  switch (battleRecord->battleType04) {
  case 0:
  case 3:
  case 4:
    primaryUnitAtlas84 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdb8);
    break;
  case 1:
    primaryUnitAtlas84 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdb8);
    secondaryUnitAtlas88 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdba);
    break;
  case 2:
    primaryUnitAtlas84 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdbb);
    secondaryUnitAtlas88 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xdba);
    break;
  }

  CString unusedTextA;
  CString unusedTextB;
  int detailCount = battleRecord->participantDetailCounts24a[participantIndex];
  for (int detailIndex = 0; detailIndex < detailCount; ++detailIndex) {
    TBatRepDetLine* line = new TBatRepDetLine;
    int lineBounds[2] = {0xec, 0x31};
    line->SetLineDataRowAndBounds(0, 0, lineBounds);
    line->battleRecord10 = battleRecord;
    line->battleDetail14 = battleRecord->participantDetails250[participantIndex] + detailIndex;
    AddOrderedEntry(line);
  }

  visibleColumnCount = 1;
  BuildPageLayout();
  ShowPage(1);
}

// FUNCTION: IMPERIALISM 0x004b0900
void TBattleUnitsView::Close() {
  TMilitaryPageView::Close();
  if (primaryUnitAtlas84 != 0) {
    g_pDisplayMgr->RemoveGWorld(primaryUnitAtlas84);
  }
  if (secondaryUnitAtlas88 != 0) {
    g_pDisplayMgr->RemoveGWorld(secondaryUnitAtlas88);
  }
}
