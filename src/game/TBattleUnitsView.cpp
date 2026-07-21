#include "game/TBattleUnitsView.h"
#include "game/TDisplayMgr.h"
#include "game/global_data_tables.h"

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
void TBattleUnitsView::StuffValues(BattleRecord* battleRecord, int participantIndex) {}

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
