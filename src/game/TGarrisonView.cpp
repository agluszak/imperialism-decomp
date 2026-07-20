#include "game/TGarrisonView.h"
#include "game/CString.h"
#include "game/TArmyUnitLine.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/global_data_tables.h"
// SYNTHETIC: IMPERIALISM 0x004a8770
// TGarrisonView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a87f0
// TGarrisonView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGarrisonView, TMilitaryPageView)

// FUNCTION: IMPERIALISM 0x004a8810
TGarrisonView::TGarrisonView() {}

// FUNCTION: IMPERIALISM 0x004a8890
void TGarrisonView::StuffValues(short tileIndex) {
  PrepareUnitCache(0xdb8, 0xeff, 0x30);

  CString unusedTextA;
  CString unusedTextB;
  selectedTileIndex8C = tileIndex;

  TMilitaryUnit* unit = 0;
  if (tileIndex >= 0 && tileIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
  }

  int lineBounds[2] = {0xec, 0x31};
  while (unit != 0) {
    if (unit->field_8 != 1) {
      TArmyUnitLine* line = new TArmyUnitLine;
      line->SetLineDataRowAndBounds(0, 0, lineBounds);
      line->militaryUnit10 = unit;
      AddOrderedEntry(line);
    }
    unit = static_cast<TMilitaryUnit*>(unit->nextOnTile);
  }

  AfterStuffValues();
}

// SYNTHETIC: IMPERIALISM 0x004a8840
// TGarrisonView::`scalar deleting destructor'
TGarrisonView::~TGarrisonView() {}

// FUNCTION: IMPERIALISM 0x004a8a20
void TGarrisonView::Close() {}
