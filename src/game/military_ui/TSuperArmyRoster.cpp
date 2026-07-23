#include "game/TSuperArmyRoster.h"

#include "game/TBook.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TMiniArmyLine.h"
#include "game/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x004aa4d0
// TSuperArmyRoster::`scalar deleting destructor'
TSuperArmyRoster::~TSuperArmyRoster() {}
// SYNTHETIC: IMPERIALISM 0x004aa450
// TSuperArmyRoster::CreateObject

// SYNTHETIC: IMPERIALISM 0x004aa520
// TSuperArmyRoster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSuperArmyRoster, TPageView)

// FUNCTION: IMPERIALISM 0x004aa540
void TSuperArmyRoster::PopulateArmyOrderPageEntries(TView* panel, int* offsetLayout,
                                                    int* sizeLayout) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
  controlTag = 0x70616765; // 'page'
  TPageView::DoPostCreate(0);

  short activeNation = g_pSimMgr->GetActiveNationId();
  for (int tileIndex = 0; tileIndex < 0x180; ++tileIndex) {
    if (g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(tileIndex) != activeNation) {
      continue;
    }
    for (TMilitaryUnit* unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
         unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
      TMiniArmyLine* line = new TMiniArmyLine;
      int lineBounds[2] = {0xec, 0x12};
      line->SetLineDataRowAndBounds(0, 0, lineBounds);
      line->militaryUnit10 = unit;
      AddOrderedEntry(line);
    }
  }

  visibleColumnCount = 2;
  BuildPageLayout();
  ShowPage(1);
  ownerContext->AssertValid();
  static_cast<TBook*>(ownerContext)->ShowPage(currentPage);
}
