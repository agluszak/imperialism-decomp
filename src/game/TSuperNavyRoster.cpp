#include "game/TSuperNavyRoster.h"

#include "game/TBook.h"
#include "game/TMiniShipLine.h"
#include "game/TShip.h"
#include "game/TSimMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/navy_order.h"
#include "game/ui_tags_common.h"

// SYNTHETIC: IMPERIALISM 0x00569870
// TSuperNavyRoster::`scalar deleting destructor'
TSuperNavyRoster::~TSuperNavyRoster() {}
// SYNTHETIC: IMPERIALISM 0x005697d0
// TSuperNavyRoster::CreateObject

// SYNTHETIC: IMPERIALISM 0x005698c0
// TSuperNavyRoster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSuperNavyRoster, TPageView)

// FUNCTION: IMPERIALISM 0x005698e0
void TSuperNavyRoster::PopulateNavyOrderPageEntriesByMapContext(TView* panel, int* offsetLayout,
                                                                int* sizeLayout) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
  controlTag = kControlTagPage; // 'page'
  TPageView::DoPostCreate(0);

  short activeNation = g_pSimMgr->GetActiveNationId();
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
      if (ship->location != zone || ship->nation != activeNation) {
        continue;
      }
      TMiniShipLine* line = new TMiniShipLine;
      int lineBounds[2] = {0xec, 0x12};
      line->SetLineDataRowAndBounds(0, 0, lineBounds);
      line->field10 = ship;
      AddOrderedEntry(line);
    }
  }

  visibleColumnCount = 2;
  BuildPageLayout();
  ShowPage(1);
  ownerContext->AssertValid();
  static_cast<TBook*>(ownerContext)->ShowPage(currentPage);
}
