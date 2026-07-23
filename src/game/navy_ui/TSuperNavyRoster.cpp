#include "game/navy_ui/TSuperNavyRoster.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/TBook.h"
#include "game/navy_ui/TMiniShipLine.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TZone.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/navy_order.h"

// SYNTHETIC: IMPERIALISM 0x00569870
// TSuperNavyRoster::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005698a0
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
