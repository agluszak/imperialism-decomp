#include "game/city_ui/TBuildingExpansionView.h"
#include "game/ui_tags_common.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/city/TProductionOrder.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x004ce480
// TBuildingExpansionView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ce500
// TBuildingExpansionView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBuildingExpansionView, TPicture)

TBuildingExpansionView::TBuildingExpansionView() {}

// SYNTHETIC: IMPERIALISM 0x004ce550
// TBuildingExpansionView::`scalar deleting destructor'
TBuildingExpansionView::~TBuildingExpansionView() {}

// FUNCTION: IMPERIALISM 0x004ce5a0
void TBuildingExpansionView::StuffValues(short buildingSlotId, TCity* city,
                                         TCityProductionView* productionView) {}

// FUNCTION: IMPERIALISM 0x004cebb0
void TBuildingExpansionView::DoClosingAction(unsigned long dialogActionTag) {
  TProductionOrder* order =
      static_cast<TProductionOrder*>(city94->orderSlotsE4[buildingSlotId90 + 0x35]);
  if (order == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xac6);
  }
  if (dialogActionTag == kControlTagOkay) { // 'okay'
    short previousBuildingType = static_cast<short>(city94->GetBuildingType(buildingSlotId90));
    order->SetQuantity(static_cast<short>(city94->GetMaxBuildingCapacity(buildingSlotId90) -
                                          previousBuildingType));
  } else if (order->quantityField04 > 0) {
    order->SetQuantity(0);
  }

  productionView98->SetBuildingPicture(
      buildingSlotId90, static_cast<short>(city94->GetBuildingType(buildingSlotId90)));
  productionView98->UpdateToolbar();
  productionView98->RefreshControl();
}
