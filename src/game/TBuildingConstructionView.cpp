#include "game/TBuildingConstructionView.h"

#include "game/TCity.h"
#include "game/TCityProductionView.h"
#include "game/TProductionOrder.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_tags_common.h"
// SYNTHETIC: IMPERIALISM 0x004c9d70
// TBuildingConstructionView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c9e10
// TBuildingConstructionView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBuildingConstructionView, TPicture)

// FUNCTION: IMPERIALISM 0x004c9e30
TBuildingConstructionView::TBuildingConstructionView()
    : TPicture(), city90(0), productionView98(0) {}

// SYNTHETIC: IMPERIALISM 0x004c9e60
// TBuildingConstructionView::`scalar deleting destructor'
TBuildingConstructionView::~TBuildingConstructionView() {}

// FUNCTION: IMPERIALISM 0x004c9eb0
void TBuildingConstructionView::StuffValues(short buildingSlotId, TCity* city,
                                            TCityProductionView* productionView) {}

// FUNCTION: IMPERIALISM 0x004ca8f0
void TBuildingConstructionView::DoClosingAction(unsigned long dialogActionTag) {
  if (buildingSlotId94 != 0xb) {
    TProductionOrder* order =
        static_cast<TProductionOrder*>(city90->orderSlotsE4[buildingSlotId94 + 0x35]);
    if (order == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0x519);
    }
    if (dialogActionTag == kControlTagOkay) { // 'okay'
      short previousBuildingType = static_cast<short>(city90->GetBuildingType(buildingSlotId94));
      order->SetQuantity(static_cast<short>(city90->GetMaxBuildingCapacity(buildingSlotId94) -
                                            previousBuildingType));
    } else if (order->quantityField04 > 0) {
      order->SetQuantity(0);
    }
  } else if (dialogActionTag == kControlTagOkay) { // 'okay'
    city90->BuildPowerPlant(1);
  }

  productionView98->SetBuildingPicture(
      buildingSlotId94, static_cast<short>(city90->GetBuildingType(buildingSlotId94)));
  productionView98->UpdateToolbar();
  productionView98->RefreshControl();
}
