#include "game/TWarehouseView.h"
#include "game/TCity.h"
#include "game/TPictureNumberText.h"
#include "game/TPopulationMgr.h"
// SYNTHETIC: IMPERIALISM 0x004c71f0
// TWarehouseView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c7290
// TWarehouseView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TWarehouseView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004c72b0
TWarehouseView::TWarehouseView() : TBuildingView() {}

// SYNTHETIC: IMPERIALISM 0x004c72e0
// TWarehouseView::`scalar deleting destructor'
TWarehouseView::~TWarehouseView() {}

// FUNCTION: IMPERIALISM 0x004c7330
void TWarehouseView::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point, TToolboxEvent* event,
                                                          CPoint origin) {
  TControl::BeginMouseCaptureAndStartRepeatTimer(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x004c7360
void TWarehouseView::DoStartup() {}

// FUNCTION: IMPERIALISM 0x004c7d90
void TWarehouseView::UpdateFields() {
  for (short commodity = 0; commodity < 23; ++commodity) {
    TPictureNumberText* valueControl = commodityValueControlsA0[commodity];
    if (valueControl != 0) {
      short amount = city94->CityStockByType(commodity);
      if (valueControl->UpdateControlCachedIntFromWindowText() != amount) {
        if (commodity == 20) {
          amount = static_cast<short>(city94->cityStockFishDC + city94->cityStockLivestockDE);
          valueControl = commodityValueControlsA0[commodity];
        }
        valueControl->SetControlValue(amount, 1);
      }
    }
  }

  if (laborValueControlFC != 0) {
    short labor = city94->productionSummary1d8->strength;
    if (laborValueControlFC->UpdateControlCachedIntFromWindowText() != labor) {
      laborValueControlFC->SetControlValue(labor, 1);
    }
  }

  if (powerValueControl100 != 0) {
    short power = city94->powerAvailableB4;
    if (powerValueControl100->UpdateControlCachedIntFromWindowText() != power) {
      powerValueControl100->SetControlValue(power, 1);
    }
  }
}
