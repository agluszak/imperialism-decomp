#include "game/city/TFoodProcessingOrder.h"

#include "game/city/TCity.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b7dc0
// TFoodProcessingOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b7df0
// TFoodProcessingOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFoodProcessingOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b7e30
// TFoodProcessingOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b7e60
TFoodProcessingOrder::~TFoodProcessingOrder() {}

// FUNCTION: IMPERIALISM 0x004b7e80
void TFoodProcessingOrder::IFoodProcessingOrder(TCity* city) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = 7;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
}

// FUNCTION: IMPERIALISM 0x004b7ed0
short TFoodProcessingOrder::MaxOrder() {
  short limit = static_cast<short>(cityField08->cityStockGrainD8 / 2);
  short fishAndLivestock =
      static_cast<short>(cityField08->cityStockFishDC + cityField08->cityStockLivestockDE);
  short workforceLimit = static_cast<short>(summaryField0c->strength / 2);
  if (cityField08->cityStockFruitDA < limit) {
    limit = cityField08->cityStockFruitDA;
  }
  if (fishAndLivestock < limit) {
    limit = fishAndLivestock;
  }
  if (workforceLimit < limit) {
    limit = workforceLimit;
  }
  return static_cast<short>(quantityField04 + limit * 2);
}

// FUNCTION: IMPERIALISM 0x004b7f50
bool TFoodProcessingOrder::SetQuantity(short quantity) {
  if ((quantity & 1) != 0) {
    ++quantity;
  }
  short previousQuantity = quantityField04;
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  quantityField04 = quantity;

  short halfDelta = static_cast<short>((quantity - previousQuantity) / 2);
  cityField08->cityStockGrainD8 = static_cast<short>(cityField08->cityStockGrainD8 - halfDelta * 2);
  cityField08->VerifyStocks();
  cityField08->cityStockFruitDA = static_cast<short>(cityField08->cityStockFruitDA - halfDelta);
  cityField08->VerifyStocks();
  summaryField0c->strength = static_cast<short>(summaryField0c->strength - halfDelta * 2);

  short livestock = cityField08->cityStockLivestockDE;
  if (livestock < halfDelta) {
    cityField08->cityStockLivestockDE = 0;
    cityField08->VerifyStocks();
    cityField08->cityStockFishDC =
        static_cast<short>(cityField08->cityStockFishDC - (halfDelta - livestock));
  } else {
    cityField08->cityStockLivestockDE =
        static_cast<short>(cityField08->cityStockLivestockDE - halfDelta);
  }
  cityField08->VerifyStocks();
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b8060
void TFoodProcessingOrder::Produce() {
  TCity* city = cityField08;
  city->cityStockCannedFoodC4 += quantityField04;
  city->VerifyStocks();
  quantityField04 = 0;
  field3e = 0;
}

// FUNCTION: IMPERIALISM 0x004b80a0
void TFoodProcessingOrder::Restock() {}

// FUNCTION: IMPERIALISM 0x004b80c0
void TFoodProcessingOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  if (quantity & 1) {
    quantity = static_cast<short>(quantity + 1);
  }
  this->ResetOrderSheet(orderSheet);
  orderSheet->slotByResourceCode[0x11] = quantity;
  orderSheet->slotByResourceCode[0x12] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[0x14] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[0x3d] = quantity;
}
