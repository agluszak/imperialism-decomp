#include "game/city/TFoodProcessingOrder.h"

#include "game/city/TCity.h"
#include "game/globals/global_types.h"
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
  ownerCity = city;
  productionSummary = city->productionSummary1d8;
  resourceTypeIndex = 7;
  quantity = 0;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    trackingSlots[resource] = 0;
  }
  accumulatedValue = 0;
  limitingConstraint = kProductionOrderLimitResources;
  reservedWorkforce = 0;
}

// FUNCTION: IMPERIALISM 0x004b7ed0
short TFoodProcessingOrder::MaxOrder() {
  short limit = static_cast<short>(ownerCity->cityStockGrainD8 / 2);
  short fishAndLivestock =
      static_cast<short>(ownerCity->cityStockFishDC + ownerCity->cityStockLivestockDE);
  short workforceLimit = static_cast<short>(productionSummary->strength / 2);
  if (ownerCity->cityStockFruitDA < limit) {
    limit = ownerCity->cityStockFruitDA;
  }
  if (fishAndLivestock < limit) {
    limit = fishAndLivestock;
  }
  if (workforceLimit < limit) {
    limit = workforceLimit;
  }
  return static_cast<short>(quantity + limit * 2);
}

// FUNCTION: IMPERIALISM 0x004b7f50
bool TFoodProcessingOrder::SetQuantity(short quantity) {
  if ((quantity & 1) != 0) {
    ++quantity;
  }
  short previousQuantity = this->quantity;
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  this->quantity = quantity;

  short halfDelta = static_cast<short>((quantity - previousQuantity) / 2);
  ownerCity->cityStockGrainD8 = static_cast<short>(ownerCity->cityStockGrainD8 - halfDelta * 2);
  ownerCity->VerifyStocks();
  ownerCity->cityStockFruitDA = static_cast<short>(ownerCity->cityStockFruitDA - halfDelta);
  ownerCity->VerifyStocks();
  productionSummary->strength = static_cast<short>(productionSummary->strength - halfDelta * 2);

  short livestock = ownerCity->cityStockLivestockDE;
  if (livestock < halfDelta) {
    ownerCity->cityStockLivestockDE = 0;
    ownerCity->VerifyStocks();
    ownerCity->cityStockFishDC =
        static_cast<short>(ownerCity->cityStockFishDC - (halfDelta - livestock));
  } else {
    ownerCity->cityStockLivestockDE =
        static_cast<short>(ownerCity->cityStockLivestockDE - halfDelta);
  }
  ownerCity->VerifyStocks();
  g_pViewMgr->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b8060
void TFoodProcessingOrder::Produce() {
  TCity* city = ownerCity;
  city->cityStockCannedFoodC4 += quantity;
  city->VerifyStocks();
  quantity = 0;
  reservedWorkforce = 0;
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
