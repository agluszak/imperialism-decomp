#include "game/city/TFoodProcessingOrder.h"

#include "game/city/TCity.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"

IMPLEMENT_DYNCREATE(TFoodProcessingOrder, TProductionOrder)

// FUNCTION: IMPERIALISM 0x004b7e80
void TFoodProcessingOrder::IFoodProcessingOrder(TCity* city) {
  TProductionOrder::IProductionOrder(city, 7);
}

// FUNCTION: IMPERIALISM 0x004b7ed0
short TFoodProcessingOrder::MaxOrder() {
  short limit = static_cast<short>(ownerCity->cityStockGrain / 2);
  short fishAndLivestock =
      static_cast<short>(ownerCity->cityStockFish + ownerCity->cityStockLivestock);
  short workforceLimit = static_cast<short>(productionSummary->strength / 2);
  if (ownerCity->cityStockFruit < limit) {
    limit = ownerCity->cityStockFruit;
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
  ownerCity->cityStockGrain = static_cast<short>(ownerCity->cityStockGrain - halfDelta * 2);
  ownerCity->VerifyStocks();
  ownerCity->cityStockFruit = static_cast<short>(ownerCity->cityStockFruit - halfDelta);
  ownerCity->VerifyStocks();
  productionSummary->strength = static_cast<short>(productionSummary->strength - halfDelta * 2);

  short livestock = ownerCity->cityStockLivestock;
  if (livestock < halfDelta) {
    ownerCity->cityStockLivestock = 0;
    ownerCity->VerifyStocks();
    ownerCity->cityStockFish =
        static_cast<short>(ownerCity->cityStockFish - (halfDelta - livestock));
  } else {
    ownerCity->cityStockLivestock = static_cast<short>(ownerCity->cityStockLivestock - halfDelta);
  }
  ownerCity->VerifyStocks();
  g_pViewMgr->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b8060
void TFoodProcessingOrder::Produce() {
  TCity* city = ownerCity;
  city->cityStockCannedFood += quantity;
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
