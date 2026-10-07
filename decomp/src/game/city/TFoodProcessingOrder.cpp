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
  short limit = ownerCity->stockByType[kResourceGrain] / 2;
  short fishAndLivestock = static_cast<short>(ownerCity->stockByType[kResourceFish] +
                                              ownerCity->stockByType[kResourceLivestock]);
  short workforceLimit = productionSummary->strength / 2;
  if (ownerCity->stockByType[kResourceFruit] < limit) {
    limit = ownerCity->stockByType[kResourceFruit];
  }
  if (fishAndLivestock < limit) {
    limit = fishAndLivestock;
  }
  if (workforceLimit < limit) {
    limit = workforceLimit;
  }
  return quantity + limit * 2;
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

  short halfDelta = (quantity - previousQuantity) / 2;
  ownerCity->stockByType[kResourceGrain] =
      static_cast<short>(ownerCity->stockByType[kResourceGrain] - halfDelta * 2);
  ownerCity->VerifyStocks();
  ownerCity->stockByType[kResourceFruit] =
      static_cast<short>(ownerCity->stockByType[kResourceFruit] - halfDelta);
  ownerCity->VerifyStocks();
  productionSummary->strength = static_cast<short>(productionSummary->strength - halfDelta * 2);

  short livestock = ownerCity->stockByType[kResourceLivestock];
  if (livestock < halfDelta) {
    ownerCity->stockByType[kResourceLivestock] = 0;
    ownerCity->VerifyStocks();
    ownerCity->stockByType[kResourceFish] =
        static_cast<short>(ownerCity->stockByType[kResourceFish] - (halfDelta - livestock));
  } else {
    ownerCity->stockByType[kResourceLivestock] =
        static_cast<short>(ownerCity->stockByType[kResourceLivestock] - halfDelta);
  }
  ownerCity->VerifyStocks();
  g_pViewMgr->UpdateCityScreen();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b8060
void TFoodProcessingOrder::Produce() {
  TCity* city = ownerCity;
  city->stockByType[kResourceFood] += quantity;
  city->VerifyStocks();
  quantity = 0;
  reservedWorkforce = 0;
}

// FUNCTION: IMPERIALISM 0x004b80a0
void TFoodProcessingOrder::Restock() {}

// FUNCTION: IMPERIALISM 0x004b80c0
void TFoodProcessingOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  if (quantity & 1) {
    ++quantity;
  }
  ResetOrderSheet(orderSheet);
  orderSheet->slotByResourceCode[17] = quantity;
  orderSheet->slotByResourceCode[18] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[20] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[61] = quantity;
}
