#include "game/city/TPopGrowthOrder.h"
#include "game/city/TCity.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"

IMPLEMENT_DYNCREATE(TPopGrowthOrder, TProductionOrder)

// FUNCTION: IMPERIALISM 0x004b8160
void TPopGrowthOrder::IPopGrowthOrder(TCity* city) {
  ownerCity = city;
  productionSummary = city != NULL ? city->productionSummary : NULL;
  resourceTypeIndex = 1;
  quantity = 0;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    trackingSlots[resource] = 0;
  }
  accumulatedValue = 0;
  limitingConstraint = kProductionOrderLimitResources;
  reservedWorkforce = 0;
}

// FUNCTION: IMPERIALISM 0x004b81b0
short TPopGrowthOrder::MaxOrder() {
  short currentQuantity = quantity;
  short furnitureLimit = static_cast<short>(ownerCity->cityStockFurniture + currentQuantity);
  short clothingLimit = static_cast<short>(ownerCity->cityStockClothing + currentQuantity);
  short foodLimit = static_cast<short>(ownerCity->cityStockCannedFood + currentQuantity);
  short capacityLimit = static_cast<short>(ownerCity->productionAccum[0x0f] + currentQuantity);

  limitingConstraint = kProductionOrderLimitResources;
  short limit = furnitureLimit;
  if (clothingLimit < limit) {
    limit = clothingLimit;
  }
  if (foodLimit < limit) {
    limit = foodLimit;
  }
  if (capacityLimit < limit) {
    limitingConstraint = kProductionOrderLimitCapacity;
    limit = capacityLimit;
  }
  return limit;
}

// FUNCTION: IMPERIALISM 0x004b8230
bool TPopGrowthOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - this->quantity);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  this->quantity = quantity;

  ownerCity->cityStockFurniture = static_cast<short>(ownerCity->cityStockFurniture - delta);
  ownerCity->VerifyStocks();
  ownerCity->cityStockClothing = static_cast<short>(ownerCity->cityStockClothing - delta);
  ownerCity->VerifyStocks();
  ownerCity->cityStockCannedFood = static_cast<short>(ownerCity->cityStockCannedFood - delta);
  ownerCity->VerifyStocks();
  ownerCity->productionAccum[0x0f] = static_cast<short>(ownerCity->productionAccum[0x0f] - delta);
  g_pViewMgr->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b82f0
void TPopGrowthOrder::Produce() {
  short quantity = this->quantity;
  TPopulationMgr* population = ownerCity->productionSummary;
  population->baselineSlots->lowSkillCount += quantity;
  population->productionSlots->lowSkillCount += quantity;
  population->populationCount += quantity;

  TCity* city = ownerCity;
  TGreatPower* owner = city->ownerNation;
  if (owner->pendingActionStatus.byAction[9] >= '3') {
    int regionCount = owner->ownedRegionList->GetSize();
    if (regionCount / 3 > 1) {
      city->productionAccum[0x0f] = static_cast<short>(owner->ownedRegionList->GetSize() / 3);
    } else {
      city->productionAccum[0x0f] = 1;
    }
  } else {
    int regionCount = owner->ownedRegionList->GetSize();
    if (regionCount / 4 > 1) {
      city->productionAccum[0x0f] = static_cast<short>(owner->ownedRegionList->GetSize() / 4);
    } else {
      city->productionAccum[0x0f] = 1;
    }
  }
  this->quantity = 0;
}

// FUNCTION: IMPERIALISM 0x004b8420
void TPopGrowthOrder::Restock() {}

// FUNCTION: IMPERIALISM 0x004b8440
void TPopGrowthOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->ResetOrderSheet(orderSheet);
  orderSheet->slotByResourceCode[0x0d] = quantity;
  orderSheet->slotByResourceCode[0x0e] = quantity;
  orderSheet->slotByResourceCode[0x07] = quantity;
}
