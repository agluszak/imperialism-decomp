#include "game/city/TPopGrowthOrder.h"
#include "game/city/TCity.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b3050
// TPopGrowthOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b3080
TPopGrowthOrder::~TPopGrowthOrder() {}
// SYNTHETIC: IMPERIALISM 0x004b8110
// TPopGrowthOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8140
// TPopGrowthOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPopGrowthOrder, TProductionOrder)

// FUNCTION: IMPERIALISM 0x004b8160
void TPopGrowthOrder::IPopGrowthOrder(TCity* city) {
  ownerCity = city;
  productionSummary = city != nullptr ? city->productionSummary1d8 : nullptr;
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
  short furnitureLimit = static_cast<short>(ownerCity->cityStockFurnitureD2 + currentQuantity);
  short clothingLimit = static_cast<short>(ownerCity->cityStockClothingD0 + currentQuantity);
  short foodLimit = static_cast<short>(ownerCity->cityStockCannedFoodC4 + currentQuantity);
  short capacityLimit = static_cast<short>(ownerCity->productionAccum1fc[0x0f] + currentQuantity);

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

  ownerCity->cityStockFurnitureD2 = static_cast<short>(ownerCity->cityStockFurnitureD2 - delta);
  ownerCity->VerifyStocks();
  ownerCity->cityStockClothingD0 = static_cast<short>(ownerCity->cityStockClothingD0 - delta);
  ownerCity->VerifyStocks();
  ownerCity->cityStockCannedFoodC4 = static_cast<short>(ownerCity->cityStockCannedFoodC4 - delta);
  ownerCity->VerifyStocks();
  ownerCity->productionAccum1fc[0x0f] =
      static_cast<short>(ownerCity->productionAccum1fc[0x0f] - delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b82f0
void TPopGrowthOrder::Produce() {
  short quantity = this->quantity;
  TPopulationMgr* population = ownerCity->productionSummary1d8;
  population->baselineSlots10->lowSkillCount04 += quantity;
  population->productionSlots14->lowSkillCount04 += quantity;
  population->populationCount08 += quantity;

  TCity* city = ownerCity;
  TGreatPower* owner = city->ownerNationAc;
  if (owner->pendingActionStatus.roles.expansionCapacityStatus09 >= '3') {
    int regionCount = owner->ownedRegionList->GetSize();
    if (regionCount / 3 > 1) {
      city->productionAccum1fc[0x0f] = static_cast<short>(owner->ownedRegionList->GetSize() / 3);
    } else {
      city->productionAccum1fc[0x0f] = 1;
    }
  } else {
    int regionCount = owner->ownedRegionList->GetSize();
    if (regionCount / 4 > 1) {
      city->productionAccum1fc[0x0f] = static_cast<short>(owner->ownedRegionList->GetSize() / 4);
    } else {
      city->productionAccum1fc[0x0f] = 1;
    }
  }
  quantity = 0;
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
