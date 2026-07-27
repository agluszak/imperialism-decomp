#include "game/city/TPopGrowthOrder.h"
#include "game/city/TCity.h"
#include "game/globals/prelude.h"
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
  cityField08 = city;
  summaryField0c = city != nullptr ? city->productionSummary1d8 : nullptr;
  resourceTypeIndex48 = 1;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
}

// FUNCTION: IMPERIALISM 0x004b81b0
short TPopGrowthOrder::MaxOrder() {
  short currentQuantity = quantityField04;
  short furnitureLimit = static_cast<short>(cityField08->cityStockFurnitureD2 + currentQuantity);
  short clothingLimit = static_cast<short>(cityField08->cityStockClothingD0 + currentQuantity);
  short foodLimit = static_cast<short>(cityField08->cityStockCannedFoodC4 + currentQuantity);
  short capacityLimit = static_cast<short>(cityField08->productionAccum1fc[0x0f] + currentQuantity);

  field40 = 0;
  short limit = furnitureLimit;
  if (clothingLimit < limit) {
    limit = clothingLimit;
  }
  if (foodLimit < limit) {
    limit = foodLimit;
  }
  if (capacityLimit < limit) {
    field40 = 2;
    limit = capacityLimit;
  }
  return limit;
}

// FUNCTION: IMPERIALISM 0x004b8230
bool TPopGrowthOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - quantityField04);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  quantityField04 = quantity;

  cityField08->cityStockFurnitureD2 = static_cast<short>(cityField08->cityStockFurnitureD2 - delta);
  cityField08->VerifyStocks();
  cityField08->cityStockClothingD0 = static_cast<short>(cityField08->cityStockClothingD0 - delta);
  cityField08->VerifyStocks();
  cityField08->cityStockCannedFoodC4 =
      static_cast<short>(cityField08->cityStockCannedFoodC4 - delta);
  cityField08->VerifyStocks();
  cityField08->productionAccum1fc[0x0f] =
      static_cast<short>(cityField08->productionAccum1fc[0x0f] - delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b82f0
void TPopGrowthOrder::Produce() {
  short quantity = quantityField04;
  TPopulationMgr* population = cityField08->productionSummary1d8;
  population->baselineSlots10->lowSkillCount04 += quantity;
  population->productionSlots14->lowSkillCount04 += quantity;
  population->populationCount08 += quantity;

  TCity* city = cityField08;
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
  quantityField04 = 0;
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
