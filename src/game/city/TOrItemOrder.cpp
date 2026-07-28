#include "game/city/TOrItemOrder.h"

#include "game/city/TCity.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"
// SYNTHETIC: IMPERIALISM 0x004b57b0
// TOrItemOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b57e0
// TOrItemOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOrItemOrder, TItemOrder)

// SYNTHETIC: IMPERIALISM 0x004b5820
// TOrItemOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b5850
TOrItemOrder::~TOrItemOrder() {}

// FUNCTION: IMPERIALISM 0x004b5870
void TOrItemOrder::IOrItemOrder(TCity* city, short resourceType, short primaryInputResource,
                                short secondaryInputResource, short productionSlotValue) {
  ownerCity = city;
  productionSummary = city->productionSummary1d8;
  resourceTypeIndex = resourceType;
  quantity = 0;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    trackingSlots[resource] = 0;
  }
  accumulatedValue = 0;
  primaryInputResourceId = primaryInputResource;
  limitingConstraint = kProductionOrderLimitResources;
  reservedWorkforce = 0;
  requestedQuantity4c = 0;
  secondaryInputResourceId = secondaryInputResource;
  productionSlot = productionSlotValue;
}

// FUNCTION: IMPERIALISM 0x004b58f0
short TOrItemOrder::MaxOrder() {
  short currentQuantity = quantity;
  short workforceLimit = static_cast<short>(productionSummary->strength / 2 + currentQuantity);
  short resourceLimit = static_cast<short>((trackingSlots[secondaryInputResourceId] +
                                            trackingSlots[primaryInputResourceId] +
                                            ownerCity->CityStockByType(secondaryInputResourceId) +
                                            ownerCity->CityStockByType(primaryInputResourceId)) /
                                           2);
  short productionLimit =
      static_cast<short>(ownerCity->productionAccum1fc[productionSlot] + currentQuantity);

  limitingConstraint = kProductionOrderLimitCapacity;
  short limit = productionLimit;
  if (workforceLimit < limit) {
    limitingConstraint = kProductionOrderLimitWorkforce;
    limit = workforceLimit;
  }
  if (resourceLimit < limit) {
    limitingConstraint = kProductionOrderLimitResources;
    limit = resourceLimit;
  }
  return limit;
}

// FUNCTION: IMPERIALISM 0x004b5990
bool TOrItemOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - this->quantity);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  this->quantity = quantity;
  requestedQuantity4c = quantity;

  short primaryAvailable;
  short secondaryAvailable;
  short primaryChange;
  short secondaryChange;
  if (delta > 0) {
    primaryAvailable = ownerCity->CityStockByType(primaryInputResourceId);
    secondaryAvailable = ownerCity->CityStockByType(secondaryInputResourceId);
    primaryChange = delta;
    secondaryChange = delta;
  } else {
    primaryAvailable = trackingSlots[primaryInputResourceId];
    secondaryAvailable = trackingSlots[secondaryInputResourceId];
    primaryChange = static_cast<short>(-delta);
    secondaryChange = primaryChange;
  }

  if (primaryAvailable < primaryChange) {
    short shortfall = static_cast<short>(primaryChange - primaryAvailable);
    primaryChange = static_cast<short>(primaryChange - shortfall);
    secondaryChange = static_cast<short>(secondaryChange + shortfall);
  } else if (secondaryAvailable < secondaryChange) {
    short shortfall = static_cast<short>(secondaryChange - secondaryAvailable);
    secondaryChange = static_cast<short>(secondaryChange - shortfall);
    primaryChange = static_cast<short>(primaryChange + shortfall);
  }
  if (delta < 0) {
    primaryChange = static_cast<short>(-primaryChange);
    secondaryChange = static_cast<short>(-secondaryChange);
  }

  ownerCity->CityStockByType(primaryInputResourceId) =
      static_cast<short>(ownerCity->CityStockByType(primaryInputResourceId) - primaryChange);
  ownerCity->VerifyStocks();
  trackingSlots[primaryInputResourceId] =
      static_cast<short>(trackingSlots[primaryInputResourceId] + primaryChange);
  ownerCity->CityStockByType(secondaryInputResourceId) =
      static_cast<short>(ownerCity->CityStockByType(secondaryInputResourceId) - secondaryChange);
  ownerCity->VerifyStocks();
  trackingSlots[secondaryInputResourceId] =
      static_cast<short>(trackingSlots[secondaryInputResourceId] + secondaryChange);

  short workforceChange = static_cast<short>(delta * 2);
  productionSummary->strength = static_cast<short>(productionSummary->strength - workforceChange);
  reservedWorkforce = static_cast<short>(reservedWorkforce + workforceChange);
  ownerCity->productionAccum1fc[productionSlot] =
      static_cast<short>(ownerCity->productionAccum1fc[productionSlot] - delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
}
