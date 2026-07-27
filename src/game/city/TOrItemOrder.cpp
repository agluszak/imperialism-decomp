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
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = resourceType;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  primaryInputResourceId = primaryInputResource;
  field40 = 0;
  field3e = 0;
  requestedQuantity4c = 0;
  secondaryInputResourceId = secondaryInputResource;
  productionSlot = productionSlotValue;
}

// FUNCTION: IMPERIALISM 0x004b58f0
short TOrItemOrder::MaxOrder() {
  short currentQuantity = quantityField04;
  short workforceLimit = static_cast<short>(summaryField0c->strength / 2 + currentQuantity);
  short resourceLimit = static_cast<short>((trackingSlots10[secondaryInputResourceId] +
                                            trackingSlots10[primaryInputResourceId] +
                                            cityField08->CityStockByType(secondaryInputResourceId) +
                                            cityField08->CityStockByType(primaryInputResourceId)) /
                                           2);
  short productionLimit =
      static_cast<short>(cityField08->productionAccum1fc[productionSlot] + currentQuantity);

  field40 = 2;
  short limit = productionLimit;
  if (workforceLimit < limit) {
    field40 = 1;
    limit = workforceLimit;
  }
  if (resourceLimit < limit) {
    field40 = 0;
    limit = resourceLimit;
  }
  return limit;
}

// FUNCTION: IMPERIALISM 0x004b5990
bool TOrItemOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - quantityField04);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  quantityField04 = quantity;
  requestedQuantity4c = quantityField04;

  short primaryAvailable;
  short secondaryAvailable;
  short primaryChange;
  short secondaryChange;
  if (delta > 0) {
    primaryAvailable = cityField08->CityStockByType(primaryInputResourceId);
    secondaryAvailable = cityField08->CityStockByType(secondaryInputResourceId);
    primaryChange = delta;
    secondaryChange = delta;
  } else {
    primaryAvailable = trackingSlots10[primaryInputResourceId];
    secondaryAvailable = trackingSlots10[secondaryInputResourceId];
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

  cityField08->CityStockByType(primaryInputResourceId) =
      static_cast<short>(cityField08->CityStockByType(primaryInputResourceId) - primaryChange);
  cityField08->VerifyStocks();
  trackingSlots10[primaryInputResourceId] =
      static_cast<short>(trackingSlots10[primaryInputResourceId] + primaryChange);
  cityField08->CityStockByType(secondaryInputResourceId) =
      static_cast<short>(cityField08->CityStockByType(secondaryInputResourceId) - secondaryChange);
  cityField08->VerifyStocks();
  trackingSlots10[secondaryInputResourceId] =
      static_cast<short>(trackingSlots10[secondaryInputResourceId] + secondaryChange);

  short workforceChange = static_cast<short>(delta * 2);
  summaryField0c->strength = static_cast<short>(summaryField0c->strength - workforceChange);
  field3e = static_cast<short>(field3e + workforceChange);
  cityField08->productionAccum1fc[productionSlot] =
      static_cast<short>(cityField08->productionAccum1fc[productionSlot] - delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
}
