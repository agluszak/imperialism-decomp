#include "game/city/TExpansionOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b8f50
// TExpansionOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8f80
// TExpansionOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TExpansionOrder, TItemOrder)

// SYNTHETIC: IMPERIALISM 0x004b8fc0
// TExpansionOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b8ff0
TExpansionOrder::~TExpansionOrder() {}

// FUNCTION: IMPERIALISM 0x004b9010
void TExpansionOrder::IExpansionOrder(TCity* city, short resourceType, short primaryInputResource,
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

// FUNCTION: IMPERIALISM 0x004b9090
void TExpansionOrder::Produce() {
  short zero = 0;
  if (quantity == zero) {
    return;
  }

  TCity* city = ownerCity;
  short newValue;
  if (resourceTypeIndex == 0x0f) {
    TGreatPower* owner = city->ownerNationAc;
    signed char usesThreeRegionsPerLevel =
        owner->pendingActionStatus.roles.expansionCapacityStatus09 >= '3';
    if (usesThreeRegionsPerLevel != zero) {
      int regionCount = owner->ownedRegionList->GetSize();
      if (regionCount / 3 > 1) {
        newValue = static_cast<short>(city->ownerNationAc->ownedRegionList->GetSize() / 3);
      } else {
        newValue = 1;
      }
    } else {
      int regionCount = owner->ownedRegionList->GetSize();
      if (regionCount / 4 > 1) {
        newValue = static_cast<short>(city->ownerNationAc->ownedRegionList->GetSize() / 4);
      } else {
        newValue = 1;
      }
    }
  } else {
    newValue = city->productionOrderTable1dc[resourceTypeIndex];
  }

  newValue = static_cast<short>(newValue + quantity);
  short delta = static_cast<short>(newValue - city->productionOrderTable1dc[resourceTypeIndex]);
  city->productionAccum1fc[resourceTypeIndex] =
      static_cast<short>(city->productionAccum1fc[resourceTypeIndex] + delta);
  city->productionOrderTable1dc[resourceTypeIndex] = newValue;
  requestedQuantity4c = zero;
  quantity = zero;
  trackingSlots[primaryInputResourceId] = zero;
  trackingSlots[secondaryInputResourceId] = zero;
}

// FUNCTION: IMPERIALISM 0x004b91f0
short TExpansionOrder::MaxOrder() {
  short limit = static_cast<short>(trackingSlots[primaryInputResourceId] +
                                   ownerCity->CityStockByType(primaryInputResourceId));
  if (secondaryInputResourceId < 0) {
    limit = static_cast<short>(limit / 2);
  } else {
    short secondaryLimit = static_cast<short>(trackingSlots[secondaryInputResourceId] +
                                              ownerCity->CityStockByType(secondaryInputResourceId));
    if (secondaryLimit < limit) {
      limit = secondaryLimit;
    }
  }
  return limit;
}

// FUNCTION: IMPERIALISM 0x004b9260
bool TExpansionOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - this->quantity);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  this->quantity = quantity;
  requestedQuantity4c = quantity;

  ownerCity->CityStockByType(primaryInputResourceId) =
      static_cast<short>(ownerCity->CityStockByType(primaryInputResourceId) - delta);
  ownerCity->VerifyStocks();
  trackingSlots[primaryInputResourceId] =
      static_cast<short>(trackingSlots[primaryInputResourceId] + delta);
  ownerCity->CityStockByType(secondaryInputResourceId) =
      static_cast<short>(ownerCity->CityStockByType(secondaryInputResourceId) - delta);
  ownerCity->VerifyStocks();
  trackingSlots[secondaryInputResourceId] =
      static_cast<short>(trackingSlots[secondaryInputResourceId] + delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b9360
void TExpansionOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->ResetOrderSheet(orderSheet);
  orderSheet->ForResourceCode(this->primaryInputResourceId) = quantity;
  if (orderSheet->ForResourceCode(this->primaryInputResourceId) < 0) {
    orderSheet->ForResourceCode(this->primaryInputResourceId) = 0;
  }
  orderSheet->ForResourceCode(this->secondaryInputResourceId) = quantity;
  if (orderSheet->ForResourceCode(this->secondaryInputResourceId) < 0) {
    orderSheet->ForResourceCode(this->secondaryInputResourceId) = 0;
  }
}

// WriteByteSwappedShortArrayToStream (0x004b94a0) moved to
// src/game/core/stream_byteswap.cpp alongside its read-side counterpart.
