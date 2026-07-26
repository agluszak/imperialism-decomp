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

// FUNCTION: IMPERIALISM 0x004b9090
void TExpansionOrder::Produce() {
  short zero = 0;
  if (quantityField04 == zero) {
    return;
  }

  TCity* city = cityField08;
  short newValue;
  if (resourceTypeIndex48 == 0x0f) {
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
    newValue = city->productionOrderTable1dc[resourceTypeIndex48];
  }

  newValue = static_cast<short>(newValue + quantityField04);
  short delta = static_cast<short>(newValue - city->productionOrderTable1dc[resourceTypeIndex48]);
  city->productionAccum1fc[resourceTypeIndex48] =
      static_cast<short>(city->productionAccum1fc[resourceTypeIndex48] + delta);
  city->productionOrderTable1dc[resourceTypeIndex48] = newValue;
  requestedQuantity4c = zero;
  quantityField04 = zero;
  trackingSlots10[primaryInputResourceId] = zero;
  trackingSlots10[secondaryInputResourceId] = zero;
}

// FUNCTION: IMPERIALISM 0x004b91f0
short TExpansionOrder::MaxOrder() {
  short limit = static_cast<short>(trackingSlots10[primaryInputResourceId] +
                                   cityField08->CityStockByType(primaryInputResourceId));
  if (secondaryInputResourceId < 0) {
    limit = static_cast<short>(limit / 2);
  } else {
    short secondaryLimit =
        static_cast<short>(trackingSlots10[secondaryInputResourceId] +
                           cityField08->CityStockByType(secondaryInputResourceId));
    if (secondaryLimit < limit) {
      limit = secondaryLimit;
    }
  }
  return limit;
}

// FUNCTION: IMPERIALISM 0x004b9260
bool TExpansionOrder::SetQuantity(short param_1) {
  short delta = static_cast<short>(param_1 - quantityField04);
  if (param_1 > MaxOrder() || param_1 < 0) {
    return false;
  }
  quantityField04 = param_1;
  requestedQuantity4c = quantityField04;

  cityField08->CityStockByType(primaryInputResourceId) =
      static_cast<short>(cityField08->CityStockByType(primaryInputResourceId) - delta);
  cityField08->VerifyStocks();
  trackingSlots10[primaryInputResourceId] =
      static_cast<short>(trackingSlots10[primaryInputResourceId] + delta);
  cityField08->CityStockByType(secondaryInputResourceId) =
      static_cast<short>(cityField08->CityStockByType(secondaryInputResourceId) - delta);
  cityField08->VerifyStocks();
  trackingSlots10[secondaryInputResourceId] =
      static_cast<short>(trackingSlots10[secondaryInputResourceId] + delta);
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
