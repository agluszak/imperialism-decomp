#include "game/city/TExpansionOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"

IMPLEMENT_DYNCREATE(TExpansionOrder, TItemOrder)

// FUNCTION: IMPERIALISM 0x004b9010
void TExpansionOrder::IExpansionOrder(TCity* city, short resourceType, short primaryInputResource,
                                      short secondaryInputResource, short productionSlotValue) {
  TItemOrder::IItemOrder(city, resourceType, primaryInputResource, secondaryInputResource,
                         productionSlotValue);
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
    TGreatPower* owner = city->ownerNation;
    signed char usesThreeRegionsPerLevel = owner->pendingActionStatus.byAction[9] >= '3';
    if (usesThreeRegionsPerLevel != zero) {
      int regionCount = owner->ownedRegionList->GetSize();
      if (regionCount / 3 > 1) {
        newValue = static_cast<short>(city->ownerNation->ownedRegionList->GetSize() / 3);
      } else {
        newValue = 1;
      }
    } else {
      int regionCount = owner->ownedRegionList->GetSize();
      if (regionCount / 4 > 1) {
        newValue = static_cast<short>(city->ownerNation->ownedRegionList->GetSize() / 4);
      } else {
        newValue = 1;
      }
    }
  } else {
    newValue = city->productionOrderTable[resourceTypeIndex];
  }

  newValue = static_cast<short>(newValue + quantity);
  short delta = static_cast<short>(newValue - city->productionOrderTable[resourceTypeIndex]);
  city->productionAccum[resourceTypeIndex] =
      static_cast<short>(city->productionAccum[resourceTypeIndex] + delta);
  city->productionOrderTable[resourceTypeIndex] = newValue;
  requestedQuantity = zero;
  quantity = zero;
  trackingSlots[primaryInputResourceId] = zero;
  trackingSlots[secondaryInputResourceId] = zero;
}

// FUNCTION: IMPERIALISM 0x004b91f0
short TExpansionOrder::MaxOrder() {
  short limit = static_cast<short>(trackingSlots[primaryInputResourceId] +
                                   ownerCity->stockByType[primaryInputResourceId]);
  if (secondaryInputResourceId < 0) {
    limit = static_cast<short>(limit / 2);
  } else {
    short secondaryLimit = static_cast<short>(trackingSlots[secondaryInputResourceId] +
                                              ownerCity->stockByType[secondaryInputResourceId]);
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
  requestedQuantity = quantity;

  ownerCity->stockByType[primaryInputResourceId] =
      static_cast<short>(ownerCity->stockByType[primaryInputResourceId] - delta);
  ownerCity->VerifyStocks();
  trackingSlots[primaryInputResourceId] =
      static_cast<short>(trackingSlots[primaryInputResourceId] + delta);
  ownerCity->stockByType[secondaryInputResourceId] =
      static_cast<short>(ownerCity->stockByType[secondaryInputResourceId] - delta);
  ownerCity->VerifyStocks();
  trackingSlots[secondaryInputResourceId] =
      static_cast<short>(trackingSlots[secondaryInputResourceId] + delta);
  g_pViewMgr->UpdateCityScreen();
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
