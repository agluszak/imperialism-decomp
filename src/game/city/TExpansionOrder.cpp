#include "game/city/TExpansionOrder.h"

#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/core/TStream.h"

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
    signed char usesThreeRegionsPerLevel = owner->field8d1 >= '3';
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
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b9260
bool TExpansionOrder::SetQuantity(short param_1) {
  return 0;
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
