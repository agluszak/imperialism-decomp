#include "game/city/TCapacityOrder.h"
#include "game/globals/global_types.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"

#include "game/mfc.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TCity.h"
#include "game/ui_core/TViewMgr.h"

#include <new>

// SYNTHETIC: IMPERIALISM 0x004b8c90
// TCapacityOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8cc0
// TCapacityOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCapacityOrder, TItemOrder)

// SYNTHETIC: IMPERIALISM 0x004b8d00
// TCapacityOrder::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004b8d50
void TCapacityOrder::ICapacityOrder(TCity* city, short resourceType, short primaryInputResource,
                                    short secondaryInputResource, short productionSlotValue) {
  this->ownerCity = city;
  this->productionSummary = city->productionSummary1d8;
  this->resourceTypeIndex = resourceType;
  this->quantity = 0;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    this->trackingSlots[resource] = 0;
  }
  this->accumulatedValue = 0;
  this->primaryInputResourceId = primaryInputResource;
  this->limitingConstraint = kProductionOrderLimitResources;
  this->reservedWorkforce = 0;
  this->requestedQuantity4c = 0;
  this->secondaryInputResourceId = secondaryInputResource;
  this->productionSlot = productionSlotValue;
}

// FUNCTION: IMPERIALISM 0x004b8dd0
void TCapacityOrder::Produce() {
  TCity* city = this->ownerCity;
  short slotIndex = this->resourceTypeIndex;
  short newValue;
  short deltaToAccum;

  if (this->quantity == 0) {
    return;
  }
  if (slotIndex == 0xe) {
    const short currentCap = static_cast<short>(city->GetOwnerNeedCapA6());
    city->SetOwnerNeedCapA6(static_cast<short>(currentCap + this->quantity));
    goto apply_done;
  }
  if (slotIndex == 0xf) {
    TGreatPower* owner = city->ownerNationAc;
    if (owner->pendingActionStatus.byAction[9] < '3') {
      int laborPool = owner->ownedRegionList->GetSize();
      if ((laborPool + ((laborPool < 0) ? 3 : 0)) >> 2 < 2) {
        newValue = 1;
      } else {
        laborPool = owner->ownedRegionList->GetSize();
        newValue = static_cast<short>((laborPool + ((laborPool < 0) ? 3 : 0)) >> 2);
      }
    } else {
      int laborPool = owner->ownedRegionList->GetSize();
      if (laborPool / 3 < 2) {
        newValue = 1;
      } else {
        laborPool = owner->ownedRegionList->GetSize();
        newValue = static_cast<short>(laborPool / 3);
      }
    }
  } else {
    newValue = city->productionOrderTable1dc[slotIndex];
  }
  newValue = static_cast<short>(newValue + this->quantity);
  deltaToAccum = static_cast<short>(newValue - city->productionOrderTable1dc[slotIndex]);
  city->productionAccum1fc[slotIndex] =
      static_cast<short>(city->productionAccum1fc[slotIndex] + deltaToAccum);
  city->productionOrderTable1dc[slotIndex] = newValue;
apply_done:
  this->requestedQuantity4c = 0;
  this->quantity = 0;
  this->trackingSlots[this->primaryInputResourceId] = 0;
  this->trackingSlots[this->secondaryInputResourceId] = 0;
  this->reservedWorkforce = 0;
}
