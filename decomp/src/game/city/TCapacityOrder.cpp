#include "game/city/TCapacityOrder.h"
#include "game/globals/global_types.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"

#include "game/mfc.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TCity.h"
#include "game/ui_core/TViewMgr.h"

#include <new>

IMPLEMENT_DYNCREATE(TCapacityOrder, TItemOrder)

// FUNCTION: IMPERIALISM 0x004b8d50
void TCapacityOrder::ICapacityOrder(TCity* city, short resourceType, short primaryInputResource,
                                    short secondaryInputResource, short productionSlotValue) {
  TItemOrder::IItemOrder(city, resourceType, primaryInputResource, secondaryInputResource,
                         productionSlotValue);
}

// FUNCTION: IMPERIALISM 0x004b8dd0
void TCapacityOrder::Produce() {
  TCity* city = ownerCity;
  short slotIndex = resourceTypeIndex;
  short newValue;
  short deltaToAccum;

  if (quantity == 0) {
    return;
  }

  if (slotIndex == 0xe) {
    const short currentCap = city->GetRollingStock();
    city->SetRollingStock(static_cast<short>(currentCap + quantity));
  } else {
    if (slotIndex == 0xf) {
      TGreatPower* owner = city->ownerNation;
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
      newValue = city->productionOrderTable[slotIndex];
    }

    newValue += quantity;
    deltaToAccum = static_cast<short>(newValue - city->productionOrderTable[slotIndex]);
    city->productionAccum[slotIndex] =
        static_cast<short>(city->productionAccum[slotIndex] + deltaToAccum);
    city->productionOrderTable[slotIndex] = newValue;
  }

  requestedQuantity = 0;
  quantity = 0;
  trackingSlots[primaryInputResourceId] = 0;
  trackingSlots[secondaryInputResourceId] = 0;
  reservedWorkforce = 0;
}
