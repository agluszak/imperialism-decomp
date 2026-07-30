#include "game/city/TItemOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b51d0
// TItemOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b5200
// TItemOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TItemOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b5240
// TItemOrder::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004b5290
void TItemOrder::IItemOrder(TCity* city, short outputResourceType, short primaryInputResource,
                            short secondaryInputResource, short productionSlotIndex) {
  ownerCity = city;
  productionSummary = city->productionSummary1d8;
  resourceTypeIndex = outputResourceType;
  quantity = 0;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    trackingSlots[resource] = 0;
  }
  accumulatedValue = 0;
  limitingConstraint = kProductionOrderLimitResources;
  reservedWorkforce = 0;
  requestedQuantity4c = 0;
  primaryInputResourceId = primaryInputResource;
  secondaryInputResourceId = secondaryInputResource;
  productionSlot = productionSlotIndex;
}

// FUNCTION: IMPERIALISM 0x004b5310
short TItemOrder::MaxOrder() {
  short currentQuantity = quantity;
  short workforceLimit = static_cast<short>(productionSummary->strength / 2 + currentQuantity);
  short productionLimit =
      static_cast<short>(ownerCity->productionAccum1fc[productionSlot] + currentQuantity);
  short resourceLimit = static_cast<short>(trackingSlots[primaryInputResourceId] +
                                           ownerCity->CityStockByType(primaryInputResourceId));

  if (secondaryInputResourceId < 0) {
    resourceLimit = static_cast<short>(resourceLimit / 2);
  } else {
    short secondaryLimit = static_cast<short>(trackingSlots[secondaryInputResourceId] +
                                              ownerCity->CityStockByType(secondaryInputResourceId));
    if (secondaryLimit < resourceLimit) {
      resourceLimit = secondaryLimit;
    }
  }

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

// FUNCTION: IMPERIALISM 0x004b53d0
bool TItemOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - this->quantity);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  this->quantity = quantity;
  requestedQuantity4c = quantity;

  short primaryChange;
  if (secondaryInputResourceId < 0) {
    primaryChange = static_cast<short>(delta * 2);
    ownerCity->CityStockByType(primaryInputResourceId) =
        static_cast<short>(ownerCity->CityStockByType(primaryInputResourceId) - primaryChange);
    ownerCity->VerifyStocks();
    trackingSlots[primaryInputResourceId] =
        static_cast<short>(trackingSlots[primaryInputResourceId] + primaryChange);
  } else {
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
  }

  short workforceChange = static_cast<short>(delta * 2);
  productionSummary->strength = static_cast<short>(productionSummary->strength - workforceChange);
  reservedWorkforce = static_cast<short>(reservedWorkforce + workforceChange);
  ownerCity->productionAccum1fc[productionSlot] =
      static_cast<short>(ownerCity->productionAccum1fc[productionSlot] - delta);
  g_pViewMgr->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b5510
void TItemOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->ResetOrderSheet(orderSheet);
  if (this->secondaryInputResourceId >= 0) {
    orderSheet->ForResourceCode(this->primaryInputResourceId) = quantity;
    orderSheet->ForResourceCode(this->secondaryInputResourceId) = quantity;
    orderSheet->slotByResourceCode[0x3d] = static_cast<short>(quantity * 2);
  } else {
    orderSheet->ForResourceCode(this->primaryInputResourceId) = static_cast<short>(quantity * 2);
    orderSheet->slotByResourceCode[0x3d] = static_cast<short>(quantity * 2);
  }
}

// FUNCTION: IMPERIALISM 0x004b5580
void TItemOrder::Produce() {
  ownerCity->productionAccum1fc[productionSlot] =
      static_cast<short>(ownerCity->productionAccum1fc[productionSlot] + quantity);
  ownerCity->CityStockByType(resourceTypeIndex) =
      static_cast<short>(ownerCity->CityStockByType(resourceTypeIndex) + quantity);
  ownerCity->VerifyStocks();
  ownerCity->rollingItemProductionScore78 += quantity;
  trackingSlots[primaryInputResourceId] = 0;
  if (secondaryInputResourceId >= 0) {
    trackingSlots[secondaryInputResourceId] = 0;
  }
  reservedWorkforce = 0;
  accumulatedValue += quantity;
}

// FUNCTION: IMPERIALISM 0x004b5620
void TItemOrder::Restock() {
  // Clamp the pending quantity to MaxOrder(): recompute the ceiling, zero the
  // pending-quantity field, then re-drive SetQuantity with whichever of the current
  // requested quantity / the new ceiling is smaller. SetQuantity itself rewrites
  // requestedQuantity4c, so the smaller-ceiling branch restores the desired value.
  short maxOrder = MaxOrder();
  short savedRequestedQuantity = requestedQuantity4c;
  quantity = 0;
  if (maxOrder < savedRequestedQuantity && limitingConstraint == kProductionOrderLimitResources) {
    SetQuantity(maxOrder);
    requestedQuantity4c = savedRequestedQuantity;
  } else {
    SetQuantity(savedRequestedQuantity);
  }
}

// Duplicates TProductionOrder::WriteTo's field-write sequence inline (calling the
// grandparent TObject::WriteTo directly, not TProductionOrder::WriteTo) before
// appending its own four fields.
// FUNCTION: IMPERIALISM 0x004b5670
void TItemOrder::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(&quantity, 2);
  stream->WriteBytes(&limitingConstraint, 2);
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(trackingSlots, sizeof(trackingSlots));
  stream->WriteBytes(&accumulatedValue, 4);
  stream->WriteBytes(&requestedQuantity4c, 2);
  stream->WriteBytes(&primaryInputResourceId, 2);
  stream->WriteBytes(&secondaryInputResourceId, 2);
  stream->WriteBytes(&productionSlot, 2);
}

// FUNCTION: IMPERIALISM 0x004b5710
void TItemOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(&quantity, 2);
  stream->ReadBytes(&limitingConstraint, 2);
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(trackingSlots, sizeof(trackingSlots));
  stream->ReadBytes(&accumulatedValue, 4);
  stream->ReadBytes(&requestedQuantity4c, 2);
  stream->ReadBytes(&primaryInputResourceId, 2);
  stream->ReadBytes(&secondaryInputResourceId, 2);
  stream->ReadBytes(&productionSlot, 2);
}
