#include "game/city/TItemOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b51d0
// TItemOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b5200
// TItemOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TItemOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b5240
// TItemOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b5270
TItemOrder::~TItemOrder() {}

// FUNCTION: IMPERIALISM 0x004b5290
void TItemOrder::IItemOrder(TCity* city, short outputResourceType, short primaryInputResource,
                            short secondaryInputResource, short productionSlotIndex) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = outputResourceType;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
  requestedQuantity4c = 0;
  primaryInputResourceId = primaryInputResource;
  secondaryInputResourceId = secondaryInputResource;
  productionSlot = productionSlotIndex;
}

// FUNCTION: IMPERIALISM 0x004b5310
short TItemOrder::MaxOrder() {
  short currentQuantity = quantityField04;
  short workforceLimit = static_cast<short>(summaryField0c->strength / 2 + currentQuantity);
  short productionLimit =
      static_cast<short>(cityField08->productionAccum1fc[productionSlot] + currentQuantity);
  short resourceLimit = static_cast<short>(trackingSlots10[primaryInputResourceId] +
                                           cityField08->CityStockByType(primaryInputResourceId));

  if (secondaryInputResourceId < 0) {
    resourceLimit = static_cast<short>(resourceLimit / 2);
  } else {
    short secondaryLimit =
        static_cast<short>(trackingSlots10[secondaryInputResourceId] +
                           cityField08->CityStockByType(secondaryInputResourceId));
    if (secondaryLimit < resourceLimit) {
      resourceLimit = secondaryLimit;
    }
  }

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

// FUNCTION: IMPERIALISM 0x004b53d0
bool TItemOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - quantityField04);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  quantityField04 = quantity;
  requestedQuantity4c = quantityField04;

  short primaryChange;
  if (secondaryInputResourceId < 0) {
    primaryChange = static_cast<short>(delta * 2);
    cityField08->CityStockByType(primaryInputResourceId) =
        static_cast<short>(cityField08->CityStockByType(primaryInputResourceId) - primaryChange);
    cityField08->VerifyStocks();
    trackingSlots10[primaryInputResourceId] =
        static_cast<short>(trackingSlots10[primaryInputResourceId] + primaryChange);
  } else {
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
  }

  short workforceChange = static_cast<short>(delta * 2);
  summaryField0c->strength = static_cast<short>(summaryField0c->strength - workforceChange);
  field3e = static_cast<short>(field3e + workforceChange);
  cityField08->productionAccum1fc[productionSlot] =
      static_cast<short>(cityField08->productionAccum1fc[productionSlot] - delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
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
  cityField08->productionAccum1fc[productionSlot] =
      static_cast<short>(cityField08->productionAccum1fc[productionSlot] + quantityField04);
  cityField08->CityStockByType(resourceTypeIndex48) =
      static_cast<short>(cityField08->CityStockByType(resourceTypeIndex48) + quantityField04);
  cityField08->VerifyStocks();
  cityField08->rollingItemProductionScore78 += quantityField04;
  trackingSlots10[primaryInputResourceId] = 0;
  if (secondaryInputResourceId >= 0) {
    trackingSlots10[secondaryInputResourceId] = 0;
  }
  field3e = 0;
  accumulatedValue += quantityField04;
}

// FUNCTION: IMPERIALISM 0x004b5620
void TItemOrder::Restock() {
  // Clamp the pending quantity to MaxOrder(): recompute the ceiling, zero the
  // pending-quantity field, then re-drive SetQuantity with whichever of the current
  // requested quantity / the new ceiling is smaller. SetQuantity itself rewrites
  // requestedQuantity4c, so the smaller-ceiling branch restores the desired value.
  short maxOrder = MaxOrder();
  short savedRequestedQuantity = requestedQuantity4c;
  quantityField04 = 0;
  if (maxOrder < savedRequestedQuantity && field40 == 0) {
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
  stream->WriteBytes(&resourceTypeIndex48, 2);
  stream->WriteBytes(&quantityField04, 2);
  stream->WriteBytes(&field40, 2);
  stream->WriteBytes(&resourceTypeIndex48, 2);
  stream->WriteBytes(trackingSlots10, 0x2e);
  stream->WriteBytes(&accumulatedValue, 4);
  stream->WriteBytes(&requestedQuantity4c, 2);
  stream->WriteBytes(&primaryInputResourceId, 2);
  stream->WriteBytes(&secondaryInputResourceId, 2);
  stream->WriteBytes(&productionSlot, 2);
}

// FUNCTION: IMPERIALISM 0x004b5710
void TItemOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(&quantityField04, 2);
  stream->ReadBytes(&field40, 2);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(trackingSlots10, 0x2e);
  stream->ReadBytes(&accumulatedValue, 4);
  stream->ReadBytes(&requestedQuantity4c, 2);
  stream->ReadBytes(&primaryInputResourceId, 2);
  stream->ReadBytes(&secondaryInputResourceId, 2);
  stream->ReadBytes(&productionSlot, 2);
}
