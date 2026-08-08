#include "game/city/TPowerPlantOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b79f0
// TPowerPlantOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b7a20
// TPowerPlantOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPowerPlantOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b7a60
// TPowerPlantOrder::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004b7ab0
void TPowerPlantOrder::IPowerPlantOrder(TCity* city) {
  ownerCity = city;
  productionSummary = city->productionSummary1d8;
  resourceTypeIndex = 0;
  quantity = 0;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    trackingSlots[resource] = 0;
  }
  accumulatedValue = 0;
  limitingConstraint = kProductionOrderLimitResources;
  reservedWorkforce = 0;
  field4c = 0;
}

// FUNCTION: IMPERIALISM 0x004b7b00
short TPowerPlantOrder::MaxOrder() {
  return static_cast<short>(quantity + ownerCity->cityStockFuelCE * 6);
}

// FUNCTION: IMPERIALISM 0x004b7b30
bool TPowerPlantOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - this->quantity);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  this->quantity = quantity;

  if (ownerCity->productionSummary1d8->strength < -static_cast<int>(delta)) {
    this->quantity = static_cast<short>(this->quantity - delta);
    return false;
  }

  field4c = quantity;
  ownerCity->cityStockFuelCE = static_cast<short>(ownerCity->cityStockFuelCE - delta / 6);
  ownerCity->VerifyStocks();

  short previousPower = ownerCity->productionSummary1d8->extraAt1e;
  ownerCity->powerAvailableB4 = quantity;
  ownerCity->productionSummary1d8->extraAt1e = quantity;
  ownerCity->productionSummary1d8->strength =
      static_cast<short>(ownerCity->productionSummary1d8->strength + quantity - previousPower);
  g_pViewMgr->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b7c20
void TPowerPlantOrder::Produce() {}

// FUNCTION: IMPERIALISM 0x004b7c40
void TPowerPlantOrder::Restock() {
  // Same quantity re-clamp as TItemOrder's slot 0x0e, minus the limitingConstraint guard: zero
  // the pending quantity and re-drive SetQuantity with the smaller of the current
  // derived value (field4c) and the recomputed MaxOrder() ceiling.
  short maxOrder = MaxOrder();
  short savedDerived = field4c;
  quantity = 0;
  if (maxOrder < savedDerived) {
    SetQuantity(maxOrder);
    field4c = savedDerived;
  } else {
    SetQuantity(savedDerived);
  }
}

// FUNCTION: IMPERIALISM 0x004b7c90
void TPowerPlantOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->ResetOrderSheet(orderSheet);
  orderSheet->slotByResourceCode[0x0c] = static_cast<short>(quantity * 6);
}

// FUNCTION: IMPERIALISM 0x004b7cc0
void TPowerPlantOrder::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(&quantity, 2);
  stream->WriteBytes(&limitingConstraint, 2);
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(trackingSlots, sizeof(trackingSlots));
  stream->WriteBytes(&accumulatedValue, 4);
  stream->WriteBytes(&field4c, 2);
}

// FUNCTION: IMPERIALISM 0x004b7d40
void TPowerPlantOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(&quantity, 2);
  stream->ReadBytes(&limitingConstraint, 2);
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(trackingSlots, sizeof(trackingSlots));
  stream->ReadBytes(&accumulatedValue, 4);
  stream->ReadBytes(&field4c, 2);
}
