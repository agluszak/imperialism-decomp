#include "game/city/TProductionOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"

// SYNTHETIC: IMPERIALISM 0x004b4eb0
// TProductionOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b4ee0
// TProductionOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TProductionOrder, TObject)

// SYNTHETIC: IMPERIALISM 0x004b4f20
// TProductionOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b4f70
void TProductionOrder::IProductionOrder(TCity* city, short resourceType) {
  ownerCity = city;
  productionSummary = city->productionSummary1d8;
  resourceTypeIndex = resourceType;
  quantity = 0;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    trackingSlots[resource] = 0;
  }
  accumulatedValue = 0;
  limitingConstraint = kProductionOrderLimitResources;
  reservedWorkforce = 0;
}

// FUNCTION: IMPERIALISM 0x004b4fe0
void TProductionOrder::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(&quantity, 2);
  stream->WriteBytes(&limitingConstraint, 2);
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(trackingSlots, sizeof(trackingSlots));
  stream->WriteBytes(&accumulatedValue, 4);
}

// FUNCTION: IMPERIALISM 0x004b5060
void TProductionOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(&quantity, 2);
  stream->ReadBytes(&limitingConstraint, 2);
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(trackingSlots, sizeof(trackingSlots));
  stream->ReadBytes(&accumulatedValue, 4);
}

// FUNCTION: IMPERIALISM 0x004b50e0
short TProductionOrder::MaxOrder() {
  return 0;
}

// NOOP: verified empty in original 0x004b5140
// FUNCTION: IMPERIALISM 0x004b5140
void TProductionOrder::Restock() {}

// FUNCTION: IMPERIALISM 0x004b5160
void TProductionOrder::Produce() {}

// Slot 0x3c (Mac: ResetOrderSheet) — clears the OrderSheet working buffers. This is the
// single owner of 0x004b5180; every order class reaches it through this vtable slot.
// FUNCTION: IMPERIALISM 0x004b5180
void TProductionOrder::ResetOrderSheet(OrderSheet* orderSheet) {
  for (int resource = 0; resource < 0x3d; ++resource) {
    orderSheet->slotByResourceCode[resource] = 0;
  }
  orderSheet->slotByResourceCode[0x3d] = 0;
  orderSheet->slotByResourceCode[0x3e] = 0;
}

// FUNCTION: IMPERIALISM 0x004b51b0
void TProductionOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  (void)quantity;
  this->ResetOrderSheet(orderSheet);
}
