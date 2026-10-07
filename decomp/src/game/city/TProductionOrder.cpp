#include "game/resource_domain_types.h"
#include "game/city/TProductionOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"

IMPLEMENT_DYNCREATE(TProductionOrder, TObject)

// FUNCTION: IMPERIALISM 0x004b4f70
void TProductionOrder::IProductionOrder(TCity* city, short resourceType) {
  ownerCity = city;
  productionSummary = city->productionSummary;
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
  // Retail writes the resource type twice. Both reads target this same field.
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

// FUNCTION: IMPERIALISM 0x004b5100
bool TProductionOrder::SetQuantity(short newQuantity) {
  if (newQuantity > MaxOrder() || newQuantity < 0) {
    return false;
  }
  quantity = newQuantity;
  return true;
}

// NOOP: verified empty in original 0x004b5140
// FUNCTION: IMPERIALISM 0x004b5140
void TProductionOrder::Restock() {}

// FUNCTION: IMPERIALISM 0x004b5160
void TProductionOrder::Produce() {}

// FUNCTION: IMPERIALISM 0x004b5180
void TProductionOrder::ResetOrderSheet(OrderSheet* orderSheet) {
  for (int resource = 0; resource < 61; ++resource) {
    orderSheet->slotByResourceCode[resource] = 0;
  }
  orderSheet->slotByResourceCode[61] = 0;
  orderSheet->slotByResourceCode[62] = 0;
}

// FUNCTION: IMPERIALISM 0x004b51b0
void TProductionOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  ResetOrderSheet(orderSheet);
}
