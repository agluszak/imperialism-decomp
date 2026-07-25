#include "game/city/TPowerPlantOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"

// SYNTHETIC: IMPERIALISM 0x004b79f0
// TPowerPlantOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b7a20
// TPowerPlantOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPowerPlantOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b7a60
// TPowerPlantOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b7a90
TPowerPlantOrder::~TPowerPlantOrder() {}

// FUNCTION: IMPERIALISM 0x004b7ab0
void TPowerPlantOrder::IPowerPlantOrder(TCity* city) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = 0;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
  field4c = 0;
}

// FUNCTION: IMPERIALISM 0x004b7b00
short TPowerPlantOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7b30
bool TPowerPlantOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7c20
void TPowerPlantOrder::Produce() {}

// FUNCTION: IMPERIALISM 0x004b7c40
void TPowerPlantOrder::Restock() {
  // Same quantity re-clamp as TItemOrder's slot 0x0e, minus the field40 guard: zero
  // the pending quantity and re-drive SetQuantity with the smaller of the current
  // derived value (field4c) and the recomputed MaxOrder() ceiling.
  short maxOrder = MaxOrder();
  short savedDerived = field4c;
  quantityField04 = 0;
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
  stream->WriteBytes(&resourceTypeIndex48, 2);
  stream->WriteBytes(&quantityField04, 2);
  stream->WriteBytes(&field40, 2);
  stream->WriteBytes(&resourceTypeIndex48, 2);
  stream->WriteBytes(trackingSlots10, 0x2e);
  stream->WriteBytes(&accumulatedValue, 4);
  stream->WriteBytes(&field4c, 2);
}

// FUNCTION: IMPERIALISM 0x004b7d40
void TPowerPlantOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(&quantityField04, 2);
  stream->ReadBytes(&field40, 2);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(trackingSlots10, 0x2e);
  stream->ReadBytes(&accumulatedValue, 4);
  stream->ReadBytes(&field4c, 2);
}
