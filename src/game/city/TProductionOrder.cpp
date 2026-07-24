#include "game/city/TProductionOrder.h"

#include "game/city/TCity.h"
#include "game/core/TStream.h"

TProductionOrder::TProductionOrder()
    : quantityField04(0), cityField08(0), summaryField0c(0), field3e(0), field40(0),
      accumulatedValue(0), resourceTypeIndex48(0), field4a(0) {
  for (int i = 0; i < 0x17; ++i) {
    trackingSlots10[i] = 0;
  }
}
// SYNTHETIC: IMPERIALISM 0x004b4eb0
// TProductionOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b4ee0
// TProductionOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TProductionOrder, TObject)

// SYNTHETIC: IMPERIALISM 0x004b4f20
// TProductionOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b4f50
TProductionOrder::~TProductionOrder() {}

// FUNCTION: IMPERIALISM 0x004b4f70
void TProductionOrder::IProductionOrder(TCity* city, short resourceType) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = resourceType;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
}

// FUNCTION: IMPERIALISM 0x004b4fe0
void TProductionOrder::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&resourceTypeIndex48, 2);
  stream->WriteBytesSlot78(&quantityField04, 2);
  stream->WriteBytesSlot78(&field40, 2);
  stream->WriteBytesSlot78(&resourceTypeIndex48, 2);
  stream->WriteBytesSlot78(trackingSlots10, 0x2e);
  stream->WriteBytesSlot78(&accumulatedValue, 4);
}

// FUNCTION: IMPERIALISM 0x004b5060
void TProductionOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(&quantityField04, 2);
  stream->ReadBytes(&field40, 2);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(trackingSlots10, 0x2e);
  stream->ReadBytes(&accumulatedValue, 4);
}

// FUNCTION: IMPERIALISM 0x004b50e0
short TProductionOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5100
bool TProductionOrder::SetQuantity(short param_1) {
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
