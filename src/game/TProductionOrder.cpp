#include "game/TProductionOrder.h"

#include "game/TStream.h"

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
TProductionOrder::~TProductionOrder() {}

// FUNCTION: IMPERIALISM 0x004b4f70
undefined TProductionOrder::InitializeBasicCityOrderContext(int param_1, undefined2 param_2) {
  return 0;
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
void TProductionOrder::ResetCityOrderItemDerivedStateNoop() {}

// FUNCTION: IMPERIALISM 0x004b5160
undefined TProductionOrder::CommitIfPending() {
  return 0;
}

// Slot 0x3c (Mac: Produce) — clears the OrderSheet working buffers. The body lives
// in TProductionOrder's own vtable region; TCityOrderItem (TCapacityOrder's parallel
// chain) shares the same slot but cannot own the address.
// FUNCTION: IMPERIALISM 0x004b5180
undefined TProductionOrder::InitializeCityOrderItemWorkingBuffers(OrderSheet* orderSheet) {
  undefined4* cursor = reinterpret_cast<undefined4*>(orderSheet->slotByResourceCode);
  int remaining = 0x1e;
  while (remaining != 0) {
    *cursor = 0;
    cursor = cursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(cursor) = 0;
  orderSheet->slotByResourceCode[0x3d] = 0;
  orderSheet->slotByResourceCode[0x3e] = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b51b0
void TProductionOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  (void)quantity;
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
}
