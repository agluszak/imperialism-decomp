#include "game/TPopGrowthOrder.h"
#include "game/TCity.h"

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

// Matches TCapacityOrder's own ZeroTrackingSlots helper: zeroes the 0x2e-byte
// trackingSlots10 array (0x17 shorts) via the same 11x-4-byte-then-1x-2-byte write
// pattern the original compiles this loop into.
static void ZeroPopGrowthTrackingSlots(TPopGrowthOrder* order) {
  int remaining = 0xb;
  int* blockCursor = reinterpret_cast<int*>(order->trackingSlots10);
  while (remaining != 0) {
    *blockCursor = 0;
    blockCursor = blockCursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(blockCursor) = 0;
}

// SYNTHETIC: IMPERIALISM 0x004b3050
// TPopGrowthOrder::`scalar deleting destructor'
TPopGrowthOrder::~TPopGrowthOrder() {}
// SYNTHETIC: IMPERIALISM 0x004b8110
// TPopGrowthOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8140
// TPopGrowthOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPopGrowthOrder, TProductionOrder)

TPopGrowthOrder::TPopGrowthOrder() {}

// FUNCTION: IMPERIALISM 0x004b8160
void TPopGrowthOrder::ConstructTPopGrowthOrderBaseState(TCity* city) {
  cityField08 = city;
  summaryField0c = city != nullptr ? city->productionSummary1d8 : nullptr;
  resourceTypeIndex48 = 1;
  quantityField04 = 0;
  ZeroPopGrowthTrackingSlots(this);
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
}

// FUNCTION: IMPERIALISM 0x004b81b0
short TPopGrowthOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8230
bool TPopGrowthOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b82f0
undefined TPopGrowthOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8420
undefined TPopGrowthOrder::ResetCityOrderItemDerivedStateNoop() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8440
void TPopGrowthOrder::FillOrderSheet(void* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(reinterpret_cast<undefined4*>(orderSheet));
  WriteShort(orderSheet, 0x1a, quantity);
  WriteShort(orderSheet, 0x1c, quantity);
  WriteShort(orderSheet, 0x0e, quantity);
}
