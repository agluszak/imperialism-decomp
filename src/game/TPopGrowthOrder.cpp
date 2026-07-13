#include "game/TPopGrowthOrder.h"

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
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
undefined TPopGrowthOrder::ConstructTPopGrowthOrderBaseState() {
  return 0;
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
undefined TPopGrowthOrder::ResetCityOrderItemDerivedStateNoop(const char* name) {
  (void)name;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8440
void TPopGrowthOrder::FillOrderSheet(void* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(reinterpret_cast<undefined4*>(orderSheet));
  WriteShort(orderSheet, 0x1a, quantity);
  WriteShort(orderSheet, 0x1c, quantity);
  WriteShort(orderSheet, 0x0e, quantity);
}
