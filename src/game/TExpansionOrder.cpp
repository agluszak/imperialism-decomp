#include "game/TExpansionOrder.h"

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

static __inline short ReadShort(void* base, int offset) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset);
}

// SYNTHETIC: IMPERIALISM 0x004b8f50
// TExpansionOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8f80
// TExpansionOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TExpansionOrder, TItemOrder)

TExpansionOrder::TExpansionOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b8fc0
// TExpansionOrder::`scalar deleting destructor'
TExpansionOrder::~TExpansionOrder() {}

// FUNCTION: IMPERIALISM 0x004b9010
undefined TExpansionOrder::InitializeCityProductionState_Impl_At004b9010(int param_1, undefined2 param_2, undefined2 param_3, undefined2 param_4, undefined2 param_5) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b9090
undefined TExpansionOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b91f0
short TExpansionOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b9260
bool TExpansionOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b9360
void TExpansionOrder::FillOrderSheet(void* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(reinterpret_cast<undefined4*>(orderSheet));
  WriteShort(orderSheet, this->field4e * 2, quantity);
  if (ReadShort(orderSheet, this->field4e * 2) < 0) {
    WriteShort(orderSheet, this->field4e * 2, 0);
  }
  WriteShort(orderSheet, this->field50 * 2, quantity);
  if (ReadShort(orderSheet, this->field50 * 2) < 0) {
    WriteShort(orderSheet, this->field50 * 2, 0);
  }
}
