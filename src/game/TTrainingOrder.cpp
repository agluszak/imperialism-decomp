#include "game/TTrainingOrder.h"

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

// SYNTHETIC: IMPERIALISM 0x004b6a60
// TTrainingOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b6a90
// TTrainingOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTrainingOrder, TProductionOrder)

TTrainingOrder::TTrainingOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b6ad0
// TTrainingOrder::`scalar deleting destructor'
TTrainingOrder::~TTrainingOrder() {}

// FUNCTION: IMPERIALISM 0x004b6b20
undefined TTrainingOrder::InitializeCityProductionState_Impl_At004b6b20(int param_1, undefined2 param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b6b90
short TTrainingOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b6cd0
bool TTrainingOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b6de0
void TTrainingOrder::FillOrderSheet(void* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(reinterpret_cast<undefined4*>(orderSheet));
  if (this->resourceTypeIndex48 == 1) {
    WriteShort(orderSheet, 0x14, quantity);
    return;
  }
  WriteShort(orderSheet, 0x2e, quantity);
  WriteShort(orderSheet, 0x14, static_cast<short>(quantity * 2));
}

// FUNCTION: IMPERIALISM 0x004b6e30
undefined TTrainingOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b6f00
undefined TTrainingOrder::ResetCityOrderItemDerivedStateNoop() {
  return 0;
}
