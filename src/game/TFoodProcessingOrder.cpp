#include "game/TFoodProcessingOrder.h"

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

// SYNTHETIC: IMPERIALISM 0x004b7dc0
// TFoodProcessingOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b7df0
// TFoodProcessingOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFoodProcessingOrder, TProductionOrder)

TFoodProcessingOrder::TFoodProcessingOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b7e30
// TFoodProcessingOrder::`scalar deleting destructor'
TFoodProcessingOrder::~TFoodProcessingOrder() {}

// FUNCTION: IMPERIALISM 0x004b7e80
undefined TFoodProcessingOrder::InitializeCityProductionState_Impl_At004b7e80(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7ed0
short TFoodProcessingOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7f50
bool TFoodProcessingOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8060
undefined TFoodProcessingOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b80a0
undefined TFoodProcessingOrder::ResetCityOrderItemDerivedStateNoop() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b80c0
void TFoodProcessingOrder::FillOrderSheet(void* orderSheet, short quantity) {
  if (quantity & 1) {
    quantity = static_cast<short>(quantity + 1);
  }
  this->InitializeCityOrderItemWorkingBuffers(reinterpret_cast<undefined4*>(orderSheet));
  WriteShort(orderSheet, 0x22, quantity);
  WriteShort(orderSheet, 0x24, static_cast<short>(quantity / 2));
  WriteShort(orderSheet, 0x28, static_cast<short>(quantity / 2));
  WriteShort(orderSheet, 0x7a, quantity);
}
