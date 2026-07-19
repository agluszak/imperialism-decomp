#include "game/TFoodProcessingOrder.h"

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
undefined TFoodProcessingOrder::FoodProcessingOrderSlot11(int param_1) {
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
undefined TFoodProcessingOrder::ResetCityOrderItemDerivedStateNoop(const char* name) {
  (void)name;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b80c0
void TFoodProcessingOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  if (quantity & 1) {
    quantity = static_cast<short>(quantity + 1);
  }
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
  orderSheet->slotByResourceCode[0x11] = quantity;
  orderSheet->slotByResourceCode[0x12] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[0x14] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[0x3d] = quantity;
}
