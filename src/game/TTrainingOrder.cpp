#include "game/TTrainingOrder.h"

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
undefined TTrainingOrder::TrainingOrderSlot11(int param_1, undefined2 param_2) {
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
void TTrainingOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
  if (this->resourceTypeIndex48 == 1) {
    orderSheet->slotByResourceCode[0x0a] = quantity;
    return;
  }
  orderSheet->slotByResourceCode[0x17] = quantity;
  orderSheet->slotByResourceCode[0x0a] = static_cast<short>(quantity * 2);
}

// FUNCTION: IMPERIALISM 0x004b6e30
undefined TTrainingOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b6f00
void TTrainingOrder::ResetCityOrderItemDerivedStateNoop() {}
