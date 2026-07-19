#include "game/TPowerPlantOrder.h"

// SYNTHETIC: IMPERIALISM 0x004b79f0
// TPowerPlantOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b7a20
// TPowerPlantOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPowerPlantOrder, TProductionOrder)

TPowerPlantOrder::TPowerPlantOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b7a60
// TPowerPlantOrder::`scalar deleting destructor'
TPowerPlantOrder::~TPowerPlantOrder() {}

// FUNCTION: IMPERIALISM 0x004b7ab0
undefined TPowerPlantOrder::InitializeCityProductionState_Impl() {
  return 0;
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
undefined TPowerPlantOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7c40
void TPowerPlantOrder::ResetCityOrderItemDerivedStateNoop() {
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
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
  orderSheet->slotByResourceCode[0x0c] = static_cast<short>(quantity * 6);
}

// FUNCTION: IMPERIALISM 0x004b7cc0
void TPowerPlantOrder::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004b7d40
void TPowerPlantOrder::ReadFrom(TStream* stream) {}
