#include "game/TPowerPlantOrder.h"

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

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
undefined TPowerPlantOrder::ResetCityOrderItemDerivedStateNoop() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7c90
void TPowerPlantOrder::FillOrderSheet(void* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(reinterpret_cast<undefined4*>(orderSheet));
  WriteShort(orderSheet, 0x18, static_cast<short>(quantity * 6));
}

// FUNCTION: IMPERIALISM 0x004b7cc0
void TPowerPlantOrder::WriteTo(TStream* stream) {
}

// FUNCTION: IMPERIALISM 0x004b7d40
void TPowerPlantOrder::ReadFrom(TStream* stream) {
}
