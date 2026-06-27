#include "game/TItemOrder.h"

TItemOrder::TItemOrder() {}
IMPLEMENT_DYNCREATE(TItemOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b5240
// TItemOrder::`scalar deleting destructor'
TItemOrder::~TItemOrder() {}

// FUNCTION: IMPERIALISM 0x004b5290
undefined TItemOrder::InitializeCityProductionState_Impl_At004b5290(int param_1, undefined2 param_2, undefined2 param_3, undefined2 param_4, undefined2 param_5) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5310
short TItemOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b53d0
bool TItemOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5510
undefined TItemOrder::FillOrderSheet() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5580
undefined TItemOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5620
undefined TItemOrder::ResetCityOrderItemDerivedStateNoop() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5670
void TItemOrder::WriteTo(TStream* stream) {
}

// FUNCTION: IMPERIALISM 0x004b5710
void TItemOrder::ReadFrom(TStream* stream) {
}
