#include "game/TExpansionOrder.h"

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
undefined TExpansionOrder::InitializeCityProductionState_Impl_At004b9010(
    int param_1, undefined2 param_2, undefined2 param_3, undefined2 param_4, undefined2 param_5) {
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

// FUNCTION: IMPERIALISM 0x004b9340
void SwapFirstTwoBytesInBuffer(unsigned char* buffer) {
  unsigned char tmp = buffer[0];
  buffer[0] = buffer[1];
  buffer[1] = tmp;
}

// FUNCTION: IMPERIALISM 0x004b9360
void TExpansionOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
  orderSheet->ForResourceCode(this->field4e) = quantity;
  if (orderSheet->ForResourceCode(this->field4e) < 0) {
    orderSheet->ForResourceCode(this->field4e) = 0;
  }
  orderSheet->ForResourceCode(this->field50) = quantity;
  if (orderSheet->ForResourceCode(this->field50) < 0) {
    orderSheet->ForResourceCode(this->field50) = 0;
  }
}
