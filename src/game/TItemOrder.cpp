#include "game/TItemOrder.h"

TItemOrder::TItemOrder() {}
// SYNTHETIC: IMPERIALISM 0x004b51d0
// TItemOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b5200
// TItemOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TItemOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b5240
// TItemOrder::`scalar deleting destructor'
TItemOrder::~TItemOrder() {}

// FUNCTION: IMPERIALISM 0x004b5290
undefined TItemOrder::ItemOrderSlot11(int param_1, undefined2 param_2, undefined2 param_3,
                                      undefined2 param_4, undefined2 param_5) {
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
void TItemOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
  if (this->field50 >= 0) {
    orderSheet->ForResourceCode(this->field4e) = quantity;
    orderSheet->ForResourceCode(this->field50) = quantity;
    orderSheet->slotByResourceCode[0x3d] = static_cast<short>(quantity * 2);
  } else {
    orderSheet->ForResourceCode(this->field4e) = static_cast<short>(quantity * 2);
    orderSheet->slotByResourceCode[0x3d] = static_cast<short>(quantity * 2);
  }
}

// FUNCTION: IMPERIALISM 0x004b5580
undefined TItemOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5620
undefined TItemOrder::ResetCityOrderItemDerivedStateNoop(const char* name) {
  (void)name;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5670
void TItemOrder::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004b5710
void TItemOrder::ReadFrom(TStream* stream) {}
