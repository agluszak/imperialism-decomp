#include "game/city/TFoodProcessingOrder.h"

#include "game/city/TCity.h"

// SYNTHETIC: IMPERIALISM 0x004b7dc0
// TFoodProcessingOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b7df0
// TFoodProcessingOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFoodProcessingOrder, TProductionOrder)

// NOOP: verified empty in original 0x004b7dc2 (no standalone TFoodProcessingOrder::TFoodProcessingOrder body exists: construction is fully inlined into CreateObject 0x004b7dc0; that address is its operator-new call site)
TFoodProcessingOrder::TFoodProcessingOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b7e30
// TFoodProcessingOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b7e60
TFoodProcessingOrder::~TFoodProcessingOrder() {}

// FUNCTION: IMPERIALISM 0x004b7e80
void TFoodProcessingOrder::IFoodProcessingOrder(TCity* city) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = 7;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
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
void TFoodProcessingOrder::Produce() {
  TCity* city = cityField08;
  city->cityStockCannedFoodC4 += quantityField04;
  city->VerifyStocks();
  quantityField04 = 0;
  field3e = 0;
}

// FUNCTION: IMPERIALISM 0x004b80a0
void TFoodProcessingOrder::Restock() {}

// FUNCTION: IMPERIALISM 0x004b80c0
void TFoodProcessingOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  if (quantity & 1) {
    quantity = static_cast<short>(quantity + 1);
  }
  this->ResetOrderSheet(orderSheet);
  orderSheet->slotByResourceCode[0x11] = quantity;
  orderSheet->slotByResourceCode[0x12] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[0x14] = static_cast<short>(quantity / 2);
  orderSheet->slotByResourceCode[0x3d] = quantity;
}
