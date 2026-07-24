#include "game/city/TOrItemOrder.h"

#include "game/city/TCity.h"
// SYNTHETIC: IMPERIALISM 0x004b57b0
// TOrItemOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b57e0
// TOrItemOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOrItemOrder, TItemOrder)

// NOOP: verified empty in original 0x004b57b2 (no standalone TOrItemOrder::TOrItemOrder body exists: construction is fully inlined into CreateObject 0x004b57b0; that address is its operator-new call site)
TOrItemOrder::TOrItemOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b5820
// TOrItemOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b5850
TOrItemOrder::~TOrItemOrder() {}

// FUNCTION: IMPERIALISM 0x004b5870
void TOrItemOrder::IOrItemOrder(TCity* city, short resourceType, short primaryInputResource,
                                short secondaryInputResource, short productionSlotValue) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = resourceType;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  primaryInputResourceId = primaryInputResource;
  field40 = 0;
  field3e = 0;
  requestedQuantity4c = 0;
  secondaryInputResourceId = secondaryInputResource;
  productionSlot = productionSlotValue;
}

// FUNCTION: IMPERIALISM 0x004b58f0
short TOrItemOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5990
bool TOrItemOrder::SetQuantity(short param_1) {
  return 0;
}
