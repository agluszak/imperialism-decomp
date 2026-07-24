#include "game/city/TPopGrowthOrder.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"

// Matches TCapacityOrder's own ZeroTrackingSlots helper: zeroes the 0x2e-byte
// trackingSlots10 array (0x17 shorts) via the same 11x-4-byte-then-1x-2-byte write
// pattern the original compiles this loop into.
static void ZeroPopGrowthTrackingSlots(TPopGrowthOrder* order) {
  int remaining = 0xb;
  int* blockCursor = reinterpret_cast<int*>(order->trackingSlots10);
  while (remaining != 0) {
    *blockCursor = 0;
    blockCursor = blockCursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(blockCursor) = 0;
}

// SYNTHETIC: IMPERIALISM 0x004b3050
// TPopGrowthOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b3080
TPopGrowthOrder::~TPopGrowthOrder() {}
// SYNTHETIC: IMPERIALISM 0x004b8110
// TPopGrowthOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8140
// TPopGrowthOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPopGrowthOrder, TProductionOrder)

// FUNCTION: IMPERIALISM 0x004b8160
void TPopGrowthOrder::IPopGrowthOrder(TCity* city) {
  cityField08 = city;
  summaryField0c = city != nullptr ? city->productionSummary1d8 : nullptr;
  resourceTypeIndex48 = 1;
  quantityField04 = 0;
  ZeroPopGrowthTrackingSlots(this);
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
}

// FUNCTION: IMPERIALISM 0x004b81b0
short TPopGrowthOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8230
bool TPopGrowthOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b82f0
void TPopGrowthOrder::Produce() {
  short quantity = quantityField04;
  TPopulationMgr* population = cityField08->productionSummary1d8;
  population->baselineSlots10->lowSkillCount04 += quantity;
  population->productionSlots14->lowSkillCount04 += quantity;
  population->populationCount08 += quantity;

  TCity* city = cityField08;
  TGreatPower* owner = city->ownerNationAc;
  if (owner->field8d1 >= '3') {
    int regionCount = owner->ownedRegionList->GetSize();
    if (regionCount / 3 > 1) {
      city->productionAccum1fc[0x0f] = static_cast<short>(owner->ownedRegionList->GetSize() / 3);
    } else {
      city->productionAccum1fc[0x0f] = 1;
    }
  } else {
    int regionCount = owner->ownedRegionList->GetSize();
    if (regionCount / 4 > 1) {
      city->productionAccum1fc[0x0f] = static_cast<short>(owner->ownedRegionList->GetSize() / 4);
    } else {
      city->productionAccum1fc[0x0f] = 1;
    }
  }
  quantityField04 = 0;
}

// FUNCTION: IMPERIALISM 0x004b8420
void TPopGrowthOrder::Restock() {}

// FUNCTION: IMPERIALISM 0x004b8440
void TPopGrowthOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->ResetOrderSheet(orderSheet);
  orderSheet->slotByResourceCode[0x0d] = quantity;
  orderSheet->slotByResourceCode[0x0e] = quantity;
  orderSheet->slotByResourceCode[0x07] = quantity;
}
