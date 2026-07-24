#include "game/city/TTrainingOrder.h"

#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"

// SYNTHETIC: IMPERIALISM 0x004b6a60
// TTrainingOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b6a90
// TTrainingOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTrainingOrder, TProductionOrder)

// NOOP: verified empty in original 0x004b6a62 (no standalone TTrainingOrder::TTrainingOrder body exists: construction is fully inlined into CreateObject 0x004b6a60; that address is its operator-new call site)
TTrainingOrder::TTrainingOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b6ad0
// TTrainingOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b6b00
TTrainingOrder::~TTrainingOrder() {}

// FUNCTION: IMPERIALISM 0x004b6b20
void TTrainingOrder::ITrainingOrder(TCity* city, short resourceType) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = resourceType;
  quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    trackingSlots10[resource] = 0;
  }
  accumulatedValue = 0;
  field40 = 0;
  field3e = 0;
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
  this->ResetOrderSheet(orderSheet);
  if (this->resourceTypeIndex48 == 1) {
    orderSheet->slotByResourceCode[0x0a] = quantity;
    return;
  }
  orderSheet->slotByResourceCode[0x17] = quantity;
  orderSheet->slotByResourceCode[0x0a] = static_cast<short>(quantity * 2);
}

// FUNCTION: IMPERIALISM 0x004b6e30
void TTrainingOrder::Produce() {
  short quantity = quantityField04;
  if (quantity == 0) {
    return;
  }

  TLaborPool* population = summaryField0c->baselineSlots10;
  if (resourceTypeIndex48 == 1) {
    population->lowSkillCount04 -= quantity;
    population->mediumSkillCount06 += quantityField04;
    quantityField04 = 0;
    return;
  }

  int newLevel = static_cast<int>(population->highSkillCount08) + quantity;
  TGreatPower* owner = cityField08->ownerNationAc;
  if (newLevel >= 10 && owner->serializedStatusFlags[7] < '2') {
    owner->SetNationPendingActionStateAndPayload(7, 2);
  } else if (newLevel >= 30 && owner->serializedStatusFlags[7] <= '3') {
    owner->SetNationPendingActionStateAndPayload(7, 3);
  }
  population->mediumSkillCount06 -= quantityField04;
  population->highSkillCount08 += quantityField04;
  quantityField04 = 0;
}

// FUNCTION: IMPERIALISM 0x004b6f00
void TTrainingOrder::Restock() {}
