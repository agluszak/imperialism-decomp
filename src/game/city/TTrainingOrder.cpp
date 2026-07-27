#include "game/city/TTrainingOrder.h"

#include "game/city/TCity.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b6a60
// TTrainingOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b6a90
// TTrainingOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTrainingOrder, TProductionOrder)

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
  short paperPerUnit;
  int cashPerUnit;
  short workforceLimit;
  if (resourceTypeIndex48 == 1) {
    paperPerUnit = 1;
    cashPerUnit = 100;
    workforceLimit = summaryField0c->productionSlots14->lowSkillCount04;
    if (summaryField0c->strength < workforceLimit) {
      workforceLimit = summaryField0c->strength;
    }
  } else {
    paperPerUnit = 2;
    cashPerUnit = 1000;
    workforceLimit = summaryField0c->productionSlots14->mediumSkillCount06;
    short strengthLimit = static_cast<short>(summaryField0c->strength / 2);
    if (strengthLimit < workforceLimit) {
      workforceLimit = strengthLimit;
    }
  }

  TGreatPower* owner = cityField08->ownerNationAc;
  short cashLimit;
  if (owner->diplomacyEligibilityA0 == 0) {
    cashLimit = workforceLimit;
  } else {
    int availableCash = owner->treasuryValue10 + owner->diplomacyBudgetBase / 100;
    if (availableCash <= 0) {
      availableCash = 0;
    }
    cashLimit = static_cast<short>(availableCash / cashPerUnit);
    if (cashLimit < 0) {
      cashLimit = 0;
    }
  }

  short paperLimit = static_cast<short>(cityField08->cityStockPaperCA / paperPerUnit);
  field40 = 1;
  short limit = workforceLimit;
  if (cashLimit < limit) {
    field40 = 3;
    limit = cashLimit;
  }
  if (paperLimit < limit) {
    field40 = 0;
    limit = paperLimit;
  }

  if (quantityField04 + limit > 99) {
    limit = static_cast<short>(99 - quantityField04);
  }
  return static_cast<short>(quantityField04 + limit);
}

// FUNCTION: IMPERIALISM 0x004b6cd0
bool TTrainingOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - quantityField04);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  quantityField04 = quantity;

  TGreatPower* owner = cityField08->ownerNationAc;
  if (resourceTypeIndex48 == 1) {
    cityField08->cityStockPaperCA = static_cast<short>(cityField08->cityStockPaperCA - delta);
    cityField08->VerifyStocks();
    owner->treasuryValue10 -= static_cast<int>(delta) * 100;
  } else {
    cityField08->cityStockPaperCA = static_cast<short>(cityField08->cityStockPaperCA - delta * 2);
    cityField08->VerifyStocks();
    owner->treasuryValue10 -= static_cast<int>(delta) * 1000;
  }
  summaryField0c->MakeUnavailable(resourceTypeIndex48, delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
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
  if (newLevel >= 10 && owner->pendingActionStatus.roles.trainingStatus07 < '2') {
    owner->SetNationPendingActionStateAndPayload(7, 2);
  } else if (newLevel >= 30 && owner->pendingActionStatus.roles.trainingStatus07 <= '3') {
    owner->SetNationPendingActionStateAndPayload(7, 3);
  }
  population->mediumSkillCount06 -= quantityField04;
  population->highSkillCount08 += quantityField04;
  quantityField04 = 0;
}

// FUNCTION: IMPERIALISM 0x004b6f00
void TTrainingOrder::Restock() {}
