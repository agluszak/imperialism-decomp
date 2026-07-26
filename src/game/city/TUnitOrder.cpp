#include "game/city/TUnitOrder.h"

#include <string.h>

#include "game/ui_screens/CString.h"
#include "game/city/TCity.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"

// SYNTHETIC: IMPERIALISM 0x004b6f20
// TUnitOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b6f50
// TUnitOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUnitOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b6f90
// TUnitOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b6fc0
TUnitOrder::~TUnitOrder() {}

// FUNCTION: IMPERIALISM 0x004b6fe0
void TUnitOrder::IUnitOrder(TCity* city, short nEntryId, short nPrimaryInputResourceId,
                            short nPrimaryInputPerUnit, short nSecondaryInputResourceId,
                            short nSecondaryInputPerUnit, short nCashCostPerUnit,
                            short nWorkforceMode, byte bSpecialistMode) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = nEntryId;
  quantityField04 = 0;
  memset(trackingSlots10, 0, sizeof(trackingSlots10));
  primaryInputResourceId = nPrimaryInputResourceId;
  primaryInputPerUnit = nPrimaryInputPerUnit;
  secondaryInputResourceId = nSecondaryInputResourceId;
  secondaryInputPerUnit = nSecondaryInputPerUnit;
  accumulatedValue = 0;
  cashCostPerUnit = nCashCostPerUnit;
  field40 = 0;
  field3e = 0;
  workforceMode = nWorkforceMode;
  specialistMode = bSpecialistMode;
}

// FUNCTION: IMPERIALISM 0x004b7080
short TUnitOrder::MaxOrder() {
  short workforceLimit;
  if (workforceMode == kLowSkillWorkforceMode) {
    workforceLimit = summaryField0c->productionSlots14->lowSkillCount04;
    if (summaryField0c->strength < workforceLimit) {
      workforceLimit = summaryField0c->strength;
    }
  } else if (workforceMode == kMediumSkillWorkforceMode) {
    workforceLimit = summaryField0c->productionSlots14->mediumSkillCount06;
    short strengthLimit = static_cast<short>(summaryField0c->strength / 2);
    if (strengthLimit < workforceLimit) {
      workforceLimit = strengthLimit;
    }
  } else if (workforceMode == kHighSkillWorkforceMode) {
    workforceLimit = summaryField0c->productionSlots14->highSkillCount08;
    short strengthLimit = static_cast<short>(summaryField0c->strength / 4);
    if (strengthLimit < workforceLimit) {
      workforceLimit = strengthLimit;
    }
  } else {
    workforceLimit = 9999;
  }

  short primaryLimit = static_cast<short>(cityField08->CityStockByType(primaryInputResourceId) /
                                          primaryInputPerUnit);
  short secondaryLimit = primaryLimit;
  if (secondaryInputResourceId >= 0) {
    secondaryLimit = static_cast<short>(cityField08->CityStockByType(secondaryInputResourceId) /
                                        secondaryInputPerUnit);
  }

  TGreatPower* owner = cityField08->ownerNationAc;
  short cashLimit = primaryLimit;
  if (cashCostPerUnit != 0 && owner->diplomacyEligibilityA0 != 0) {
    int availableCash = owner->treasuryValue10 + owner->diplomacyBudgetBase / 100;
    if (availableCash <= 0) {
      availableCash = 0;
    }
    cashLimit = static_cast<short>(availableCash / cashCostPerUnit);
    if (cashLimit < 0) {
      cashLimit = 0;
    }
  }

  field40 = 1;
  short limit = workforceLimit;
  if (primaryLimit < limit) {
    field40 = 0;
    limit = primaryLimit;
  }
  if (secondaryLimit < limit) {
    field40 = 0;
    limit = secondaryLimit;
  }
  if (cashLimit < limit) {
    field40 = 3;
    limit = cashLimit;
  }
  return static_cast<short>(quantityField04 + limit);
}

// FUNCTION: IMPERIALISM 0x004b7210
bool TUnitOrder::SetQuantity(short param_1) {
  short delta = static_cast<short>(param_1 - quantityField04);
  if (param_1 > MaxOrder() || param_1 < 0) {
    return false;
  }
  quantityField04 = param_1;

  cityField08->CityStockByType(primaryInputResourceId) = static_cast<short>(
      cityField08->CityStockByType(primaryInputResourceId) - primaryInputPerUnit * delta);
  cityField08->VerifyStocks();
  if (secondaryInputResourceId >= 0) {
    cityField08->CityStockByType(secondaryInputResourceId) = static_cast<short>(
        cityField08->CityStockByType(secondaryInputResourceId) - secondaryInputPerUnit * delta);
    cityField08->VerifyStocks();
  }
  if (workforceMode) {
    summaryField0c->RemovePopulation(workforceMode, delta);
  }
  cityField08->ownerNationAc->treasuryValue10 -=
      static_cast<int>(cashCostPerUnit) * static_cast<int>(delta);
  g_pUiRuntimeContext->RefreshCityProductionUi();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b7320
void TUnitOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->ResetOrderSheet(orderSheet);
  orderSheet->ForResourceCode(this->primaryInputResourceId) =
      static_cast<short>(this->primaryInputPerUnit * quantity);
  if (this->secondaryInputResourceId >= 0) {
    orderSheet->ForResourceCode(this->secondaryInputResourceId) =
        static_cast<short>(this->secondaryInputPerUnit * quantity);
  }
  if (this->workforceMode == kMediumSkillWorkforceMode) {
    orderSheet->slotByResourceCode[0x17] = quantity;
    return;
  }
  if (this->workforceMode == kHighSkillWorkforceMode) {
    orderSheet->slotByResourceCode[0x18] = quantity;
    return;
  }
  orderSheet->slotByResourceCode[0x3c] = quantity;
}

// Slot 0x0d: commit the pending recruitment delta for this city order. Civilian recruits
// are placed on a reachable tile belonging to the selected town's connected region. The
// retail search is repeated for every recruit because each constructed TCivUnit immediately
// occupies its chosen tile and changes the next search result.
// FUNCTION: IMPERIALISM 0x004b73b0
void TUnitOrder::Produce() {
  short pendingDelta = quantityField04;
  TCity* cityContext = cityField08;
  if (pendingDelta <= 0 || cityContext == 0) {
    return;
  }

  CString sharedRefA;
  CString sharedRefB;

  short entryId = resourceTypeIndex48;
  unsigned char specialist = specialistMode;
  TSimMgr* localization = g_pSimMgr;
  if (localization != 0) {
    localization->GetString(static_cast<short>((specialist == 0) ? 0x2718 : 0x2717), entryId,
                            &sharedRefB);
  }

  cityContext->cityMetricsBlock4A[entryId] =
      static_cast<short>(cityContext->cityMetricsBlock4A[entryId] + pendingDelta);

  TGreatPower* ownerNation = cityContext->ownerNationAc;
  short ownerNationSlot = 0;
  if (ownerNation != 0) {
    ownerNationSlot = ownerNation->nationSlot;
  }

  const short recruitSearchOrigin = cityContext->SelectedOrderTileId();
  const bool allowActiveFlag2 = entryId == 4;
  for (short i = 0; i < pendingDelta; ++i) {
    short spawnTile = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
        recruitSearchOrigin, allowActiveFlag2);
    if (spawnTile == -1) {
      continue;
    }

    TCivUnit* orderObject = new TCivUnit();
    if (orderObject == nullptr) {
      continue;
    }

    CivilianUnitKind unitKind = DecodeCivilianUnitKind(entryId);
    orderObject->ICivUnit(unitKind, spawnTile, ownerNationSlot);
  }

  quantityField04 = 0;
}

// The store order (0x48, 0x4c, 0x50, 0x4e, 0x52, 0x54, 0x56) follows the original's
// interleaved word moves.
// FUNCTION: IMPERIALISM 0x004b77e0
void TUnitOrder::SetOrderCostProfile(short resourceTypeIndex, short nPrimaryInputResourceId,
                                     short nPrimaryInputPerUnit, short nSecondaryInputResourceId,
                                     short nSecondaryInputPerUnit, short nCashCostPerUnit,
                                     short nWorkforceMode) {
  this->resourceTypeIndex48 = resourceTypeIndex;
  this->primaryInputResourceId = nPrimaryInputResourceId;
  this->primaryInputPerUnit = nPrimaryInputPerUnit;
  this->secondaryInputResourceId = nSecondaryInputResourceId;
  this->secondaryInputPerUnit = nSecondaryInputPerUnit;
  this->cashCostPerUnit = nCashCostPerUnit;
  this->workforceMode = nWorkforceMode;
}

// FUNCTION: IMPERIALISM 0x004b7850
void TUnitOrder::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&resourceTypeIndex48, 2);
  stream->WriteBytes(&quantityField04, 2);
  stream->WriteBytes(&field40, 2);
  stream->WriteBytes(&resourceTypeIndex48, 2);
  stream->WriteBytes(trackingSlots10, 0x2e);
  stream->WriteBytes(&accumulatedValue, 4);
  stream->WriteBytes(&primaryInputResourceId, 2);
  stream->WriteBytes(&secondaryInputResourceId, 2);
  stream->WriteBytes(&primaryInputPerUnit, 2);
  stream->WriteBytes(&secondaryInputPerUnit, 2);
  stream->WriteBytes(&cashCostPerUnit, 2);
  stream->WriteBytes(&workforceMode, 2);
  stream->WriteBytes(&specialistMode, 1);
}

// FUNCTION: IMPERIALISM 0x004b7920
void TUnitOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(&quantityField04, 2);
  stream->ReadBytes(&field40, 2);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(trackingSlots10, 0x2e);
  stream->ReadBytes(&accumulatedValue, 4);
  stream->ReadBytes(&primaryInputResourceId, 2);
  stream->ReadBytes(&secondaryInputResourceId, 2);
  stream->ReadBytes(&primaryInputPerUnit, 2);
  stream->ReadBytes(&secondaryInputPerUnit, 2);
  stream->ReadBytes(&cashCostPerUnit, 2);
  stream->ReadBytes(&workforceMode, 2);
  stream->ReadBytes(&specialistMode, 1);
}
