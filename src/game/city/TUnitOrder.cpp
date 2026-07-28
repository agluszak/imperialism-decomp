#include "game/city/TUnitOrder.h"

#include <string.h>

#include "game/core/CString.h"
#include "game/city/TCity.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/military/TMilitaryUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
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
  ownerCity = city;
  productionSummary = city->productionSummary1d8;
  resourceTypeIndex = nEntryId;
  quantity = 0;
  memset(trackingSlots, 0, sizeof(trackingSlots));
  primaryInputResourceId = nPrimaryInputResourceId;
  primaryInputPerUnit = nPrimaryInputPerUnit;
  secondaryInputResourceId = nSecondaryInputResourceId;
  secondaryInputPerUnit = nSecondaryInputPerUnit;
  accumulatedValue = 0;
  cashCostPerUnit = nCashCostPerUnit;
  limitingConstraint = kProductionOrderLimitResources;
  reservedWorkforce = 0;
  workforceMode = nWorkforceMode;
  specialistMode = bSpecialistMode;
}

// FUNCTION: IMPERIALISM 0x004b7080
short TUnitOrder::MaxOrder() {
  short workforceLimit;
  if (workforceMode == kLowSkillWorkforceMode) {
    workforceLimit = productionSummary->productionSlots14->lowSkillCount04;
    if (productionSummary->strength < workforceLimit) {
      workforceLimit = productionSummary->strength;
    }
  } else if (workforceMode == kMediumSkillWorkforceMode) {
    workforceLimit = productionSummary->productionSlots14->mediumSkillCount06;
    short strengthLimit = static_cast<short>(productionSummary->strength / 2);
    if (strengthLimit < workforceLimit) {
      workforceLimit = strengthLimit;
    }
  } else if (workforceMode == kHighSkillWorkforceMode) {
    workforceLimit = productionSummary->productionSlots14->highSkillCount08;
    short strengthLimit = static_cast<short>(productionSummary->strength / 4);
    if (strengthLimit < workforceLimit) {
      workforceLimit = strengthLimit;
    }
  } else {
    workforceLimit = 9999;
  }

  short primaryLimit =
      static_cast<short>(ownerCity->CityStockByType(primaryInputResourceId) / primaryInputPerUnit);
  short secondaryLimit = primaryLimit;
  if (secondaryInputResourceId >= 0) {
    secondaryLimit = static_cast<short>(ownerCity->CityStockByType(secondaryInputResourceId) /
                                        secondaryInputPerUnit);
  }

  TGreatPower* owner = ownerCity->ownerNationAc;
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

  limitingConstraint = kProductionOrderLimitWorkforce;
  short limit = workforceLimit;
  if (primaryLimit < limit) {
    limitingConstraint = kProductionOrderLimitResources;
    limit = primaryLimit;
  }
  if (secondaryLimit < limit) {
    limitingConstraint = kProductionOrderLimitResources;
    limit = secondaryLimit;
  }
  if (cashLimit < limit) {
    limitingConstraint = kProductionOrderLimitTreasury;
    limit = cashLimit;
  }
  return static_cast<short>(quantity + limit);
}

// FUNCTION: IMPERIALISM 0x004b7210
bool TUnitOrder::SetQuantity(short quantity) {
  short delta = static_cast<short>(quantity - this->quantity);
  if (quantity > MaxOrder() || quantity < 0) {
    return false;
  }
  this->quantity = quantity;

  ownerCity->CityStockByType(primaryInputResourceId) = static_cast<short>(
      ownerCity->CityStockByType(primaryInputResourceId) - primaryInputPerUnit * delta);
  ownerCity->VerifyStocks();
  if (secondaryInputResourceId >= 0) {
    ownerCity->CityStockByType(secondaryInputResourceId) = static_cast<short>(
        ownerCity->CityStockByType(secondaryInputResourceId) - secondaryInputPerUnit * delta);
    ownerCity->VerifyStocks();
  }
  if (workforceMode) {
    productionSummary->RemovePopulation(workforceMode, delta);
  }
  ownerCity->ownerNationAc->treasuryValue10 -=
      static_cast<int>(cashCostPerUnit) * static_cast<int>(delta);
  g_pViewMgr->RefreshCityProductionUi();
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
  short pendingDelta = quantity;
  TCity* cityContext = ownerCity;
  if (pendingDelta <= 0 || cityContext == 0) {
    return;
  }

  CString sharedRefA;
  CString sharedRefB;

  short entryId = resourceTypeIndex;
  unsigned char specialist = specialistMode;
  TSimMgr* localization = g_pSimMgr;
  if (localization != 0) {
    if (specialist == 0) {
      localization->GetString(0x2718, entryId, &sharedRefB);
    } else {
      localization->GetString(0x2717, entryId, &sharedRefB);
    }
  }

  cityContext->cityMetricsBlock4A[entryId] =
      static_cast<short>(cityContext->cityMetricsBlock4A[entryId] + pendingDelta);

  TGreatPower* ownerNation = cityContext->ownerNationAc;
  short ownerNationSlot = 0;
  if (ownerNation != 0) {
    ownerNationSlot = ownerNation->nationSlot;
  }

  if (specialist == 0) {
    const short recruitSearchOrigin = cityContext->HomeTownTileId();
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
  } else {
    for (short i = 0; i < pendingDelta; ++i) {
      short homeTile = cityContext->HomeTownTileId();
      short homeProvince = g_pGlobalMapState->terrainStateTable[homeTile].cityRecordIndex;
      TMilitaryUnit* orderObject = new TMilitaryUnit();
      if (orderObject == 0) {
        continue;
      }
      orderObject->IMilitaryUnit(static_cast<MilitaryUnitKindStorage>(entryId), homeProvince,
                                 ownerNationSlot, 0);
      if (ownerNation->pendingActionStatus.roles.territorialPressureStatus06 >= 0x33) {
        orderObject->experiencePercent38 = 100;
      }

      ownerNation->ComputeSelectedMilitaryPowerScore();
      if (ownerNation->pendingActionStatus.roles.landRecruitStatus01 != 0x32) {
        int currentLevel = ownerNation->pendingActionStatus.roles.landRecruitStatus01;
        if (currentLevel != 0) {
          currentLevel -= 0x33;
        }
        int militaryPower = ownerNation->ComputeSelectedMilitaryPowerScore();
        if (militaryPower >= 0xf && militaryPower < 0x28 && currentLevel == 0) {
          ownerNation->SetNationPendingActionStateAndPayload(1, 1);
        } else if (militaryPower >= 0x28 && militaryPower < 0x46 && currentLevel < 2) {
          ownerNation->SetNationPendingActionStateAndPayload(1, 2);
        } else if (militaryPower >= 0x46 && militaryPower < 0x78 && currentLevel < 3) {
          ownerNation->SetNationPendingActionStateAndPayload(1, 3);
        } else if (militaryPower >= 0x78 && militaryPower < 0xaa && currentLevel < 4) {
          ownerNation->SetNationPendingActionStateAndPayload(1, 4);
        } else if (militaryPower >= 0xdc && militaryPower < 0x10e && currentLevel < 5) {
          ownerNation->SetNationPendingActionStateAndPayload(1, 5);
        } else if (militaryPower >= 0x10e && militaryPower < 0x140 && currentLevel < 6) {
          ownerNation->SetNationPendingActionStateAndPayload(1, 6);
        }
      }
    }
  }

  ownerNation->AnnounceLater(specialist == 0 ? 2 : 3, entryId, pendingDelta);
  quantity = 0;
  if (entryId == 0) {
    cityContext->serializedState0a = static_cast<short>(cityContext->serializedState0a + 1);
  }
}

// The store order (0x48, 0x4c, 0x50, 0x4e, 0x52, 0x54, 0x56) follows the original's
// interleaved word moves.
// FUNCTION: IMPERIALISM 0x004b77e0
void TUnitOrder::SetOrderCostProfile(short resourceTypeIndex, short nPrimaryInputResourceId,
                                     short nPrimaryInputPerUnit, short nSecondaryInputResourceId,
                                     short nSecondaryInputPerUnit, short nCashCostPerUnit,
                                     short nWorkforceMode) {
  this->resourceTypeIndex = resourceTypeIndex;
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
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(&quantity, 2);
  stream->WriteBytes(&limitingConstraint, 2);
  stream->WriteBytes(&resourceTypeIndex, 2);
  stream->WriteBytes(trackingSlots, sizeof(trackingSlots));
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
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(&quantity, 2);
  stream->ReadBytes(&limitingConstraint, 2);
  stream->ReadBytes(&resourceTypeIndex, 2);
  stream->ReadBytes(trackingSlots, sizeof(trackingSlots));
  stream->ReadBytes(&accumulatedValue, 4);
  stream->ReadBytes(&primaryInputResourceId, 2);
  stream->ReadBytes(&secondaryInputResourceId, 2);
  stream->ReadBytes(&primaryInputPerUnit, 2);
  stream->ReadBytes(&secondaryInputPerUnit, 2);
  stream->ReadBytes(&cashCostPerUnit, 2);
  stream->ReadBytes(&workforceMode, 2);
  stream->ReadBytes(&specialistMode, 1);
}
