#include "game/military/TMilitaryUnit.h"
#include "game/core/stream_byteswap.h"

#include "game/ui_core/CIterator.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMission.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x004a3b30
void TMilitaryUnit::SetOrClearBattleStateFlags(short mask, bool setFlag) {
  if (setFlag) {
    battleStateFlags |= mask;
  } else {
    battleStateFlags &= ~mask;
  }
}

IMPLEMENT_DYNCREATE(TMilitaryUnit, TObject)

// FUNCTION: IMPERIALISM 0x005c2df0
TMilitaryUnit::TMilitaryUnit()
    : experiencePercent(0), battleStateFlags(0), strengthSnapshot(0), ownerMission(NULL) {
  militaryRegistrationFlag = true;
  strength = 0x1f4;
  eraIndex = 0;
  CString empty(g_szEmptyString);
  name = empty;
}

// FUNCTION: IMPERIALISM 0x005c2f00
TMilitaryUnit::~TMilitaryUnit() {}

// FUNCTION: IMPERIALISM 0x005c2f50
void TMilitaryUnit::IMilitaryUnit(MilitaryUnitKindStorage unitKind, int nodeContext,
                                  short nationSlot, short registerArg3) {
  militaryRegistrationFlag = true;
  tileIndex = -1;
  IUnit(unitKind, nodeContext, nationSlot, registerArg3);
  eraIndex = static_cast<short>(
      (static_cast<int>(unitKind) + (static_cast<int>(unitKind) >> 31 & 7)) >> 3);
  if (unitKind >= EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1)) {
    g_apTerrainTypeDescriptorTable[nationSlot]->GenerateEthnicName(&name);
  }
  ClearPath();
}

// FUNCTION: IMPERIALISM 0x005c2fd0
void TMilitaryUnit::ReadFrom(TStream* stream) {
  TUnit::ReadFrom(stream);
  stream->ReadSharedString(&name, 0x20);
  stream->ReadBytes(orderTargetTiles, 6);
  SwapShortArrayBytes(orderTargetTiles, 3);
  stream->ReadBytes(orderTargetTilesMirror, 6);
  SwapShortArrayBytes(orderTargetTilesMirror, 3);
  stream->ReadBytes(&strength, 2);
  stream->ReadBytes(&eraIndex, 2);
  stream->ReadBytes(&experiencePercent, 2);
  stream->ReadBytes(&battleStateFlags, 2);
}

// FUNCTION: IMPERIALISM 0x005c30a0
void TMilitaryUnit::WriteTo(TStream* stream) {
  TUnit::WriteTo(stream);
  stream->WriteSharedString(&name);
  WriteShortArrayElems(stream, orderTargetTiles, 3);
  WriteShortArrayElemsRev(stream, orderTargetTilesMirror, 3);
  stream->WriteBytes(&strength, 2);
  stream->WriteBytes(&eraIndex, 2);
  stream->WriteBytes(&experiencePercent, 2);
  stream->WriteBytes(&battleStateFlags, 2);
}

// FUNCTION: IMPERIALISM 0x005c3190
void TMilitaryUnit::ClearPath() {
  for (int i = 0; i < 3; ++i) {
    orderTargetTiles[i] = tileIndex;
    orderTargetTilesMirror[i] = tileIndex;
  }
}

// FUNCTION: IMPERIALISM 0x005c31c0
void TMilitaryUnit::Vaporize() {
  if (ownerMission != 0) {
    ownerMission->RejectConstituent(this, true);
  }
  MoveTo(-1);
  ClearPath();
}

// FUNCTION: IMPERIALISM 0x005c3200
void TMilitaryUnit::MoveTo(short anchorIndex) {
  if (tileIndex != -1) {
    if (previousAtLocation == 0) {
      if (tileIndex >= 0 && tileIndex < kProvinceCount) {
        g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain =
            static_cast<TMilitaryUnit*>(nextAtLocation);
      }
    } else {
      previousAtLocation->nextAtLocation = nextAtLocation;
    }
    if (nextAtLocation != 0) {
      nextAtLocation->previousAtLocation = previousAtLocation;
    }
    tileIndex = -1;
    previousAtLocation = 0;
    nextAtLocation = 0;
  }

  short newTileIndex = anchorIndex;
  if (newTileIndex == -1) {
    previousAtLocation = 0;
    nextAtLocation = 0;
    tileIndex = newTileIndex;
    orderTargetIndex = -1;
    return;
  }

  TMilitaryUnit* head = 0;
  if (newTileIndex >= 0 && newTileIndex < kProvinceCount) {
    head = g_pGlobalMapState->cityScoreTable[newTileIndex].stationedUnitChain;
  }

  if (head == 0) {
    if (newTileIndex >= 0 && newTileIndex < kProvinceCount) {
      g_pGlobalMapState->cityScoreTable[newTileIndex].stationedUnitChain = this;
    }
    previousAtLocation = 0;
    nextAtLocation = 0;
    tileIndex = newTileIndex;
    orderTargetIndex = -1;
    return;
  }

  short priority = g_awTacticalUnitCategoryCodeBySlot[orderType];
  if (g_awTacticalUnitCategoryCodeBySlot[head->orderType] < priority) {
    TUnit* scanNode = head;
    TUnit* nextScan = scanNode->nextAtLocation;
    if (nextScan != 0) {
      bool found = false;
      do {
        if (found) {
          break;
        }
        if (g_awTacticalUnitCategoryCodeBySlot[static_cast<TMilitaryUnit*>(nextScan)->orderType] <
            priority) {
          scanNode = nextScan;
        } else {
          found = true;
        }
        nextScan = scanNode->nextAtLocation;
      } while (nextScan != 0);
    }
    TUnit* afterScan = scanNode->nextAtLocation;
    previousAtLocation = scanNode;
    nextAtLocation = afterScan;
    scanNode->nextAtLocation = this;
    if (nextAtLocation != 0) {
      nextAtLocation->previousAtLocation = this;
    }
  } else {
    g_pGlobalMapState->cityScoreTable[newTileIndex].stationedUnitChain = this;
    head->previousAtLocation = this;
    previousAtLocation = 0;
    nextAtLocation = head;
  }

  tileIndex = newTileIndex;
  orderTargetIndex = -1;
}

// FUNCTION: IMPERIALISM 0x005c3400
short TMilitaryUnit::GetArmsCarried() const {
  MilitaryUnitKindStorage unitType = orderType;
  if (unitType == EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1) ||
      unitType == EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra2) ||
      unitType == EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra3)) {
    return 1;
  }
  if (g_aUnitOrderCostProfileByAbilityId[unitType][1] == 0x10) {
    return g_aUnitOrderCostProfileByAbilityId[unitType][2];
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005c3450
short TMilitaryUnit::GetTypeArmsCarried(int slot) {
  if (g_aUnitOrderCostProfileByAbilityId[slot][1] == 0x10) {
    return g_aUnitOrderCostProfileByAbilityId[slot][2];
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005c3490
ArmyUnitCategoryStorage TMilitaryUnit::GetCategory() const {
  return g_awTacticalUnitCategoryCodeBySlot[orderType];
}

// FUNCTION: IMPERIALISM 0x005c34b0
ArmyUnitCategoryStorage TMilitaryUnit::GetTypeCategory(MilitaryUnitKindStorage slot) {
  return g_awTacticalUnitCategoryCodeBySlot[slot];
}

// FUNCTION: IMPERIALISM 0x005c34d0
short TMilitaryUnit::GetTurnDistanceTo(short provinceId) const {
  return tileIndex != provinceId;
}

// FUNCTION: IMPERIALISM 0x005c3500
bool TMilitaryUnit::IsWithinXTurnsOf(short turnLimit, short targetTile) const {
  if (turnLimit == 0) {
    return tileIndex == targetTile;
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x005c3530
short TMilitaryUnit::GetAttribute(short statIndex) const {
  return static_cast<short>((g_UnitTypeStatTable[orderType][statIndex] * 100) /
                            g_UnitTypeStatDivisorTable[statIndex]);
}

// FUNCTION: IMPERIALISM 0x005c3580
short TMilitaryUnit::GetTypeAttribute(MilitaryUnitKindStorage unitType, short statIndex) {
  return static_cast<short>((g_UnitTypeStatTable[unitType][statIndex] * 100) /
                            g_UnitTypeStatDivisorTable[statIndex]);
}

// FUNCTION: IMPERIALISM 0x005c35c0
MilitaryUnitKindStorage TMilitaryUnit::UpgradeType() {
  MilitaryUnitKindStorage unitType = orderType;
  MilitaryUnitKindStorage candidate;
  if (unitType < EncodeMilitaryUnitKind(kMilitaryUnitConscripts)) {
    candidate = static_cast<short>(unitType + 8);
  } else if (unitType == EncodeMilitaryUnitKind(kMilitaryUnitSappers) ||
             unitType == EncodeMilitaryUnitKind(kMilitaryUnitCombatEngineers) ||
             unitType == EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1) ||
             unitType == EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra2)) {
    candidate = static_cast<short>(unitType + 1);
  } else {
    return -1;
  }
  if (g_pTechMgr->abilityActiveRows[ownerNationSlot].abilityActiveById[candidate] == 0 &&
      g_pTechMgr->abilityActiveRows[ownerNationSlot].abilityActiveById[unitType] != 0) {
    return -1;
  }
  return candidate;
}

// FUNCTION: IMPERIALISM 0x005c3650
bool TMilitaryUnit::CanUpgrade() {
  return UpgradeType() != -1;
}

// FUNCTION: IMPERIALISM 0x005c3670
bool TMilitaryUnit::Upgrade() {
  if (UpgradeType() == -1) {
    return false;
  }
  short candidate = UpgradeType();
  short primaryCost = g_aUnitOrderCostProfileByAbilityId[candidate][2];
  short cashCost = g_aUnitOrderCostProfileByAbilityId[candidate][5];
  short secondaryCost;
  if (g_aUnitOrderCostProfileByAbilityId[candidate][3] == 0xc) {
    secondaryCost = g_aUnitOrderCostProfileByAbilityId[candidate][4];
  } else {
    secondaryCost = 0;
  }
  if (primaryCost > g_apNationStates[ownerNationSlot]->GetStockpile(kResourceArms)) {
    return false;
  }
  if (secondaryCost > g_apNationStates[ownerNationSlot]->GetStockpile(kResourceFuel)) {
    return false;
  }
  TGreatPower* nation = g_apNationStates[ownerNationSlot];
  if (nation->diplomacyEligibility != 0 &&
      static_cast<int>(cashCost) > nation->ComputeAvailableDiplomacyBudget()) {
    return false;
  }
  nation->SetStockpile(0x10, static_cast<short>(nation->GetStockpile(kResourceArms) - primaryCost));
  g_apNationStates[ownerNationSlot]->SetStockpile(
      0xc, static_cast<short>(g_apNationStates[ownerNationSlot]->GetStockpile(kResourceFuel) -
                              secondaryCost));
  g_apNationStates[ownerNationSlot]->treasuryValue -= cashCost;
  orderType = candidate;
  return true;
}

// FUNCTION: IMPERIALISM 0x005c3840
void TMilitaryUnit::UpgradeRequirements(short& candidateSlot, short& armsCost, short& cashCost,
                                        short& fuelCost) {
  candidateSlot = UpgradeType();
  armsCost = g_aiCityActionCostProfiles[candidateSlot].primaryMetricMultiplier;
  cashCost = g_aiCityActionCostProfiles[candidateSlot].baseCost;
  if (g_aiCityActionCostProfiles[candidateSlot].secondaryMetricCode == 0xc) {
    fuelCost = g_aiCityActionCostProfiles[candidateSlot].secondaryMetricMultiplier;
  } else {
    fuelCost = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005c38e0
TMilitaryUnit* TMilitaryUnit::FindUnitByUID(int unitId) {
  if (unitId == 0) {
    return 0;
  }
  for (TCountry** cell = g_apTerrainTypeDescriptorTable;
       cell < g_apTerrainTypeDescriptorTable + kTerrainTypeDescriptorTableCount; ++cell) {
    TCountry* descriptor = *cell;
    if (descriptor != 0) {
      CIterator unitIter(descriptor->militaryUnitList);
      for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
           unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
        int candidateId;
        if (unit != 0) {
          candidateId = unit->persistentUnitId;
        } else {
          candidateId = 0;
        }
        if (candidateId == unitId) {
          return unit;
        }
      }
    }
  }
  return 0;
}
