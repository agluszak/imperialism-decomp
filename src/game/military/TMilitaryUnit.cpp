#include "game/military/TMilitaryUnit.h"

#include "game/ui_core/CIterator.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMission.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/military_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x004a3b30
void TMilitaryUnit::SetOrClearWordMaskBits3a(short mask, bool setFlag) {
  if (setFlag) {
    this->field_3A |= mask;
  } else {
    this->field_3A &= ~mask;
  }
}

// SYNTHETIC: IMPERIALISM 0x005c2cb0
// TMilitaryUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c2dd0
// TMilitaryUnit::GetRuntimeClass

// The original descriptor's m_pBaseClass (0x66ed80) points at TObject's CRuntimeClass —
// the retail macro skipped the real C++ base TUnit (the ctor at 0x5c2df0 constructs the
// TUnit prefix layout). Reproduce the retail macro argument.
IMPLEMENT_DYNCREATE(TMilitaryUnit, TObject)

// FUNCTION: IMPERIALISM 0x005c2df0
TMilitaryUnit::TMilitaryUnit()
    : name24(), field_38(0), field_3A(0), field_3C(0), ownerMission40(nullptr) {
  field_1C = 1;
  field_34 = 0x1f4;
  field_36 = 0;
  CString empty(g_szEmptyString); // temp -> 0x00605950, ~ -> 0x006058e2
  name24 = empty;                 // -> 0x00605a29 CString::operator=
}

// SYNTHETIC: IMPERIALISM 0x005c2ed0
// TMilitaryUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2f00
TMilitaryUnit::~TMilitaryUnit() {}

// FUNCTION: IMPERIALISM 0x005c2f50
void TMilitaryUnit::IMilitaryUnit(MilitaryUnitKindStorage unitKind, int nodeContext,
                                  short nationSlot, short registerArg3) {
  field_1C = 1;
  tileIndex06 = static_cast<short>(-1);
  RegisterUnitOrderWithOwnerManager(unitKind, nodeContext, nationSlot, registerArg3);
  field_36 = static_cast<short>(
      (static_cast<int>(unitKind) + (static_cast<int>(unitKind) >> 31 & 7)) >> 3);
  if (unitKind >= EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1)) {
    g_apTerrainTypeDescriptorTable[nationSlot]->GenerateEthnicName(&name24);
  }
  ClearPath();
}

static void SwapAdjacentBytesInShortArray(short* entries, int pairCount) {
  for (int i = 0; i < pairCount; ++i) {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&entries[i]);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
  }
}

// FUNCTION: IMPERIALISM 0x005c2fd0
void TMilitaryUnit::ReadFrom(TStream* stream) {
  TUnit::ReadFrom(stream);
  // name24 (CString) is read here in the original via TStream slot 0x70
  // (streamSlot70, "read shared string with capacity"): args (&name24, 0x20)
  // verified against 0x5c2fd0.
  stream->streamSlot70(&name24, 0x20);
  stream->ReadBytes(orderTargetTiles28, 6);
  SwapAdjacentBytesInShortArray(orderTargetTiles28, 3);
  stream->ReadBytes(orderTargetTilesMirror2E, 6);
  SwapAdjacentBytesInShortArray(orderTargetTilesMirror2E, 3);
  stream->ReadBytes(&field_34, 2);
  stream->ReadBytes(&field_36, 2);
  stream->ReadBytes(&field_38, 2);
  stream->ReadBytes(&field_3A, 2);
}

// FUNCTION: IMPERIALISM 0x005c30a0
void TMilitaryUnit::WriteTo(TStream* stream) {
  TUnit::WriteTo(stream);
  stream->streamSlotAc(&name24);
  for (int i = 0; i < 3; ++i) {
    short swapped = orderTargetTiles28[i];
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&swapped);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    stream->WriteBytesSlot78(&swapped, 2);
  }
  for (int j = 0; j < 3; ++j) {
    short swapped = orderTargetTilesMirror2E[j];
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&swapped);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    stream->WriteBytesSlot78(&swapped, 2);
  }
  stream->WriteBytesSlot78(&field_34, 2);
  stream->WriteBytesSlot78(&field_36, 2);
  stream->WriteBytesSlot78(&field_38, 2);
  stream->WriteBytesSlot78(&field_3A, 2);
}

// FUNCTION: IMPERIALISM 0x005c3190
void TMilitaryUnit::ClearPath() {
  short tile = tileIndex06;
  short* cursor = orderTargetTilesMirror2E;
  int remaining = 3;
  do {
    cursor[-3] = tile; // lands in orderTargetTiles28[]
    *cursor = tile;
    ++cursor;
    --remaining;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x005c31c0
void TMilitaryUnit::DetachUnitOrderFromOwnerAndReset() {
  if (ownerMission40 != 0) {
    ownerMission40->RejectConstituent(this, 1);
  }
  VTableSlot10(-1);
  ClearPath();
}

// Moves this unit between two regions' priority-ordered stationed-unit chains
// (cityScoreTable[region].stationedUnitChain98, threaded via nextOnTile/field_10,
// ordered by g_awTacticalUnitCategoryCodeBySlot[orderType] ascending): detaches from
// the current region's chain (if any), then inserts into the new region's chain (if
// pOwnerContext isn't -1 = none) either as the new head or, when the head's priority
// is lower than this unit's, at the first position whose successor's priority is not
// lower.
// FUNCTION: IMPERIALISM 0x005c3200
void TMilitaryUnit::VTableSlot10(int pOwnerContext) {
  if (tileIndex06 != -1) {
    if (field_10 == 0) {
      if (tileIndex06 >= 0 && tileIndex06 < 0x180) {
        g_pGlobalMapState->cityScoreTable[tileIndex06].stationedUnitChain98 =
            static_cast<TMilitaryUnit*>(nextOnTile);
      }
    } else {
      field_10->nextOnTile = nextOnTile;
    }
    if (nextOnTile != 0) {
      nextOnTile->field_10 = field_10;
    }
    tileIndex06 = -1;
    field_10 = 0;
    nextOnTile = 0;
  }

  short newTileIndex = static_cast<short>(pOwnerContext);
  if (newTileIndex == -1) {
    field_10 = 0;
    nextOnTile = 0;
    tileIndex06 = newTileIndex;
    field_C = -1;
    return;
  }

  TMilitaryUnit* head = 0;
  if (newTileIndex >= 0 && newTileIndex < 0x180) {
    head = g_pGlobalMapState->cityScoreTable[newTileIndex].stationedUnitChain98;
  }

  if (head == 0) {
    if (newTileIndex >= 0 && newTileIndex < 0x180) {
      g_pGlobalMapState->cityScoreTable[newTileIndex].stationedUnitChain98 = this;
    }
    field_10 = 0;
    nextOnTile = 0;
    tileIndex06 = newTileIndex;
    field_C = -1;
    return;
  }

  short priority = g_awTacticalUnitCategoryCodeBySlot[orderType];
  if (g_awTacticalUnitCategoryCodeBySlot[head->orderType] < priority) {
    TUnit* scanNode = head;
    TUnit* nextScan = scanNode->nextOnTile;
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
        nextScan = scanNode->nextOnTile;
      } while (nextScan != 0);
    }
    TUnit* afterScan = scanNode->nextOnTile;
    field_10 = scanNode;
    nextOnTile = afterScan;
    scanNode->nextOnTile = this;
    if (nextOnTile != 0) {
      nextOnTile->field_10 = this;
    }
  } else {
    head->field_10 = this;
    field_10 = 0;
    nextOnTile = head;
  }

  tileIndex06 = newTileIndex;
  field_C = -1;
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
  return g_awTacticalUnitCategoryCodeBySlot[this->orderType];
}

// FUNCTION: IMPERIALISM 0x005c34b0
ArmyUnitCategoryStorage TMilitaryUnit::GetTypeCategory(MilitaryUnitKindStorage slot) {
  return g_awTacticalUnitCategoryCodeBySlot[slot];
}

// FUNCTION: IMPERIALISM 0x005c34d0
short TMilitaryUnit::GetTurnDistanceTo(short provinceId) const {
  return tileIndex06 != provinceId;
}

// FUNCTION: IMPERIALISM 0x005c3500
bool TMilitaryUnit::IsWithinXTurnsOf(short turnLimit, short targetTile) const {
  if (turnLimit == 0) {
    return tileIndex06 == targetTile;
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x005c3530
short TMilitaryUnit::GetAttribute(short statIndex) const {
  return static_cast<short>((g_UnitTypeStatTable_0066EB88[orderType][statIndex] * 100) /
                            g_UnitTypeStatDivisorTable_0066ED30[statIndex]);
}

// FUNCTION: IMPERIALISM 0x005c3580
short TMilitaryUnit::GetTypeAttribute(MilitaryUnitKindStorage unitType, short statIndex) {
  return static_cast<short>((g_UnitTypeStatTable_0066EB88[unitType][statIndex] * 100) /
                            g_UnitTypeStatDivisorTable_0066ED30[statIndex]);
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
  if (g_pCityOrderCapabilityState->abilityActiveRows395[field_18].abilityActiveById[candidate] ==
          0 &&
      g_pCityOrderCapabilityState->abilityActiveRows395[field_18].abilityActiveById[unitType] !=
          0) {
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
  if (primaryCost > g_apNationStates[field_18]->GetDiplomacyExternalStateByTarget(0x10)) {
    return false;
  }
  if (secondaryCost > g_apNationStates[field_18]->GetDiplomacyExternalStateByTarget(0xc)) {
    return false;
  }
  TGreatPower* nation = g_apNationStates[field_18];
  if (nation->diplomacyEligibilityA0 != 0 &&
      static_cast<int>(cashCost) > nation->ComputeAvailableDiplomacyBudget()) {
    return false;
  }
  nation->SetCityStockCounterAndRefresh(
      0x10, static_cast<short>(nation->GetDiplomacyExternalStateByTarget(0x10) - primaryCost));
  g_apNationStates[field_18]->SetCityStockCounterAndRefresh(
      0xc, static_cast<short>(g_apNationStates[field_18]->GetDiplomacyExternalStateByTarget(0xc) -
                              secondaryCost));
  g_apNationStates[field_18]->treasuryValue10 -= cashCost;
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
      CIterator unitIter(descriptor->militaryUnitList44);
      for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
           unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
        int candidateId;
        if (unit != 0) {
          candidateId = unit->field_20;
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
