#include "game/military/TArmyStack.h"
#include "game/map/TMapMgr.h"

#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/city_ui/TCountry.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x004a3b70
TMilitaryUnit* TArmyStack::ResetCursorAndGetHeadUnit() {
  this->cursor18 = this->head14;
  return (this->head14 != nullptr) ? this->head14->unit : nullptr;
}

// FUNCTION: IMPERIALISM 0x004a3b90
TMilitaryUnit* TArmyStack::AdvanceCursorAndGetUnit() {
  if (this->cursor18 != nullptr) {
    this->cursor18 = this->cursor18->next;
    if (this->cursor18 != nullptr) {
      return this->cursor18->unit;
    }
  }
  return nullptr;
}

// SYNTHETIC: IMPERIALISM 0x004a76a0
// TArmyStack::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a76d0
// TArmyStack::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyStack, TObject)

// FUNCTION: IMPERIALISM 0x004a76f0
TArmyStack::TArmyStack() {
  head14 = 0;
  cursor18 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004a7720
// TArmyStack::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004a7750
TArmyStack::~TArmyStack() {}

// FUNCTION: IMPERIALISM 0x004a7770
void TArmyStack::IArmyStack(char ownerNationIndex, short ownerNationCode, short tileIndex) {
  unitCountA = 0;
  field6 = 0;
  field4 = 0;
  fieldC = 0;
  ownerNationCodeE = ownerNationCode;
  categoryFlag8 = ownerNationIndex;
  tileIndex10 = tileIndex;
}

// FUNCTION: IMPERIALISM 0x004a77b0
void TArmyStack::ReadFrom(TStream* stream) {
  stream->ReadBytes(&field4, 2);
  stream->ReadBytes(&field6, 2);
  stream->ReadBytes(&categoryFlag8, 1);
  stream->ReadBytes(&fortLevelAttackerPenaltyCache9, 1);
  short unitCount;
  stream->ReadBytes(&unitCount, 2);
  stream->ReadBytes(&fieldC, 1);
  stream->ReadBytes(&ownerNationCodeE, 2);
  stream->ReadBytes(&tileIndex10, 2);

  for (int i = 0; i < unitCount; ++i) {
    short rosterID;
    stream->ReadBytes(&rosterID, 2);
    AddUnitByRosterId(rosterID);
  }
  cursor18 = 0;
}

// FUNCTION: IMPERIALISM 0x004a7960
void TArmyStack::WriteTo(TStream* stream) {
  stream->WriteBytes(&field4, 2);
  stream->WriteBytes(&field6, 2);
  stream->WriteBytes(&categoryFlag8, 1);
  stream->WriteBytes(&fortLevelAttackerPenaltyCache9, 1);
  stream->WriteBytes(&unitCountA, 2);
  stream->WriteBytes(&fieldC, 1);
  stream->WriteBytes(&ownerNationCodeE, 2);
  stream->WriteBytes(&tileIndex10, 2);

  for (TMilitaryUnit* unit = ResetCursorAndGetHeadUnit(); unit != 0;
       unit = AdvanceCursorAndGetUnit()) {
    short rosterID = unit->unitRosterId1A;
    stream->WriteBytes(&rosterID, 2);
  }
  cursor18 = 0;
}

// FUNCTION: IMPERIALISM 0x004a7a40
void TArmyStack::AddUnitByRosterId(short rosterID) {
  TSortedList* unitList = g_apTerrainTypeDescriptorTable[categoryFlag8]->militaryUnitList44;
  CIterator cursor(unitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset()); cursor.More();
       unit = static_cast<TMilitaryUnit*>(cursor.Advance())) {
    if (unit->unitRosterId1A == rosterID) {
      AddUnitToChainHead(unit);
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a7b20
void TArmyStack::AddUnitToChainHead(TMilitaryUnit* unit) {
  TArmyStackUnitNode* node = new TArmyStackUnitNode();
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0xbeb);
  }
  node->unit = unit;
  node->next = head14;
  ++unitCountA;
  head14 = node;
}

// FUNCTION: IMPERIALISM 0x004a7ba0
void TArmyStack::RemoveUnitFromChain(TMilitaryUnit* unit) {
  TArmyStackUnitNode* prev = head14;
  if (prev != nullptr) {
    TArmyStackUnitNode* node = prev->next;
    if (prev->unit == unit) {
      head14 = node;
      delete prev;
      --unitCountA;
      return;
    }
    for (; node != nullptr && node->unit != unit; node = node->next) {
      prev = node;
    }
    TArmyStackUnitNode* found = prev->next;
    if (found != nullptr) {
      prev->next = found->next;
      delete found;
      --unitCountA;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a7c20
void TArmyStack::Free() {
  TArmyStackUnitNode* next = head14;
  while (next != 0) {
    TArmyStackUnitNode* node = next;
    next = next->next;
    delete node;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004a7c60
void TArmyStack::ComputeStackCompositionClassCode() {
  short minClass = 3;
  short maxClass = 1;
  for (TMilitaryUnit* unit = ResetCursorAndGetHeadUnit(); unit != 0;
       unit = AdvanceCursorAndGetUnit()) {
    short unitClass = g_awUnitCombatClassBySlot[unit->orderType];
    if (unitClass < minClass) {
      minClass = unitClass;
    }
    if (unitClass > maxClass) {
      maxClass = unitClass;
    }
  }
  field4 = g_abStackCompositionClassTable[maxClass][minClass];
  int roll = rand();
  field6 = static_cast<short>((field4 << 8) + (roll & 0xff));
}

// FUNCTION: IMPERIALISM 0x004a7d20
void TArmyStack::ReseatChainUnitsAndClearOrders() {
  for (TMilitaryUnit* unit = ResetCursorAndGetHeadUnit(); unit != 0;
       unit = AdvanceCursorAndGetUnit()) {
    unit->MoveTo(unit->orderTargetIndex0C);
    unit->SetOrders(kUnitOrderIdle, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004a7d90
void TArmyStack::InitializeStrategicBattle(unsigned char boosted) {
  TMilitaryUnit* unit = ResetCursorAndGetHeadUnit();
  if (unit == 0) {
    return;
  }

  fortLevelAttackerPenaltyCache9 = static_cast<unsigned char>(
      g_anFortLevelAttackerPenaltyPercentByLevel
          [g_pGlobalMapState->cityScoreTable[unit->tileIndex06].fortLevel03]);

  for (; unit != 0; unit = AdvanceCursorAndGetUnit()) {
    unit->strengthSnapshot3C = unit->strength34;
    if (boosted != 0 && g_abUnitTypeBlinkEligibilityFlag[unit->orderType] != 0) {
      unit->battleStateFlags3A |= 1;
    } else {
      unit->battleStateFlags3A &= ~1;
    }
    unit->battleStateFlags3A &= ~2;
  }
}

// FUNCTION: IMPERIALISM 0x004a7e70
void TArmyStack::AccumulateWeightedMeterAndCountFromEligibleLinkedEntries(int* outWeightedSum,
                                                                          int* outCount,
                                                                          int counter) {
  // Blend-ratio pair, indexed by counter (0-3): primary weight favors the "weight class"
  // score early, secondary weight favors the "scaled factor" score in later rounds.
  const int kRoundBlendWeightPrimary[4] = {100, 75, 50, 25};
  const int kRoundBlendWeightSecondary[4] = {0, 25, 50, 75};
  if (counter > 3) {
    counter = 3;
  }
  *outWeightedSum = 0;
  *outCount = 0;

  for (TMilitaryUnit* unit = ResetCursorAndGetHeadUnit(); unit != 0;
       unit = AdvanceCursorAndGetUnit()) {
    if (unit->strength34 > unit->strengthSnapshot3C / 2 && (unit->battleStateFlags3A & 2) == 0) {
      int weightClass = g_anWeightClassByOrderType[unit->orderType];
      short scaledFactor = g_anScaledFactorByOrderType[unit->orderType];
      int percentEfficiency = static_cast<int>(g_afPercentEfficiencyByOrderType[unit->orderType]);
      *outWeightedSum += (((scaledFactor * kRoundBlendWeightSecondary[counter]) / 1000 +
                           (kRoundBlendWeightPrimary[counter] * weightClass) / 100) *
                          percentEfficiency * unit->strength34) /
                         500;
      *outCount += g_anCountWeightByOrderType[unit->orderType];
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a8040
void TArmyStack::ApplyRandomizedMeterDecayToEligibleLinkedEntries(int weightedSum, int count,
                                                                  int counter) {
  if (counter > 3) {
    counter = 3;
  }

  int activityScore = 0;
  for (TMilitaryUnit* unit = ResetCursorAndGetHeadUnit(); unit != 0;
       unit = AdvanceCursorAndGetUnit()) {
    if (unit->strength34 > 0 && (unit->battleStateFlags3A & 2) == 0) {
      activityScore += (unit->strength34 > unit->strengthSnapshot3C / 2) ? 2 : 1;
    }
  }
  if (activityScore == 0) {
    return;
  }

  const int kDecayScalePercentByRound[4] = {70, 80, 90, 90};
  int averageStrength = weightedSum / activityScore;
  int participationPercent = count + static_cast<signed char>(fortLevelAttackerPenaltyCache9);
  if (participationPercent > 100) {
    participationPercent = 100;
  }
  int baseDecay = participationPercent * averageStrength / 100;

  for (TMilitaryUnit* decayUnit = ResetCursorAndGetHeadUnit(); decayUnit != 0;
       decayUnit = AdvanceCursorAndGetUnit()) {
    if (decayUnit->strength34 > 0 && (decayUnit->battleStateFlags3A & 2) == 0) {
      int eligibilityScale = decayUnit->strength34 > decayUnit->strengthSnapshot3C / 2 ? 2 : 1;
      int randomScale = (((rand() % 7) + 7) * eligibilityScale * baseDecay) / 10;
      if (g_MapContextStaticTable_00695428[decayUnit->orderType] != 0) {
        randomScale /= 2;
      }
      int decayAmount = static_cast<int>(g_afRandomizedMeterDecayByOrderType[decayUnit->orderType] *
                                         100.0f * randomScale);
      if ((decayUnit->battleStateFlags3A & 1) != 0) {
        decayAmount = (kDecayScalePercentByRound[counter] * decayAmount) / 100;
      }
      if (decayAmount < decayUnit->strength34) {
        decayUnit->strength34 -= static_cast<short>(decayAmount);
      } else {
        decayUnit->strength34 = 0;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a82b0
void TArmyStack::ApplyMeterGrowthToEligibleUnits(bool boosted) {
  short growthAmount = boosted ? 0x23 : 0x14;
  for (TMilitaryUnit* unit = ResetCursorAndGetHeadUnit(); unit != 0;
       unit = AdvanceCursorAndGetUnit()) {
    if (unit->strength34 > 0) {
      unit->experiencePercent38 = static_cast<short>(unit->experiencePercent38 + growthAmount);
      if (unit->experiencePercent38 > 0x190) {
        unit->experiencePercent38 = 0x190;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a8330
bool TArmyStack::UnitsFighting() {
  for (TMilitaryUnit* unit = ResetCursorAndGetHeadUnit(); unit != 0;
       unit = AdvanceCursorAndGetUnit()) {
    if (unit->strength34 > unit->strengthSnapshot3C / 2 && (unit->battleStateFlags3A & 2) == 0) {
      return true;
    }
  }
  return false;
}
