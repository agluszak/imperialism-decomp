#include "game/military/TArmyStack.h"

#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/city_ui/TCountry.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/military_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// Duplicates TArmyMgr.cpp's own (file-static) IsUnitMeterEligible check -- ground truth
// repeats this same inline test across every meter-related function in this family
// rather than factoring it into a shared helper.
static bool IsUnitMeterEligible(TUnit* unit) {
  TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
  return milUnit->field_34 > milUnit->field_3C / 2 && (milUnit->field_3A & 2) == 0;
}

// FUNCTION: IMPERIALISM 0x004a3b70
TUnit* TArmyStack::ResetCursorAndGetHeadUnit() {
  this->cursor18 = this->head14;
  return (this->head14 != nullptr) ? this->head14->unit : nullptr;
}

// FUNCTION: IMPERIALISM 0x004a3b90
TUnit* TArmyStack::AdvanceCursorAndGetUnit() {
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
TArmyStack::~TArmyStack() {}

// FUNCTION: IMPERIALISM 0x004a7770
void TArmyStack::InitializeSideAndTile(char ownerNationIndex, short ownerNationCode,
                                       short tileIndex) {
  fieldA = 0;
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

  for (short i = 0; i < unitCount; ++i) {
    short unitTag;
    stream->ReadBytes(&unitTag, 2);

    TSortedList* unitList = g_apTerrainTypeDescriptorTable[categoryFlag8]->militaryUnitList44;
    TUnit* foundUnit = 0;
    CIterator cursor(unitList);
    for (TUnit* unit = static_cast<TUnit*>(cursor.Reset()); cursor.More();
         unit = static_cast<TUnit*>(cursor.Advance())) {
      if (unit->field_1A == unitTag) {
        foundUnit = unit;
        break;
      }
    }

    if (foundUnit != 0) {
      TArmyStackUnitNode* node = new TArmyStackUnitNode();
      if (node == 0) {
        MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
        TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0xbeb);
      }
      node->unit = foundUnit;
      node->next = head14;
      ++fieldA;
      head14 = node;
    }
  }
  cursor18 = 0;
}

// FUNCTION: IMPERIALISM 0x004a7960
void TArmyStack::WriteTo(TStream* stream) {
  stream->WriteBytesSlot78(&field4, 2);
  stream->WriteBytesSlot78(&field6, 2);
  stream->WriteBytesSlot78(&categoryFlag8, 1);
  stream->WriteBytesSlot78(&fortLevelAttackerPenaltyCache9, 1);
  stream->WriteBytesSlot78(&fieldA, 2);
  stream->WriteBytesSlot78(&fieldC, 1);
  stream->WriteBytesSlot78(&ownerNationCodeE, 2);
  stream->WriteBytesSlot78(&tileIndex10, 2);

  TArmyStackUnitNode* node = head14;
  cursor18 = node;
  TUnit* unit = (node != 0) ? node->unit : 0;
  while (unit != 0) {
    stream->WriteBytesSlot78(&unit->field_1A, 2);
    node = cursor18;
    if (node != 0) {
      node = node->next;
      cursor18 = node;
      unit = (node != 0) ? node->unit : 0;
    } else {
      unit = 0;
    }
  }
  cursor18 = 0;
}

// FUNCTION: IMPERIALISM 0x004a7b20
void TArmyStack::AddUnitToChainHead(TUnit* unit) {
  TArmyStackUnitNode* node = new TArmyStackUnitNode();
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0xbeb);
  }
  node->unit = unit;
  node->next = head14;
  ++fieldA;
  head14 = node;
}

// FUNCTION: IMPERIALISM 0x004a7ba0
void TArmyStack::RemoveUnitFromChain(TUnit* unit) {
  TArmyStackUnitNode* prev = head14;
  if (prev != nullptr) {
    TArmyStackUnitNode* node = prev->next;
    if (prev->unit == unit) {
      head14 = node;
      delete prev;
      --fieldA;
      return;
    }
    for (; node != nullptr && node->unit != unit; node = node->next) {
      prev = node;
    }
    TArmyStackUnitNode* found = prev->next;
    if (found != nullptr) {
      prev->next = found->next;
      delete found;
      --fieldA;
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

// FUNCTION: IMPERIALISM 0x004a7e70
void TArmyStack::AccumulateWeightedMeterAndCountFromEligibleLinkedEntries(int* outWeightedSum,
                                                                          int* outCount,
                                                                          int counter) {
  // Blend-ratio pair, indexed by counter (0-3): primary weight favors the "weight class"
  // score early, secondary weight favors the "scaled factor" score in later rounds.
  static const int kRoundBlendWeightPrimary[4] = {100, 75, 50, 25};
  static const int kRoundBlendWeightSecondary[4] = {0, 25, 50, 75};
  if (counter > 3) {
    counter = 3;
  }
  *outWeightedSum = 0;
  *outCount = 0;

  for (TUnit* unit = this->ResetCursorAndGetHeadUnit(); unit != nullptr;
       unit = this->AdvanceCursorAndGetUnit()) {
    if (!IsUnitMeterEligible(unit)) {
      continue;
    }
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    int weightClass = g_anWeightClassByOrderType[unit->orderType];
    short scaledFactor = g_anScaledFactorByOrderType[unit->orderType];
    int percentEfficiency = static_cast<int>(g_afPercentEfficiencyByOrderType[unit->orderType]);
    *outWeightedSum += (((scaledFactor * kRoundBlendWeightSecondary[counter]) / 1000 +
                         (kRoundBlendWeightPrimary[counter] * weightClass) / 100) *
                        percentEfficiency * milUnit->field_34) /
                       500;
    *outCount += g_anCountWeightByOrderType[unit->orderType];
  }
}

// FUNCTION: IMPERIALISM 0x004a8040
void TArmyStack::ApplyRandomizedMeterDecayToEligibleLinkedEntries(int weightedSum, int count,
                                                                  int counter) {
  // Ground truth never reads weightedSum/count in this function (dead params kept for a
  // call-signature match with AccumulateWeightedMeterAndCountFromEligibleLinkedEntries).
  (void)weightedSum;
  (void)count;
  if (counter > 3) {
    counter = 3;
  }

  int activityScore = 0;
  for (TUnit* unit = this->ResetCursorAndGetHeadUnit(); unit != nullptr;
       unit = this->AdvanceCursorAndGetUnit()) {
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    if (milUnit->field_34 > 0 && (milUnit->field_3A & 2) == 0) {
      activityScore += (milUnit->field_34 > milUnit->field_3C / 2) ? 2 : 1;
    }
  }
  if (activityScore == 0) {
    return;
  }

  static const int kDecayScalePercentByRound[4] = {70, 80, 90, 90};
  for (TUnit* decayUnit = this->ResetCursorAndGetHeadUnit(); decayUnit != nullptr;
       decayUnit = this->AdvanceCursorAndGetUnit()) {
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(decayUnit);
    if (milUnit->field_34 > 0 && (milUnit->field_3A & 2) == 0) {
      int roll = static_cast<int>(rand());
      if ((milUnit->field_3A & 1) != 0) {
        roll = (kDecayScalePercentByRound[counter] * roll) / 100;
      }
      if (roll < milUnit->field_34) {
        milUnit->field_34 -= static_cast<short>(roll);
      } else {
        milUnit->field_34 = 0;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a82b0
void TArmyStack::ApplyMeterGrowthToEligibleUnits(bool boosted) {
  short growthAmount = boosted ? 0x23 : 0x14;
  TUnit* unit = this->ResetCursorAndGetHeadUnit();
  while (unit != nullptr) {
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    if (milUnit->field_34 > 0) {
      milUnit->field_38 = static_cast<short>(milUnit->field_38 + growthAmount);
      if (milUnit->field_38 > 0x190) {
        milUnit->field_38 = 0x190;
      }
    }
    unit = this->AdvanceCursorAndGetUnit();
  }
}
