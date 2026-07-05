#include "game/TArmyStack.h"

#include "game/TMilitaryUnit.h"
#include "game/global_data_tables.h"

extern undefined4 GenerateThreadLocalRandom15(void);

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

TArmyStack::TArmyStack() {}

// SYNTHETIC: IMPERIALISM 0x004a7720
// TArmyStack::`scalar deleting destructor'
TArmyStack::~TArmyStack() {}

// FUNCTION: IMPERIALISM 0x004a77b0
void TArmyStack::ReadFrom(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a7960
void TArmyStack::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a7c20
void TArmyStack::Free() {}

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
      int roll = static_cast<int>(GenerateThreadLocalRandom15());
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
