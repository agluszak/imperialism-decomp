#include "game/TGreatPower_internal.h"
#include "game/navy_order.h"

#include "game/ui_core/CIterator.h"
#include "game/military/TArmyMission.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TSortedList.h"
#include "game/globals/prelude.h"
#include "game/globals/nation_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"

int SumMilitaryUnitPowerWeights(TSortedList* unitList) {
  int powerSum = 0;
  CIterator unitIter(unitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    powerSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }
  return powerSum;
}

float SumAlliedArmyScoreFactors(int targetNation) {
  float allySum = 0.0f;
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation) > 0) {
    do {
      int allyNation =
          g_pDiplomacyTurnStateManager->GetNthAlliedMajorNationSlot90(allyIndex, targetNation);
      allySum = allySum + g_apNationStates[allyNation]->GetScoreFactorSlot23C();
      ++allyIndex;
    } while (allyIndex <
             g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation));
  }
  return allySum;
}

float SumAlliedNavyScoreFactors(int targetNation) {
  float allySum = 0.0f;
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation) > 0) {
    do {
      int allyNation =
          g_pDiplomacyTurnStateManager->GetNthAlliedMajorNationSlot90(allyIndex, targetNation);
      allySum = allySum + g_apNationStates[allyNation]->GetScoreFactorSlot240();
      ++allyIndex;
    } while (allyIndex <
             g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation));
  }
  return allySum;
}

short* GetRelationStandingRowForNation(short nationSlot) {
  return &g_pDiplomacyTurnStateManager
              ->relationStandingScoreMatrix79c[nationSlot * kNationSlotCount];
}

int GetClampedQuarterYearTerm(void) {
  TSimMgr* localization = g_pSimMgr;
  int yearTerm = static_cast<short>(localization->economicTurn / 4);
  if (yearTerm >= 0x3c) {
    yearTerm = 0x3c;
  }
  return yearTerm;
}

float TruncatedScoreFactorToFloat(float score) {
  int truncated = static_cast<int>(score);
  if (truncated <= 1) {
    truncated = 1;
  }
  return static_cast<float>(truncated);
}

// Recomputes per-nation navy/army order-priority metrics from queued map-order
// distributions. Runs in game-flow state 0x15, before the per-nation +0x2B8/+0x108
// passes. For each eligible nation (g_pSimMgr->IsNationSlotEligibleForEventProcessing):
//  1. Blends the 4-category TShip navy-order contribution percentages for that
//     nation's ships into a queue-demand divergence score (normalized against
//     g_Populate_Beachhead_Mission_LookupTable_00697958), cached in both
//     g_afNationOrderQueueDivergence_006a3a88 and its mirror at 006a3ac0.
//  2. Accumulates a per-unit-type weighted vector over the nation's militaryUnitList44
//     entries with a nonzero GetCategory ("mobile" units), normalized
//     against two different slices of g_awTacticalCompositionReferenceProfiles_00697870
//     -- one cached as the "mobile unit score" (006a3b88), the other as a divergence
//     figure (006a3ae0).
//  3. Continues accumulating the same vector over the remaining ("static",
//     GetCategory == 0) units without resetting it, then re-normalizes
//     the combined vector the same way into g_afNationCombinedUnitDivergence_006a3b50.
//  4. Scales the mobile-unit score by the nation's military-power-to-navy-order-cost
//     ratio (capped at 1.0) into g_afNationWeightedMilitaryOrderScore_006a3b20.
// A second pass lets each eligible nation consume the completed cross-nation cache set.
// FUNCTION: IMPERIALISM 0x0053fe30
void RecomputeNationOrderPriorityMetrics() {
  for (short nationIdx = 0; nationIdx < 7; ++nationIdx) {
    if (!g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationIdx)) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[nationIdx];

    float categoryVector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
      if (ship->nation == nationIdx) {
        ship->GetMaxStrength();
        categoryVector[0] +=
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0));
        categoryVector[1] +=
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1));
        categoryVector[2] +=
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2));
        categoryVector[3] +=
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3));
      }
    }
    float queueSum = categoryVector[0] + categoryVector[1] + categoryVector[2] + categoryVector[3];
    float queueDivergence = 0.0f;
    if (queueSum != 0.0f) {
      float diffSum = 0.0f;
      for (int i = 0; i < 4; ++i) {
        float diff =
            categoryVector[i] / queueSum -
            static_cast<float>(g_Populate_Beachhead_Mission_LookupTable_00697958[i]) * 0.01f;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      queueDivergence = queueSum * (1.0f - diffSum * 0.5f);
    }
    g_afNationOrderQueueDivergence_006a3a88[nationIdx] = queueDivergence;
    g_afNationOrderQueueDivergenceMirror_006a3ac0[nationIdx] = queueDivergence;

    float unitVector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    CIterator mobileIter(nation->militaryUnitList44);
    for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(mobileIter.Reset()); mobileIter.More();
         unit = static_cast<TMilitaryUnit*>(mobileIter.Advance())) {
      if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
        AccumulateUnitOrderPriorityVectorContribution(unit, unitVector, 1.0f, 0.33f);
      }
    }

    float mobileSum = unitVector[0] + unitVector[1] + unitVector[2] + unitVector[3] + unitVector[4];
    float mobileUnitScore = 0.0f;
    if (mobileSum != 0.0f) {
      float diffSum = 0.0f;
      for (int i = 0; i < 5; ++i) {
        float diff =
            unitVector[i] / mobileSum -
            static_cast<float>(g_awTacticalCompositionReferenceProfiles_00697870[5 + i]) * 0.01f;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      mobileUnitScore = mobileSum * (1.0f - diffSum * 0.5f);
    }
    g_afNationMobileUnitScore_006a3b88[nationIdx] = mobileUnitScore;

    float mobileSum2 =
        unitVector[0] + unitVector[1] + unitVector[2] + unitVector[3] + unitVector[4];
    float mobileUnitDivergence = 0.0f;
    if (mobileSum2 != 0.0f) {
      float diffSum = 0.0f;
      for (int i = 0; i < 5; ++i) {
        float diff =
            unitVector[i] / mobileSum2 -
            static_cast<float>(g_awTacticalCompositionReferenceProfiles_00697870[i]) * 0.01f;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      mobileUnitDivergence = mobileSum2 * (1.0f - diffSum * 0.5f);
    }
    g_afNationMobileUnitDivergence_006a3ae0[nationIdx] = mobileUnitDivergence;

    CIterator staticIter(nation->militaryUnitList44);
    for (TMilitaryUnit* staticUnit = static_cast<TMilitaryUnit*>(staticIter.Reset());
         staticIter.More(); staticUnit = static_cast<TMilitaryUnit*>(staticIter.Advance())) {
      if (staticUnit->GetCategory() == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
        AccumulateUnitOrderPriorityVectorContribution(staticUnit, unitVector, 1.0f, 0.33f);
      }
    }

    float combinedSum =
        unitVector[0] + unitVector[1] + unitVector[2] + unitVector[3] + unitVector[4];
    float combinedUnitDivergence = 0.0f;
    if (combinedSum != 0.0f) {
      float diffSum = 0.0f;
      for (int i = 0; i < 5; ++i) {
        float diff =
            unitVector[i] / combinedSum -
            static_cast<float>(g_awTacticalCompositionReferenceProfiles_00697870[i]) * 0.01f;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      combinedUnitDivergence = combinedSum * (1.0f - diffSum * 0.5f);
    }
    g_afNationCombinedUnitDivergence_006a3b50[nationIdx] = combinedUnitDivergence;

    int militaryPower = nation->ComputeSelectedMilitaryPowerScore();
    int navyOrderIndustrySum = nation->SumNavyOrderPriorityForNationSlot86();
    float powerRatio = 1.0f;
    if (static_cast<float>(militaryPower) < static_cast<float>(navyOrderIndustrySum)) {
      powerRatio = static_cast<float>(militaryPower) / static_cast<float>(navyOrderIndustrySum);
    }
    g_afNationWeightedMilitaryOrderScore_006a3b20[nationIdx] =
        g_afNationMobileUnitScore_006a3b88[nationIdx] * powerRatio;
  }

  for (short finalNationIdx = 0; finalNationIdx < 7; ++finalNationIdx) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(finalNationIdx)) {
      g_apNationStates[finalNationIdx]->RecomputeAiExpansionAndMissionPressureScores();
    }
  }
}
