#include "game/nation/TGreatPower_internal.h"
#include "game/navy_order.h"

#include "game/ui_core/CIterator.h"
#include "game/military/TArmyMission.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TSortedList.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"

// FUNCTION: IMPERIALISM 0x0053fe30
void RecomputeNationOrderPriorityMetrics() {
  for (short nationIdx = 0; nationIdx < 7; ++nationIdx) {
    if (!g_pSimMgr->ReallyInTheGame(nationIdx)) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[nationIdx];

    float categoryVector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
      if (ship->nation == nationIdx) {
        int strengthRatio = ship->strength / ship->GetMaxStrength();
        categoryVector[0] +=
            strengthRatio *
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0));
        categoryVector[1] +=
            strengthRatio *
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1));
        categoryVector[2] +=
            strengthRatio *
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
        float diff = categoryVector[i] / queueSum -
                     static_cast<float>(g_Populate_Beachhead_Mission_LookupTable[i]) *
                         g_Recompute_Nation_Order_LookupTable_0065A9F8;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      queueDivergence = queueSum * (1.0f - diffSum * 0.5f);
    }
    g_afNationOrderQueueDivergence[nationIdx] = queueDivergence;
    g_afNationOrderQueueDivergenceMirror[nationIdx] = queueDivergence;

    float unitVector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    CIterator mobileIter(nation->militaryUnitList);
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
        float diff = unitVector[i] / mobileSum -
                     static_cast<float>(g_awTacticalCompositionReferenceProfiles[5 + i]) *
                         g_Recompute_Nation_Order_LookupTable_0065A9F8;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      mobileUnitScore = mobileSum * (1.0f - diffSum * 0.5f);
    }
    g_afNationMobileUnitScore[nationIdx] = mobileUnitScore;

    float mobileSum2 =
        unitVector[0] + unitVector[1] + unitVector[2] + unitVector[3] + unitVector[4];
    float mobileUnitDivergence = 0.0f;
    if (mobileSum2 != 0.0f) {
      float diffSum = 0.0f;
      for (int i = 0; i < 5; ++i) {
        float diff = unitVector[i] / mobileSum2 -
                     static_cast<float>(g_awTacticalCompositionReferenceProfiles[i]) *
                         g_Recompute_Nation_Order_LookupTable_0065A9F8;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      mobileUnitDivergence = mobileSum2 * (1.0f - diffSum * 0.5f);
    }
    g_afNationMobileUnitDivergence[nationIdx] = mobileUnitDivergence;

    CIterator staticIter(nation->militaryUnitList);
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
        float diff = unitVector[i] / combinedSum -
                     static_cast<float>(g_awTacticalCompositionReferenceProfiles[i]) *
                         g_Recompute_Nation_Order_LookupTable_0065A9F8;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        diffSum += diff;
      }
      combinedUnitDivergence = combinedSum * (1.0f - diffSum * 0.5f);
    }
    g_afNationCombinedUnitDivergence[nationIdx] = combinedUnitDivergence;

    int militaryPower = nation->ComputeSelectedMilitaryPowerScore();
    int navyOrderIndustrySum = nation->GetArmsInNavy();
    float powerRatio = 1.0f;
    if (static_cast<float>(navyOrderIndustrySum) < static_cast<float>(militaryPower)) {
      powerRatio = static_cast<float>(navyOrderIndustrySum) / static_cast<float>(militaryPower);
    }
    g_afNationWeightedMilitaryOrderScore[nationIdx] =
        g_afNationMobileUnitScore[nationIdx] * powerRatio;
  }

  for (short finalNationIdx = 0; finalNationIdx < 7; ++finalNationIdx) {
    if (g_pSimMgr->ReallyInTheGame(finalNationIdx)) {
      g_apNationStates[finalNationIdx]->RecomputeAiExpansionAndMissionPressureScores();
    }
  }
}
