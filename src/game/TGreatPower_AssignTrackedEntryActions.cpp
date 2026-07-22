#include "game/TGreatPower_internal.h"

#include "game/CIterator.h"
#include "game/TAutoGreatPower.h"
#include "game/TGreatPower.h"
#include "game/TMilitaryUnit.h"
#include "game/TMission.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/global_data_tables.h"

namespace {

// Same shape as CompareMissionOrderEntriesByPriorityScore's per-side computation
// (TMission.cpp:276), just against the 0x6545d0/d8 address instances of the same
// conceptual constants.
inline float ComputeMissionRemainingPriorityScore(TMission* mission) {
  float diff = g_MissionScoreOneConstant_006545d8 - mission->GetWeightedSatisfaction();
  return (diff >= g_MissionDefaultScore_006545d0) ? diff * mission->importanceScore0c
                                                  : diff / mission->importanceScore0c;
}

} // namespace

// FUNCTION: IMPERIALISM 0x004eb8b0
void TAutoGreatPower::AssignTrackedEntryActionsByProfileToOrdersOrUnits(int unused) {
  (void)unused;
  {
    CIterator resetIter(missionQueue);
    for (TMission* entry = static_cast<TMission*>(resetIter.Reset()); resetIter.More();
         entry = static_cast<TMission*>(resetIter.Advance())) {
      entry->SmokeEmIfYouGotEm();
    }
  }

  int weights[9];
  float weightFractions[9];
  int total;
  for (;;) {
    TMission* bestNavy = nullptr;
    {
      CIterator navyIter(missionQueue);
      for (TMission* entry = static_cast<TMission*>(navyIter.Reset()); navyIter.More();
           entry = static_cast<TMission*>(navyIter.Advance())) {
        TMission* candidate = entry->GetNavyMission();
        if (candidate == nullptr || candidate->flag10 != 0) {
          continue;
        }
        if (bestNavy == nullptr) {
          bestNavy = candidate;
          continue;
        }
        float candidateScore = ComputeMissionRemainingPriorityScore(candidate);
        float bestScore = ComputeMissionRemainingPriorityScore(bestNavy);
        if (candidateScore > g_MissionScoreZeroThreshold_006545f0 &&
            static_cast<char>(candidate->state08) < static_cast<char>(bestNavy->state08)) {
          bestNavy = candidate;
          continue;
        }
        if (bestScore <= g_MissionScoreZeroThreshold_006545f0 ||
            static_cast<char>(candidate->state08) <= static_cast<char>(bestNavy->state08)) {
          float bestScore2 = ComputeMissionRemainingPriorityScore(bestNavy);
          float candidateScore2 = ComputeMissionRemainingPriorityScore(candidate);
          if (bestScore2 < candidateScore2) {
            bestNavy = candidate;
          }
        }
      }
    }

    if (bestNavy != nullptr) {
      for (int navyZeroIdx = 0; navyZeroIdx < 9; ++navyZeroIdx) {
        weights[navyZeroIdx] = 0;
      }
      total = bestNavy->AccumulateLack(weights, 0);
      for (int navyWeightIdx = 0; navyWeightIdx < 9; ++navyWeightIdx) {
        weightFractions[navyWeightIdx] =
            static_cast<float>(weights[navyWeightIdx]) / static_cast<float>(total);
      }

      TShip* bestShip = nullptr;
      float bestShipScore = 0.0f;
      for (TShip* shipNode = GetNavyPrimaryOrderListHead(); shipNode != nullptr;
           shipNode = shipNode->nextOlder24) {
        if (shipNode->ownerNationSlot14 == nationSlot && shipNode->missionBacklink2c == nullptr) {
          float score = bestNavy->FitnessOf(shipNode, weightFractions);
          if (bestShip == nullptr || bestShipScore < score) {
            bestShipScore = score;
            bestShip = shipNode;
          }
        }
      }

      if (bestShip != nullptr) {
        bestNavy->AcceptReenforcement(bestShip, 1);
        continue;
      }
    }

    TMission* bestArmy = nullptr;
    TMission* eligibleRunnerUp = nullptr;
    {
      CIterator armyIter(missionQueue);
      for (TMission* entry = static_cast<TMission*>(armyIter.Reset()); armyIter.More();
           entry = static_cast<TMission*>(armyIter.Advance())) {
        TMission* candidate = entry->GetArmyMission();
        if (candidate == nullptr || candidate->flag10 != 0) {
          continue;
        }
        float candidateScore = ComputeMissionRemainingPriorityScore(candidate);
        if (eligibleRunnerUp == nullptr && candidateScore > g_MissionScoreZeroThreshold_006545f0 &&
            (candidate->marker11 & 1) != 0) {
          eligibleRunnerUp = candidate;
        }
        if (bestArmy == nullptr) {
          bestArmy = candidate;
          continue;
        }
        float bestArmyScore = ComputeMissionRemainingPriorityScore(bestArmy);
        if (candidateScore > g_MissionScoreZeroThreshold_006545f0 &&
            static_cast<char>(bestArmy->state08) > static_cast<char>(candidate->state08)) {
          bestArmy = candidate;
          continue;
        }
        if (bestArmyScore > g_MissionScoreZeroThreshold_006545f0 &&
            static_cast<char>(bestArmy->state08) < static_cast<char>(candidate->state08)) {
          continue;
        }
        if (bestArmyScore < candidateScore) {
          bestArmy = candidate;
        }
      }
    }

    if (bestArmy == nullptr) {
      return;
    }
    if (eligibleRunnerUp != nullptr &&
        static_cast<char>(eligibleRunnerUp->state08) <= static_cast<char>(bestArmy->state08) &&
        (bestArmy->marker11 & 1) == 0) {
      float bestArmyRatio = bestArmy->importanceScore0c / bestArmy->IndustrialCostOfNeeds();
      float runnerUpRatio =
          eligibleRunnerUp->importanceScore0c / eligibleRunnerUp->IndustrialCostOfNeeds();
      if (bestArmyRatio < runnerUpRatio) {
        bestArmy = eligibleRunnerUp;
      }
    }

    for (int armyZeroIdx = 0; armyZeroIdx < 9; ++armyZeroIdx) {
      weights[armyZeroIdx] = 0;
    }
    bestArmy->AccumulateLack(weights, 0);
    total = 0;
    for (int armyClampIdx = 0; armyClampIdx < 9; ++armyClampIdx) {
      if (weights[armyClampIdx] < 0) {
        weights[armyClampIdx] = 0;
      }
      total += weights[armyClampIdx];
    }
    if (total == 0) {
      total = 1;
    }
    for (int armyNormIdx = 0; armyNormIdx < 9; ++armyNormIdx) {
      weightFractions[armyNormIdx] =
          static_cast<float>(weights[armyNormIdx]) / static_cast<float>(total);
    }

    TMilitaryUnit* bestUnit = nullptr;
    float bestUnitScore = 0.0f;
    {
      CIterator unitIter(militaryUnitList44);
      for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
           unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
        if (unit->ownerMission40 == nullptr) {
          float score = bestArmy->FitnessOf(unit, weightFractions);
          if (bestUnit == nullptr || bestUnitScore < score) {
            bestUnitScore = score;
            bestUnit = unit;
          }
        }
      }
    }

    if (bestUnit == nullptr) {
      return;
    }
    bestArmy->AdoptUnitSlot80(bestUnit, 1);
  }
}
