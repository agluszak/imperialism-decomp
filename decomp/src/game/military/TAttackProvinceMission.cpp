// TAttackProvinceMission implementations.

#include <math.h>

#include "game/military/TAttackProvinceMission.h"
#include "game/ui_core/CIterator.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"

IMPLEMENT_SERIAL(TAttackProvinceMission, TArmyMission, 1)

// FUNCTION: IMPERIALISM 0x0053d6f0
bool TAttackProvinceMission::IsHospitalMission() const {
  return false;
}
// FUNCTION: IMPERIALISM 0x0053d780
TAttackProvinceMission::TAttackProvinceMission(short targetProvince, short amassingProvince)
    : TArmyMission(-1) {
  this->targetProvince = targetProvince;
  this->amassingProvince = amassingProvince;
}

// FUNCTION: IMPERIALISM 0x0053d810
void TAttackProvinceMission::WriteTo(TStream* stream) {
  TArmyMission::WriteTo(stream);
  stream->WriteBytes(&targetProvince, 2);
  stream->WriteBytes(&amassingProvince, 2);
}

// FUNCTION: IMPERIALISM 0x0053d850
void TAttackProvinceMission::ReadFrom(TStream* stream) {
  TArmyMission::ReadFrom(stream);
  stream->ReadBytes(&targetProvince, 2);
  stream->ReadBytes(&amassingProvince, 2);
}

// FUNCTION: IMPERIALISM 0x0053d890
void TAttackProvinceMission::Free() {
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId]);
  nationState->AssertValid();

  nationState->SetProvinceStatus(targetProvince, kMissionDesirabilityUnmarked);

  CIterator iter(orderList);
  void* current = iter.Reset();
  while (iter.More()) {
    static_cast<TMilitaryUnit*>(current)->ownerMission = nullptr;
    current = iter.Advance();
  }

  orderList->RemoveAll();
  if (orderList != nullptr) {
    orderList->FreePayloadsAndDestroy();
  }
  orderList = nullptr;

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053d950
bool TAttackProvinceMission::SmokeEmIfYouGotEm() {
  if (flag10 == 0) {
    float vector[5];
    float total = 0.0f;
    float weighted = 0.0f;
    ProjectEquipage(vector, GetPresentLocation(), 0);

    for (int i = 0; i < 5; ++i) {
      weighted += sqrtf(vector[i] * requiredEquipageByClass[i]);
      total += requiredEquipageByClass[i];
    }

    if (weighted / total > g_AttackProvinceMissionReadinessThreshold) {
      CIterator eligibilityIter(orderList);
      TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(eligibilityIter.Reset());
      while (eligibilityIter.More()) {
        if (static_cast<double>(unit->strength) * g_ArmyMissionEligibleUnitStrengthScale <
            g_Recompute_Nation_Order_LookupTable_0065AA20) {
          CIterator queueIter(orderList);
          for (unit = static_cast<TMilitaryUnit*>(queueIter.Reset()); queueIter.More();
               unit = static_cast<TMilitaryUnit*>(queueIter.Advance())) {
            if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
              RejectConstituent(unit, true);
            }
          }
          return true;
        }
        unit = static_cast<TMilitaryUnit*>(eligibilityIter.Advance());
      }
      return false;
    }
  }

  CIterator queueIter(orderList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(queueIter.Reset()); queueIter.More();
       unit = static_cast<TMilitaryUnit*>(queueIter.Advance())) {
    if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      RejectConstituent(unit, true);
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x0053db60
bool TAttackProvinceMission::TryResolveTargetTerrainClass() {
  presentLocation = -1;
  float bestScore = 0.0f;

  const Province& targetRecord = g_pGlobalMapState->cityScoreTable[targetProvince];

  int candidateIndex = 0;
  const short* candidateCursor = targetRecord.adjacentRegionIds;
  for (; candidateIndex < targetRecord.adjacentRegionCount; candidateIndex++, candidateCursor++) {
    short candidateTile = *candidateCursor;
    short tileOwnerNationCode =
        g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(candidateTile);
    if (tileOwnerNationCode == nationId) {
      if (presentLocation != -1) {
        const Province& candidateRecord = g_pGlobalMapState->cityScoreTable[candidateTile];
        float candidateScore = static_cast<float>(candidateRecord.cityScoreValue);
        int matchCount = 0;
        int adjacentIndex = 0;
        const short* adjacentCursor = candidateRecord.adjacentRegionIds;
        while (adjacentIndex < candidateRecord.adjacentRegionCount) {
          short adjOwnerNationCode =
              g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(*adjacentCursor);
          if (adjOwnerNationCode == nationId) {
            matchCount++;
          }
          adjacentIndex++;
          adjacentCursor++;
        }
        if (candidateRecord.adjacentRegionCount > 0) {
          candidateScore = (static_cast<float>(matchCount) /
                                static_cast<float>(candidateRecord.adjacentRegionCount) -
                            g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                           candidateScore;
        }
        candidateScore = candidateScore / g_fMissionScoreNormalizationDivisor;

        if (candidateScore <= bestScore) {
          continue;
        }
      }

      presentLocation = candidateTile;

      const Province& candidateRecord = g_pGlobalMapState->cityScoreTable[candidateTile];
      float candidateScore = static_cast<float>(candidateRecord.cityScoreValue);
      int matchCount = 0;
      int adjacentIndex = 0;
      const short* adjacentCursor = candidateRecord.adjacentRegionIds;
      while (adjacentIndex < candidateRecord.adjacentRegionCount) {
        short adjOwnerNationCode =
            g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(*adjacentCursor);
        if (adjOwnerNationCode == nationId) {
          matchCount++;
        }
        adjacentIndex++;
        adjacentCursor++;
      }
      if (candidateRecord.adjacentRegionCount > 0) {
        candidateScore = (static_cast<float>(matchCount) /
                              static_cast<float>(candidateRecord.adjacentRegionCount) -
                          g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                         candidateScore;
      }
      bestScore = candidateScore / g_fMissionScoreNormalizationDivisor;
    }
  }

  return presentLocation != -1;
}

// FUNCTION: IMPERIALISM 0x0053de00
void TAttackProvinceMission::GiveOrders() {
  CIterator targetIter(orderList);
  if (presentLocation == -1) {
    TryResolveTargetTerrainClass();
  }

  {
    float vector[5];
    float total = 0.0f;
    float weighted = 0.0f;
    ProjectEquipage(vector, GetPresentLocation(), 0);

    float* projectedCursor = vector;
    float* weightCursor = requiredEquipageByClass;
    int remainingWeights = 5;
    do {
      weighted += sqrtf(*weightCursor * *projectedCursor);
      projectedCursor++;
      weightCursor++;
      total += weightCursor[-1];
      remainingWeights--;
    } while (remainingWeights != 0);

    if (weighted / total > g_AttackProvinceMissionReadinessThreshold) {
      if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
              nationId, g_pGlobalMapState->cityScoreTable[targetProvince].ownerNationCode)) {
        for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(targetIter.Reset());
             targetIter.More(); unit = static_cast<TMilitaryUnit*>(targetIter.Advance())) {
          if (unit->tileIndex == presentLocation) {
            unit->SetOrders(kUnitOrderRedeploy, targetProvince);
          }
        }
      } else if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(
                     nationId, g_pGlobalMapState->cityScoreTable[targetProvince].ownerNationCode)) {
        signed char targetOwnerNation =
            g_pGlobalMapState->cityScoreTable[targetProvince].ownerNationCode;
        if (g_apNationStates[nationId]->diplomacyPolicyByNation[targetOwnerNation] !=
            kDiplomacyProposalDeclareWar) {
          g_apNationStates[nationId]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
              targetOwnerNation, kDiplomacyProposalDeclareWar);
        }
      }
    }
  }

  short resolvedTarget = presentLocation;
  CIterator retargetIter(orderList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(retargetIter.Reset()); retargetIter.More();
       unit = static_cast<TMilitaryUnit*>(retargetIter.Advance())) {
    if (unit->tileIndex != resolvedTarget) {
      unit->SetOrders(kUnitOrderRedeploy, resolvedTarget);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0053e050
TMission* TAttackProvinceMission::GetReplacement() {
  if (presentLocation == -1) {
    TryResolveTargetTerrainClass();
  }
  if (presentLocation == -1) {
    return nullptr;
  }

  short targetOwnerNation = g_pGlobalMapState->cityScoreTable[targetProvince].ownerNationCode;
  bool retarget = false;

  if (targetOwnerNation == pathMarker) {
    if (amassingProvince != -1) {
      short amassingOwnerNation =
          g_pGlobalMapState->cityScoreTable[amassingProvince].ownerNationCode;
      if (nationId == amassingOwnerNation) {
        targetProvince = amassingProvince;
        amassingProvince = -1;
        retarget = true;
        TryResolveTargetTerrainClass();
      }
    }
  } else if (targetOwnerNation == nationId) {
    short tileOwnerNationCode =
        g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(presentLocation);
    if (tileOwnerNationCode == pathMarker) {
      retarget = true;
    } else {
      retarget = (TryResolveTargetTerrainClass());
    }
  }

  if (!retarget) {
    return nullptr;
  }

  if (g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(nationId) &&
      !g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, targetOwnerNation)) {
    return nullptr;
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x0053e180
void TAttackProvinceMission::SetStateByte8To2() {
  state08 = 2;
}

// FUNCTION: IMPERIALISM 0x0053e1a0
void TAttackProvinceMission::CalculateImportance() {
  short targetProvince = this->targetProvince;
  short missionNation = nationId;
  int matchCount = 0;
  int adjacentIndex = 0;
  const Province& targetRecord = g_pGlobalMapState->cityScoreTable[targetProvince];
  float score = static_cast<float>(targetRecord.cityScoreValue);

  if (targetRecord.adjacentRegionCount > 0) {
    const short* adjacentCursor = targetRecord.adjacentRegionIds;
    do {
      short tileOwnerNationCode =
          g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(*adjacentCursor);
      if (tileOwnerNationCode == missionNation) {
        matchCount++;
      }
      adjacentIndex++;
      adjacentCursor++;
    } while (adjacentIndex < targetRecord.adjacentRegionCount);
  }

  if (targetRecord.adjacentRegionCount > 0) {
    score = (static_cast<float>(matchCount) / static_cast<float>(targetRecord.adjacentRegionCount) -
             g_Recompute_Nation_Order_LookupTable_0065A9E0) *
            score;
  }
  importanceScore = score / g_fMissionScoreNormalizationDivisor;
}

// Shared with TInvadeMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x0053e290
void TAttackProvinceMission::CalculateNeeds() {
  short unitOrderWeight = g_pGlobalMapState->GetProvinceUnitOrderWeight(targetProvince);

  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  if (targetProvince >= 0 && targetProvince <= 0x17f) {
    for (TMilitaryUnit* unit = g_pGlobalMapState->cityScoreTable[targetProvince].stationedUnitChain;
         unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
      AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f,
                                                    static_cast<float>(unitOrderWeight));
    }
  }

  signed char fortLevel = g_pGlobalMapState->cityScoreTable[targetProvince].fortLevel;
  float total = 0.0f;
  for (int i = 0; i < 5; ++i) {
    total += vector[i];
  }

  float similarity = 0.0f;
  if (total != 0.0f) {
    const short* reference = &g_awTacticalCompositionReferenceProfiles[(fortLevel > 0) ? 15 : 0];
    float divergence = 0.0f;
    for (int referenceIndex = 0; referenceIndex < 5; ++referenceIndex) {
      float delta =
          vector[referenceIndex] / total - static_cast<float>(reference[referenceIndex]) *
                                               g_Recompute_Nation_Order_LookupTable_0065A9F8;
      if (delta <= 0.0f) {
        delta = -delta;
      }
      divergence += delta;
    }
    similarity = total * (g_Recompute_Nation_Order_LookupTable_0065AA08 -
                          divergence * g_Recompute_Nation_Order_LookupTable_0065AA00);
  }
  if (similarity == 0.0f) {
    similarity = 1.0f;
  }

  float scale =
      g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel[g_pSimMgr->difficultyLevel]
                                                                  [fortLevel] *
      similarity;
  const short* outputProfile = &g_awTacticalCompositionReferenceProfiles[(fortLevel > 0) ? 10 : 5];
  for (int outputIndex = 0; outputIndex < 5; ++outputIndex) {
    requiredEquipageByClass[outputIndex] = static_cast<float>(outputProfile[outputIndex]) * scale *
                                           g_Recompute_Nation_Order_LookupTable_0065A9F8;
  }
}

// Shared with TInvadeMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x0053e500
float TAttackProvinceMission::FitnessOf(TMilitaryUnit* candidateUnit, float* referenceVector) {
  if (referenceVector[2] > 0.0f) {
    if (candidateUnit->GetAttribute(2) < 10) {
      return -1000.0f;
    }
  }
  return TArmyMission::FitnessOf(candidateUnit, referenceVector);
}

// FUNCTION: IMPERIALISM 0x0053e570
void TAttackProvinceMission::Initialize() {
  marker11 = 1;
  if (targetProvince != -1) {
    pathMarker =
        static_cast<short>(g_pGlobalMapState->cityScoreTable[targetProvince].ownerNationCode);
  }
}

// FUNCTION: IMPERIALISM 0x0053e5b0
bool TAttackProvinceMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  (void)zoneContext;
  return (missionType == kMissionTypeAttackProvince || missionType == kMissionTypeAmassProvince) &&
         key == static_cast<int>(targetProvince);
}
