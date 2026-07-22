// TAttackProvinceMission implementations.

#include <math.h>

#include "game/TAttackProvinceMission.h"
#include "game/CIterator.h"
#include "game/TAutoGreatPower.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TAttackProvinceMission, TArmyMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053d670
// TAttackProvinceMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053d710
// TAttackProvinceMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053d7c0
// TAttackProvinceMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0053d6f0
char TAttackProvinceMission::IsHospitalMission() const {
  return 0;
}

TAttackProvinceMission::TAttackProvinceMission() : TArmyMission(0xffff) {
  targetProvince30 = static_cast<short>(0xffff);
  amassingProvince32 = static_cast<short>(0xffff);
}

// FUNCTION: IMPERIALISM 0x0053d780
TAttackProvinceMission::TAttackProvinceMission(short targetProvince, short amassingProvince)
    : TArmyMission(0xffff) {
  targetProvince30 = targetProvince;
  amassingProvince32 = amassingProvince;
}

// FUNCTION: IMPERIALISM 0x0053d810
void TAttackProvinceMission::WriteTo(TStream* stream) {
  TArmyMission::WriteTo(stream);
  stream->WriteBytesSlot78(&targetProvince30, 2);
  stream->WriteBytesSlot78(&amassingProvince32, 2);
}

// FUNCTION: IMPERIALISM 0x0053d850
void TAttackProvinceMission::ReadFrom(TStream* stream) {
  TArmyMission::ReadFrom(stream);
  stream->ReadBytes(&targetProvince30, 2);
  stream->ReadBytes(&amassingProvince32, 2);
}

// FUNCTION: IMPERIALISM 0x0053d890
void TAttackProvinceMission::Free() {
  // The AI-only tail state block (mapNodeStateFlags/portZoneStateFlags/...) that
  // SetMapStateByteFlag970WithRuntimeGate touches lives only on TAutoGreatPower (RTTI
  // object size proves the other GreatPower subclasses have no room for it); missions
  // are an AI-only game mechanic, so g_apNationStates[nationId04] here is genuinely a
  // TAutoGreatPower.
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
  nationState->AssertValid();

  nationState->SetMapStateByteFlag970WithRuntimeGate(targetProvince30, 0);

  CIterator iter(orderListAt18);
  void* current = iter.Reset();
  while (iter.More()) {
    static_cast<TMilitaryUnit*>(current)->ownerMission40 = nullptr;
    current = iter.Advance();
  }

  orderListAt18->RemoveAll();
  if (orderListAt18 != nullptr) {
    orderListAt18->FreePayloadsAndDestroy();
  }
  orderListAt18 = nullptr;

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053d950
char TAttackProvinceMission::SmokeEmIfYouGotEm() {
  if (flag10 == 0) {
    float vector[5];
    float total = 0.0f;
    float weighted = 0.0f;
    ProjectEquipage(vector, GetPresentLocation(), 0);

    for (int i = 0; i < 5; ++i) {
      weighted += sqrtf(vector[i] * requiredEquipageByClass[i]);
      total += requiredEquipageByClass[i];
    }

    if (weighted / total > g_AttackProvinceMissionReadinessThreshold_0065A8F0) {
      CIterator eligibilityIter(orderListAt18);
      TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(eligibilityIter.Reset());
      while (eligibilityIter.More()) {
        if (static_cast<double>(unit->field_34) * g_ArmyMissionEligibleUnitStrengthScale_0065AA48 <
            g_Recompute_Nation_Order_LookupTable_0065AA20) {
          CIterator queueIter(orderListAt18);
          for (unit = static_cast<TMilitaryUnit*>(queueIter.Reset()); queueIter.More();
               unit = static_cast<TMilitaryUnit*>(queueIter.Advance())) {
            if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
              RejectConstituent(unit, 1);
            }
          }
          return 1;
        }
        unit = static_cast<TMilitaryUnit*>(eligibilityIter.Advance());
      }
      return 0;
    }
  }

  CIterator queueIter(orderListAt18);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(queueIter.Reset()); queueIter.More();
       unit = static_cast<TMilitaryUnit*>(queueIter.Advance())) {
    if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      RejectConstituent(unit, 1);
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053db60
char TAttackProvinceMission::TryResolveTargetTerrainClass() {
  presentLocation14 = static_cast<short>(0xffff);
  float bestScore = 0.0f;

  const Province& targetRecord = g_pGlobalMapState->cityScoreTable[targetProvince30];

  int candidateIndex = 0;
  const short* candidateCursor = targetRecord.adjacentRegionIds0A;
  for (; candidateIndex < targetRecord.adjacentRegionCount08; candidateIndex++, candidateCursor++) {
    short candidateTile = *candidateCursor;
    short tileOwnerNationCode =
        g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(candidateTile);
    if (tileOwnerNationCode == nationId04) {
      if (presentLocation14 != -1) {
        const Province& candidateRecord = g_pGlobalMapState->cityScoreTable[candidateTile];
        float candidateScore = static_cast<float>(candidateRecord.cityScoreValue);
        int matchCount = 0;
        int adjacentIndex = 0;
        const short* adjacentCursor = candidateRecord.adjacentRegionIds0A;
        while (adjacentIndex < candidateRecord.adjacentRegionCount08) {
          short adjOwnerNationCode =
              g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(*adjacentCursor);
          if (adjOwnerNationCode == nationId04) {
            matchCount++;
          }
          adjacentIndex++;
          adjacentCursor++;
        }
        if (candidateRecord.adjacentRegionCount08 > 0) {
          candidateScore = (static_cast<float>(matchCount) /
                                static_cast<float>(candidateRecord.adjacentRegionCount08) -
                            g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                           candidateScore;
        }
        candidateScore = candidateScore / g_fMissionScoreNormalizationDivisor;

        if (candidateScore <= bestScore) {
          continue;
        }
      }

      presentLocation14 = candidateTile;

      const Province& candidateRecord = g_pGlobalMapState->cityScoreTable[candidateTile];
      float candidateScore = static_cast<float>(candidateRecord.cityScoreValue);
      int matchCount = 0;
      int adjacentIndex = 0;
      const short* adjacentCursor = candidateRecord.adjacentRegionIds0A;
      while (adjacentIndex < candidateRecord.adjacentRegionCount08) {
        short adjOwnerNationCode =
            g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(*adjacentCursor);
        if (adjOwnerNationCode == nationId04) {
          matchCount++;
        }
        adjacentIndex++;
        adjacentCursor++;
      }
      if (candidateRecord.adjacentRegionCount08 > 0) {
        candidateScore = (static_cast<float>(matchCount) /
                              static_cast<float>(candidateRecord.adjacentRegionCount08) -
                          g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                         candidateScore;
      }
      bestScore = candidateScore / g_fMissionScoreNormalizationDivisor;
    }
  }

  return presentLocation14 != -1;
}

// FUNCTION: IMPERIALISM 0x0053de00
void TAttackProvinceMission::GiveOrders() {
  CIterator targetIter(orderListAt18);
  if (presentLocation14 == -1) {
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

    if (weighted / total > g_AttackProvinceMissionReadinessThreshold_0065A8F0) {
      if (g_pDiplomacyTurnStateManager->HasOutdatedWarRelationSlot48(
              nationId04, g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00)) {
        for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(targetIter.Reset());
             targetIter.More(); unit = static_cast<TMilitaryUnit*>(targetIter.Advance())) {
          if (unit->tileIndex06 == presentLocation14) {
            unit->SetOrders(kUnitOrderRedeploy, targetProvince30);
          }
        }
      } else if (!g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
                     nationId04,
                     g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00)) {
        signed char targetOwnerNation =
            g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00;
        if (g_apNationStates[nationId04]->diplomacyPolicyByNation[targetOwnerNation] != 0x131) {
          g_apNationStates[nationId04]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
              targetOwnerNation, 0x131);
        }
      }
    }
  }

  short resolvedTarget = presentLocation14;
  CIterator retargetIter(orderListAt18);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(retargetIter.Reset()); retargetIter.More();
       unit = static_cast<TMilitaryUnit*>(retargetIter.Advance())) {
    if (unit->tileIndex06 != resolvedTarget) {
      unit->SetOrders(kUnitOrderRedeploy, resolvedTarget);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0053e050
TMission* TAttackProvinceMission::GetReplacementSlot48() {
  if (presentLocation14 == -1) {
    TryResolveTargetTerrainClass();
  }
  if (presentLocation14 == -1) {
    return nullptr;
  }

  short targetOwnerNation = g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00;
  bool retarget = false;

  if (targetOwnerNation == pathMarker06) {
    if (amassingProvince32 != -1) {
      short amassingOwnerNation =
          g_pGlobalMapState->cityScoreTable[amassingProvince32].ownerNationCode00;
      if (nationId04 == amassingOwnerNation) {
        targetProvince30 = amassingProvince32;
        amassingProvince32 = static_cast<short>(0xffff);
        retarget = true;
        TryResolveTargetTerrainClass();
      }
    }
  } else if (targetOwnerNation == nationId04) {
    short tileOwnerNationCode =
        g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(presentLocation14);
    if (tileOwnerNationCode == pathMarker06) {
      retarget = true;
    } else {
      retarget = (TryResolveTargetTerrainClass() != 0);
    }
  }

  if (!retarget) {
    return nullptr;
  }

  if (g_pDiplomacyTurnStateManager->HasOutdatedWarRelationSlot48(pathMarker06, nationId04) &&
      !g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(pathMarker06, targetOwnerNation)) {
    return nullptr;
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x0053e180
void TAttackProvinceMission::SetStateByte8To2() {
  state08 = 2;
}

// Shared with TInvadeMission (COMDAT-folded body; TInvadeMission does not
// redeclare a `// FUNCTION:` marker for this address, see TInvadeMission.cpp).
// FUNCTION: IMPERIALISM 0x0053e1a0
void TAttackProvinceMission::CalculateImportance() {
  short targetProvince = targetProvince30;
  short missionNation = nationId04;
  int matchCount = 0;
  int adjacentIndex = 0;
  const Province& targetRecord = g_pGlobalMapState->cityScoreTable[targetProvince];
  float score = static_cast<float>(targetRecord.cityScoreValue);

  if (targetRecord.adjacentRegionCount08 > 0) {
    const short* adjacentCursor = targetRecord.adjacentRegionIds0A;
    do {
      short tileOwnerNationCode =
          g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(*adjacentCursor);
      if (tileOwnerNationCode == missionNation) {
        matchCount++;
      }
      adjacentIndex++;
      adjacentCursor++;
    } while (adjacentIndex < targetRecord.adjacentRegionCount08);
  }

  if (targetRecord.adjacentRegionCount08 > 0) {
    score =
        (static_cast<float>(matchCount) / static_cast<float>(targetRecord.adjacentRegionCount08) -
         g_Recompute_Nation_Order_LookupTable_0065A9E0) *
        score;
  }
  importanceScore0c = score / g_fMissionScoreNormalizationDivisor;
}

// Shared with TInvadeMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x0053e290
void TAttackProvinceMission::CalculateNeeds() {
  short unitOrderWeight = g_pGlobalMapState->GetProvinceUnitOrderWeight(targetProvince30);

  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  if (targetProvince30 >= 0 && targetProvince30 <= 0x17f) {
    for (TMilitaryUnit* unit =
             g_pGlobalMapState->cityScoreTable[targetProvince30].stationedUnitChain98;
         unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
      AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f,
                                                    static_cast<float>(unitOrderWeight));
    }
  }

  unsigned char fortLevel = g_pGlobalMapState->cityScoreTable[targetProvince30].fortLevel03;
  float total = 0.0f;
  for (int i = 0; i < 5; ++i) {
    total += vector[i];
  }

  float similarity = 0.0f;
  if (total != 0.0f) {
    const short* reference =
        &g_awTacticalCompositionReferenceProfiles_00697870[(fortLevel > 0) ? 15 : 0];
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

  float scale = g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel_0065A968
                    [g_pSimMgr->difficultyLevel][fortLevel] *
                similarity;
  const short* outputProfile =
      &g_awTacticalCompositionReferenceProfiles_00697870[(fortLevel > 0) ? 10 : 5];
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
  flag10 = 1;
  if (targetProvince30 != -1) {
    pathMarker06 =
        static_cast<short>(g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00);
  }
}

// FUNCTION: IMPERIALISM 0x0053e5b0
char TAttackProvinceMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  (void)zoneContext;
  return (missionType == kMissionTypeAttackProvince || missionType == kMissionTypeAmassProvince) &&
         key == static_cast<int>(targetProvince30);
}
