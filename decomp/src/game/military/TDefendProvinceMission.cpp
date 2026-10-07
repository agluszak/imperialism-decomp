#include "game/military/TDefendProvinceMission.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/navy/TNavyMgr.h"
#include "game/TList.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/tactical_ui/TTechMgr.h"

IMPLEMENT_SERIAL(TDefendProvinceMission, TArmyMission, 1)

#include "game/ui_core/CIterator.h"

// FUNCTION: IMPERIALISM 0x00535770
void TDefendProvinceMission::GiveOrders() {
  PropagateTargetTileToLinkedUnitsIfDifferent(presentLocation);
}

// FUNCTION: IMPERIALISM 0x00535790
bool TDefendProvinceMission::IsHospitalMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x005357b0
bool TDefendProvinceMission::IsANoBrainer() const {
  return true;
}

// Global factory function
// FUNCTION: IMPERIALISM 0x00535800
TDefendProvinceMission::~TDefendProvinceMission() {}

// FUNCTION: IMPERIALISM 0x005359e0
bool IsMapTileCompatibleWithCurrentTerrainOrActionContext(int tileIndex) {
  Province& record = g_pGlobalMapState->cityScoreTable[tileIndex];
  signed char primaryOwner = record.ownerNationCode;
  if (g_apTerrainTypeDescriptorTable[primaryOwner]->GetCapitolProvince() == tileIndex) {
    return true;
  }

  for (int i = record.adjacentRegionCount - 1; i >= 0; --i) {
    short neighborTile = record.adjacentRegionIds[i];
    signed char neighborOwner = g_pGlobalMapState->cityScoreTable[neighborTile].ownerNationCode;
    if (neighborOwner < 7 && neighborOwner != primaryOwner) {
      return true;
    }
  }

  TZone* zone = g_pMapActionContextListHead;
  if (zone == NULL) {
    return false;
  }
  unsigned char excludeOwnerMask = (1 << (primaryOwner & 0x1f)) ^ 0x7f;
  while ((zone->nationKeyMask & excludeOwnerMask) == 0 ||
         !zone->ContainsCityStatePointerInZoneArrayByCityIndex(tileIndex)) {
    zone = zone->prev18;
    if (zone == NULL) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x0053c950
void TDefendProvinceMission::PropagateTargetTileToLinkedUnitsIfDifferent(short newTile) {
  CIterator iter(orderList);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->tileIndex != newTile) {
      unit->SetOrders(kUnitOrderRedeploy, newTile);
    }
  }
}

namespace {

inline float NormalizeFiveComponentPriorityVector(const float* vector, float sum,
                                                  const short* lookupTable) {
  if (sum == 0.0) {
    return 0.0f;
  }

  float accum = 0.0f;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    float diff =
        vector[componentIndex] / sum - static_cast<short>(lookupTable[componentIndex]) * 0.01;
    if (diff <= 0.0) {
      diff = -diff;
    }
    accum += diff;
  }

  return sum * (1.0 - accum * 0.5);
}

} // namespace

// FUNCTION: IMPERIALISM 0x0053e6e0
float TDefendProvinceMission::ComputeCrossNationSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  int remainingBudgetByNation[kMajorNationCount];

  float unitOrderWeight = static_cast<float>(
      g_pGlobalMapState->GetProvinceUnitOrderWeight(static_cast<short>(nodeContext)));

  Province* sourceRecord = &g_pGlobalMapState->cityScoreTable[nodeContext];
  int sourceNation = sourceRecord->ownerNationCode;

  for (int nationIndex = 0; nationIndex < kMajorNationCount; ++nationIndex) {
    short navyBudget =
        g_pNavyOrderManager->GetInvasionCapacity(static_cast<short>(nationIndex), sourceRecord, 0);
    remainingBudgetByNation[nationIndex] = static_cast<int>(navyBudget);
  }

  for (int regionIndex = 0; regionIndex < kProvinceCount; ++regionIndex) {
    short candidateNation =
        static_cast<short>(g_pGlobalMapState->cityScoreTable[regionIndex].ownerNationCode);
    if (candidateNation < kMajorNationCount) {
      int candidateNationIndex = candidateNation;
      if (candidateNationIndex != sourceNation &&
          g_pDiplomacyTurnStateManager->AreAtWar(candidateNation, sourceNation)) {
        if (g_pGlobalMapState->IsProvinceAdjacentTo(nodeContext, regionIndex)) {
          short checkedRegion = regionIndex;
          TMilitaryUnit* unit = 0;
          if (checkedRegion >= 0 && checkedRegion < kProvinceCount) {
            unit = g_pGlobalMapState->cityScoreTable[checkedRegion].stationedUnitChain;
          }
          for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
            if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
              AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f, unitOrderWeight);
            }
          }
        } else if (remainingBudgetByNation[candidateNationIndex] > 0 &&
                   g_pGlobalMapState->HasPortInProvince(regionIndex)) {
          short checkedRegion = regionIndex;
          TMilitaryUnit* unit = 0;
          if (checkedRegion >= 0 && checkedRegion < kProvinceCount) {
            unit = g_pGlobalMapState->cityScoreTable[checkedRegion].stationedUnitChain;
          }
          for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
            short costPoints = unit->GetArmsCarried();
            if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
              int remainingBudget = remainingBudgetByNation[candidateNationIndex];
              if (costPoints < remainingBudget) {
                AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f, unitOrderWeight);
                remainingBudgetByNation[candidateNationIndex] = remainingBudget - costPoints;
              }
            }
          }
        }
      }
    }
  }

  float sum = 0.0f;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    sum += vector[componentIndex];
  }

  int lookupGroup = (sourceRecord->fortLevel > 0) ? 2 : 1;
  const short* lookupTable = g_awTacticalCompositionReferenceProfiles + lookupGroup * 5;
  return NormalizeFiveComponentPriorityVector(vector, sum, lookupTable);
}

// FUNCTION: IMPERIALISM 0x0053ea70
float TDefendProvinceMission::ComputeLocalSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};

  short unitOrderWeight =
      g_pGlobalMapState->GetProvinceUnitOrderWeight(static_cast<short>(nodeContext));

  short regionIndex = nodeContext;
  TMilitaryUnit* unit = 0;
  if (regionIndex >= 0 && regionIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[regionIndex].stationedUnitChain;
  }
  for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f,
                                                  static_cast<float>(unitOrderWeight));
  }

  float sum = 0.0f;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    sum += vector[componentIndex];
  }

  return NormalizeFiveComponentPriorityVector(vector, sum,
                                              g_awTacticalCompositionReferenceProfiles);
}

// Inlined into TMission::CreateMission; no standalone address.

// FUNCTION: IMPERIALISM 0x0053ebe0
void TDefendProvinceMission::Free() {
  // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId]);
  nationState->AssertValid();

  nationState->SetProvinceStatus(presentLocation, kMissionDesirabilityUnmarked);

  CIterator iter(orderList);
  void* current = iter.Reset();
  while (iter.More()) {
    static_cast<TMilitaryUnit*>(current)->ownerMission = NULL;
    current = iter.Advance();
  }

  orderList->RemoveAll();
  if (orderList != NULL) {
    orderList->FreeList();
  }
  orderList = NULL;

  if (this != NULL) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053eca0
float TDefendProvinceMission::AssessImmediateThreat() {
  return ComputeCrossNationSupportVectorScore(presentLocation);
}

// FUNCTION: IMPERIALISM 0x0053ecc0
void TDefendProvinceMission::SetStateByte8To2() {
  TGreatPower* nation = g_apNationStates[nationId];
  short val = nation->GetCapitolProvince();
  if (val == presentLocation) {
    state08 = 0;
  } else {
    state08 = 2;
  }
}

// FUNCTION: IMPERIALISM 0x0053ed00
void TDefendProvinceMission::CalculateImportance() {
  int tileIndex = presentLocation;
  const Province& cityRecord = g_pGlobalMapState->cityScoreTable[tileIndex];

  float score = static_cast<float>(cityRecord.cityScoreValue);
  int adjacentCount = cityRecord.adjacentRegionCount;
  int ownedNeighborCount = 0;

  if (adjacentCount > 0) {
    const short* adjArray = cityRecord.adjacentRegionIds;
    for (int i = 0; i < adjacentCount; ++i) {
      short adjTileIndex = adjArray[i];
      short tileOwnerNationCode = g_pGlobalMapState->FindCountry(adjTileIndex);
      if (nationId == tileOwnerNationCode) {
        ownedNeighborCount++;
      }
    }

    score = (static_cast<float>(ownedNeighborCount) / static_cast<float>(adjacentCount) -
             static_cast<float>((-1.0))) *
            score;
  }

  importanceScore = score / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x0053edf0
void TDefendProvinceMission::CalculateNeeds() {
  // These AI pressure scores live in TAutoGreatPower's derived-only tail.
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId]);
  nationState->AssertValid();

  float pressure = nationState->averageUnitDivergencePerOwnedRegion;

  if (pressure <= static_cast<float>(0.0)) {
    pressure = g_MissionPositiveFallback;
  }

  bool compat = IsMapTileCompatibleWithCurrentTerrainOrActionContext(presentLocation);

  if (!compat) {
    unsigned char unitTier;
    if (g_pTechMgr->abilityActiveRows[nationId].abilityActiveById[16] == 0) {
      unitTier = (g_pTechMgr->abilityActiveRows[nationId].abilityActiveById[8] != 0) ? 8 : 0;
    } else {
      unitTier = 0x10;
    }

    int i;
    int sumCosts = 0;
    for (i = 0; i < 5; ++i) {
      sumCosts += TMilitaryUnit::GetTypeAttribute(unitTier, static_cast<short>(i));
    }

    for (i = 0; i < 5; ++i) {
      short cost = TMilitaryUnit::GetTypeAttribute(unitTier, static_cast<short>(i));
      requiredEquipageByClass[i] =
          (static_cast<float>(cost) * pressure) / static_cast<float>(sumCosts);
    }
    return;
  }

  bool hasWar = g_pDiplomacyTurnStateManager->IsAtWarWithAnybody(nationId);
  float requiredStrength = nationState->expansionPressurePerCompatibleRegion + pressure;

  if (hasWar) {
    float crossScore = ComputeCrossNationSupportVectorScore(presentLocation);
    float factor = g_DefendProvinceMissionCrossSupportFloorScale;
    if (requiredStrength < crossScore * factor) {
      requiredStrength = crossScore * factor;
    }
  }

  signed char fortLevel = g_pGlobalMapState->cityScoreTable[presentLocation].fortLevel;
  int offset = (fortLevel < 1) ? 0 : 15;
  short* referenceProfile = g_awTacticalCompositionReferenceProfiles + offset;

  for (int j = 0; j < 5; ++j) {
    short val = referenceProfile[j];
    requiredEquipageByClass[j] =
        static_cast<float>(val) * requiredStrength * static_cast<float>(0.01);
  }
}

// FUNCTION: IMPERIALISM 0x0053eff0
void TDefendProvinceMission::Initialize() {
  marker11 = 0;
}

// FUNCTION: IMPERIALISM 0x0053f010
bool TDefendProvinceMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  return missionType == kMissionTypeDefendProvince && key == static_cast<int>(presentLocation);
}

// FUNCTION: IMPERIALISM 0x0053f040
TMission* TDefendProvinceMission::GetReplacement() {
  short tileOwnerNationCode = g_pGlobalMapState->FindCountry(presentLocation);
  return (tileOwnerNationCode == nationId) ? this : NULL;
}
