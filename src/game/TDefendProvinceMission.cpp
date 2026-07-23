// TDefendProvinceMission implementations.

#include "game/TDefendProvinceMission.h"
#include "game/TAutoGreatPower.h"
#include "game/TDiplomacyMgr.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TNavyMgr.h"
#include "game/TList.h"
#include "game/TGreatPower.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/TTechMgr.h"

IMPLEMENT_SERIAL(TDefendProvinceMission, TArmyMission, 1)

#include "game/CIterator.h"

// FUNCTION: IMPERIALISM 0x00535770
void TDefendProvinceMission::GiveOrders() {
  PropagateTargetTileToLinkedUnitsIfDifferent(presentLocation14);
}

// FUNCTION: IMPERIALISM 0x00535790
bool TDefendProvinceMission::IsHospitalMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x005357b0
bool TDefendProvinceMission::IsANoBrainer() const {
  return true;
}
// SYNTHETIC: IMPERIALISM 0x005357d0
// TDefendProvinceMission::`scalar deleting destructor'

// Global factory function
// FUNCTION: IMPERIALISM 0x00535800
TDefendProvinceMission::~TDefendProvinceMission() {}

// True if tileIndex is the home region of its own owner nation, or has an adjacent
// region owned by a different valid nation, or is claimed (secondaryNeighbors array
// entry) by some other map-action-context zone whose nationKeyMask10 mask has a bit set outside
// the owner's own bit.
// FUNCTION: IMPERIALISM 0x005359e0
bool IsMapTileCompatibleWithCurrentTerrainOrActionContext(int tileIndex) {
  Province& record = g_pGlobalMapState->cityScoreTable[tileIndex];
  signed char primaryOwner = record.ownerNationCode00;
  if (g_apTerrainTypeDescriptorTable[primaryOwner]->GetHomeRegionCityRecordIndex() == tileIndex) {
    return true;
  }

  for (int i = record.adjacentRegionCount08 - 1; i >= 0; --i) {
    short neighborTile = record.adjacentRegionIds0A[i];
    signed char neighborOwner = g_pGlobalMapState->cityScoreTable[neighborTile].ownerNationCode00;
    if (neighborOwner < 7 && neighborOwner != primaryOwner) {
      return true;
    }
  }

  TZone* zone = g_pMapActionContextListHead;
  if (zone == nullptr) {
    return false;
  }
  unsigned char excludeOwnerMask = static_cast<unsigned char>((1 << (primaryOwner & 0x1f)) ^ 0x7f);
  while ((zone->nationKeyMask10 & excludeOwnerMask) == 0 ||
         !zone->ContainsCityStatePointerInZoneArrayByCityIndex(static_cast<short>(tileIndex))) {
    zone = zone->prev18;
    if (zone == nullptr) {
      return false;
    }
  }
  return true;
}

// Walks orderListAt18 and re-issues TUnit::SetOrders(kUnitOrderRedeploy, newTile) on every linked
// TMilitaryUnit whose tileIndex06 differs from newTile.
// FUNCTION: IMPERIALISM 0x0053c950
void TDefendProvinceMission::PropagateTargetTileToLinkedUnitsIfDifferent(short newTile) {
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->tileIndex06 != newTile) {
      unit->SetOrders(kUnitOrderRedeploy, newTile);
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x0053e5f0
// TDefendProvinceMission::CreateObject

namespace {

inline float NormalizeFiveComponentPriorityVector(const float* vector, float sum,
                                                  const short* lookupTable) {
  if (sum == g_Recompute_Nation_Order_LookupTable_0065A9F0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }

  float accum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    float diff = vector[componentIndex] / sum - static_cast<short>(lookupTable[componentIndex]) *
                                                    g_Recompute_Nation_Order_LookupTable_0065A9F8;
    if (diff <= g_Recompute_Nation_Order_LookupTable_0065A9F0) {
      diff = -diff;
    }
    accum += diff;
  }

  return sum * (g_Recompute_Nation_Order_LookupTable_0065AA08 -
                accum * g_Recompute_Nation_Order_LookupTable_0065AA00);
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x0053e670
// TDefendProvinceMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x0053e6e0
float TDefendProvinceMission::ComputeCrossNationSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  int remainingBudgetByNation[7];

  float unitOrderWeight = static_cast<float>(
      g_pGlobalMapState->GetProvinceUnitOrderWeight(static_cast<short>(nodeContext)));

  Province* sourceRecord = &g_pGlobalMapState->cityScoreTable[nodeContext];
  int sourceNation = static_cast<int>(sourceRecord->ownerNationCode00);

  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    short navyBudget =
        g_pNavyOrderManager->GetInvasionCapacity(static_cast<short>(nationIndex), sourceRecord, 0);
    remainingBudgetByNation[nationIndex] = static_cast<int>(navyBudget);
  }

  int regionIndex = 0;
  do {
    short candidateNation =
        static_cast<short>(g_pGlobalMapState->cityScoreTable[regionIndex].ownerNationCode00);
    if (candidateNation < 7) {
      int candidateNationIndex = static_cast<int>(candidateNation);
      if (candidateNationIndex != sourceNation &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(candidateNation, sourceNation) != 0) {
        if (g_pGlobalMapState->TileHasMovementClassId(nodeContext, regionIndex) != 0) {
          short checkedRegion = static_cast<short>(regionIndex);
          TMilitaryUnit* unit = 0;
          if (checkedRegion >= 0 && checkedRegion < 0x180) {
            unit = g_pGlobalMapState->cityScoreTable[checkedRegion].stationedUnitChain98;
          }
          for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
            if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
              AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f, unitOrderWeight);
            }
          }
        } else if (remainingBudgetByNation[candidateNationIndex] > 0 &&
                   g_pGlobalMapState->AreAllLinkedEntriesTerrainFlagBit2Clear(regionIndex) != 0) {
          short checkedRegion = static_cast<short>(regionIndex);
          TMilitaryUnit* unit = 0;
          if (checkedRegion >= 0 && checkedRegion < 0x180) {
            unit = g_pGlobalMapState->cityScoreTable[checkedRegion].stationedUnitChain98;
          }
          for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
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
    ++regionIndex;
  } while (regionIndex < 0x180);

  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    sum += vector[componentIndex];
  }

  int lookupGroup = (sourceRecord->fortLevel03 > 0) ? 2 : 1;
  const short* lookupTable = g_awTacticalCompositionReferenceProfiles_00697870 + lookupGroup * 5;
  return NormalizeFiveComponentPriorityVector(vector, sum, lookupTable);
}

// FUNCTION: IMPERIALISM 0x0053ea70
float TDefendProvinceMission::ComputeLocalSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};

  short unitOrderWeight =
      g_pGlobalMapState->GetProvinceUnitOrderWeight(static_cast<short>(nodeContext));

  short regionIndex = static_cast<short>(nodeContext);
  TMilitaryUnit* unit = 0;
  if (regionIndex >= 0 && regionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[regionIndex].stationedUnitChain98;
  }
  for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
    AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f,
                                                  static_cast<float>(unitOrderWeight));
  }

  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    sum += vector[componentIndex];
  }

  return NormalizeFiveComponentPriorityVector(vector, sum,
                                              g_awTacticalCompositionReferenceProfiles_00697870);
}

// Default constructor
TDefendProvinceMission::TDefendProvinceMission() : TArmyMission() {}

// Node-key constructor: delegates to TArmyMission(nodeKey) and stamps this class's
// vtable. Inlined into the mission factory (TMission::CreateMission,
// case 3, param_4 == 0); has no standalone address of its own.
TDefendProvinceMission::TDefendProvinceMission(int nodeKey) : TArmyMission(nodeKey) {}

// FUNCTION: IMPERIALISM 0x0053ebe0
void TDefendProvinceMission::Free() {
  // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
  nationState->AssertValid();

  nationState->SetMapStateByteFlag970WithRuntimeGate(presentLocation14, 0);

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

// FUNCTION: IMPERIALISM 0x0053ecc0
void TDefendProvinceMission::SetStateByte8To2() {
  TGreatPower* nation = g_apNationStates[nationId04];
  short val = nation->GetHomeRegionCityRecordIndex();
  if (val == presentLocation14) {
    state08 = 0;
  } else {
    state08 = 2;
  }
}

// FUNCTION: IMPERIALISM 0x0053ed00
void TDefendProvinceMission::CalculateImportance() {
  int tileIndex = presentLocation14;
  const Province& cityRecord = g_pGlobalMapState->cityScoreTable[tileIndex];

  // Ground truth: 0x53ed00 uses FILD (int-to-float conversion), not a raw float
  // bit-reinterpret -- cityScoreValue is a genuine int (see TMapMgr.h).
  float local_8 = static_cast<float>(cityRecord.cityScoreValue);
  int adjacentCount = static_cast<int>(cityRecord.adjacentRegionCount08);
  int local_c = 0;

  if (adjacentCount > 0) {
    const short* adjArray = cityRecord.adjacentRegionIds0A;
    for (int i = 0; i < adjacentCount; ++i) {
      short adjTileIndex = adjArray[i];
      short tileOwnerNationCode =
          g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(adjTileIndex);
      if (nationId04 == tileOwnerNationCode) {
        local_c++;
      }
    }

    static const double* const p_neg_one_0065A9E0 = reinterpret_cast<const double*>(0x0065a9e0);
    local_8 = (static_cast<float>(local_c) / static_cast<float>(adjacentCount) -
               static_cast<float>(*p_neg_one_0065A9E0)) *
              local_8;
  }

  importanceScore0c = local_8 / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x0053edf0
void TDefendProvinceMission::CalculateNeeds() {
  // These AI pressure scores live in TAutoGreatPower's derived-only tail.
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
  nationState->AssertValid();

  float fStack_c = nationState->averageUnitDivergencePerOwnedRegionB68;

  if (fStack_c <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    fStack_c = g_MissionPositiveFallback_0065A9B8;
  }

  bool compat = IsMapTileCompatibleWithCurrentTerrainOrActionContext(presentLocation14);

  if (compat == 0) {
    unsigned char bVar8;
    if (g_pCityOrderCapabilityState->abilityActiveRows395[nationId04].abilityActiveById[0x10] ==
        0) {
      bVar8 =
          (g_pCityOrderCapabilityState->abilityActiveRows395[nationId04].abilityActiveById[8] != 0)
              ? 8
              : 0;
    } else {
      bVar8 = 0x10;
    }

    int i;
    int sumCosts = 0;
    for (i = 0; i < 5; ++i) {
      sumCosts += TMilitaryUnit::GetTypeAttribute(bVar8, static_cast<short>(i));
    }

    for (i = 0; i < 5; ++i) {
      short cost = TMilitaryUnit::GetTypeAttribute(bVar8, static_cast<short>(i));
      requiredEquipageByClass[i] =
          (static_cast<float>(cost) * fStack_c) / static_cast<float>(sumCosts);
    }
    return;
  }

  bool hasWar = g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(nationId04);
  float unaff_EBX = nationState->expansionPressurePerCompatibleRegionB64 + fStack_c;

  if (hasWar != 0) {
    float crossScore = ComputeCrossNationSupportVectorScore(presentLocation14);
    float factor = g_DefendProvinceMissionCrossSupportFloorScale_0065A8F8;
    if (unaff_EBX < crossScore * factor) {
      unaff_EBX = crossScore * factor;
    }
  }

  unsigned char fortLevel = g_pGlobalMapState->cityScoreTable[presentLocation14].fortLevel03;
  int offset = (fortLevel < 1) ? 0 : 15;
  short* psVar5 = g_awTacticalCompositionReferenceProfiles_00697870 + offset;

  for (int j = 0; j < 5; ++j) {
    short val = psVar5[j];
    requiredEquipageByClass[j] = static_cast<float>(val) * unaff_EBX *
                                 static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
  }
}

// FUNCTION: IMPERIALISM 0x0053eff0
void TDefendProvinceMission::Initialize() {
  marker11 = 0;
}

// FUNCTION: IMPERIALISM 0x0053f010
bool TDefendProvinceMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  (void)zoneContext;
  return missionType == kMissionTypeDefendProvince && key == static_cast<int>(presentLocation14);
}

// FUNCTION: IMPERIALISM 0x0053f040
TMission* TDefendProvinceMission::GetReplacementSlot48() {
  short tileOwnerNationCode =
      g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(presentLocation14);
  return (tileOwnerNationCode == nationId04) ? this : nullptr;
}
