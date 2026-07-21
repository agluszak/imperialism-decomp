// TDefendProvinceMission implementations.

#include "game/TDefendProvinceMission.h"
#include "game/TAutoGreatPower.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
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
void TDefendProvinceMission::MissionSlot44() {
  PropagateTargetTileToLinkedUnitsIfDifferent(field_14);
}

// FUNCTION: IMPERIALISM 0x00535790
char TDefendProvinceMission::ReturnFalseSlot64() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x005357b0
char TDefendProvinceMission::ReturnFalseSlot28() {
  return 1;
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
char IsMapTileCompatibleWithCurrentTerrainOrActionContext(int tileIndex) {
  TGlobalMapCityScoreRecord& record = g_pGlobalMapState->cityScoreTable[tileIndex];
  signed char primaryOwner = record.ownerNationCode00;
  if (g_apTerrainTypeDescriptorTable[primaryOwner]->GetHomeRegionCityRecordIndex() == tileIndex) {
    return 1;
  }

  for (int i = record.adjacentRegionCount08 - 1; i >= 0; --i) {
    short neighborTile = record.adjacentRegionIds0A[i];
    signed char neighborOwner = g_pGlobalMapState->cityScoreTable[neighborTile].ownerNationCode00;
    if (neighborOwner < 7 && neighborOwner != primaryOwner) {
      return 1;
    }
  }

  TZone* zone = g_pMapActionContextListHead;
  if (zone == nullptr) {
    return 0;
  }
  unsigned char excludeOwnerMask = static_cast<unsigned char>((1 << (primaryOwner & 0x1f)) ^ 0x7f);
  while ((zone->nationKeyMask10 & excludeOwnerMask) == 0 ||
         !zone->ContainsCityStatePointerInZoneArrayByCityIndex(static_cast<short>(tileIndex))) {
    zone = zone->prev18;
    if (zone == nullptr) {
      return 0;
    }
  }
  return 1;
}

// Walks orderListAt18 and re-issues TUnit::SetOrderModeSlot34(1, newTile) on every linked
// TMilitaryUnit whose tileIndex06 differs from newTile.
// FUNCTION: IMPERIALISM 0x0053c950
void TDefendProvinceMission::PropagateTargetTileToLinkedUnitsIfDifferent(short newTile) {
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->tileIndex06 != newTile) {
      unit->SetOrderModeSlot34(1, newTile);
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x0053e5f0
// TDefendProvinceMission::CreateObject

namespace {

char* NationContextRecordBytes(int regionIndex) {
  return reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + regionIndex * 0xa8;
}

TMilitaryUnit* StationedUnitChainAt(int regionIndex) {
  if (regionIndex < 0 || regionIndex > 0x17f) {
    return 0;
  }
  return *reinterpret_cast<TMilitaryUnit**>(NationContextRecordBytes(regionIndex) + 0x98);
}

float NormalizeFiveComponentPriorityVector(const float* vector, float sum,
                                           const unsigned short* lookupTable) {
  if (sum == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }

  float accum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    float diff = vector[componentIndex] / sum -
                 static_cast<float>(static_cast<short>(lookupTable[componentIndex])) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    accum += diff;
  }

  return sum * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                accum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x0053e670
// TDefendProvinceMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x0053e6e0
float TDefendProvinceMission::ComputeCrossNationSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  int remainingBudgetByNation[7] = {0, 0, 0, 0, 0, 0, 0};

  short unitOrderWeight =
      g_pGlobalMapState->GetProvinceUnitOrderWeight(static_cast<short>(nodeContext));

  char* nationContextTable = reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable);
  int sourceNation =
      static_cast<int>(static_cast<signed char>(nationContextTable[nodeContext * 0xa8]));

  void* nodeCityRecord = nationContextTable + nodeContext * 0xa8;
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    short navyBudget =
        g_pNavyOrderManager->ComputeAggregateWeightedChildCostForMatchingType5NavyOrders(
            static_cast<short>(nationIndex), nodeCityRecord, 0);
    remainingBudgetByNation[nationIndex] = static_cast<int>(navyBudget);
  }

  short regionIndex = 0;
  int regionByteOffset = 0;
  do {
    short candidateNation =
        static_cast<short>(static_cast<signed char>(nationContextTable[regionByteOffset]));
    if (candidateNation < 7) {
      int candidateNationIndex = static_cast<int>(candidateNation);
      if (candidateNationIndex != sourceNation &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(candidateNation, sourceNation) !=
              0) {

        char tileHasMovementClass =
            g_pGlobalMapState->TileHasMovementClassId(nodeContext, regionIndex);

        if (tileHasMovementClass == 0) {
          if (remainingBudgetByNation[candidateNationIndex] > 0) {

            char linkedTerrainClear =
                g_pGlobalMapState->AreAllLinkedEntriesTerrainFlagBit2Clear(regionIndex);

            if (linkedTerrainClear != 0) {
              for (TMilitaryUnit* unit = StationedUnitChainAt(regionIndex); unit != 0;
                   unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
                short costPoints = unit->GetUnitTypeCostPoints();
                short movementClassId = unit->GetUnitMovementClassId();
                if (movementClassId > 0) {
                  int remainingBudget = remainingBudgetByNation[candidateNationIndex];
                  if (costPoints < remainingBudget) {
                    AccumulateUnitOrderPriorityVectorContribution(
                        unit, vector, 1.0f, static_cast<float>(unitOrderWeight));
                    remainingBudgetByNation[candidateNationIndex] = remainingBudget - costPoints;
                  }
                }
              }
            }
          }
        } else {
          for (TMilitaryUnit* unit = StationedUnitChainAt(regionIndex); unit != 0;
               unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
            short movementClassId = unit->GetUnitMovementClassId();
            if (movementClassId > 0) {
              AccumulateUnitOrderPriorityVectorContribution(unit, vector, 1.0f,
                                                            static_cast<float>(unitOrderWeight));
            }
          }
        }
      }
    }
    ++regionIndex;
    regionByteOffset += 0xa8;
  } while (regionByteOffset < 0xfc00);

  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    sum += vector[componentIndex];
  }

  char resourceTypeByte = nationContextTable[nodeContext * 0xa8 + 3];
  int lookupGroup = (resourceTypeByte > 0) ? 2 : 1;
  const unsigned short* lookupTable =
      g_awTacticalCompositionReferenceProfiles_00697870 + lookupGroup * 5;
  return NormalizeFiveComponentPriorityVector(vector, sum, lookupTable);
}

// FUNCTION: IMPERIALISM 0x0053ea70
float TDefendProvinceMission::ComputeLocalSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};

  short unitOrderWeight =
      g_pGlobalMapState->GetProvinceUnitOrderWeight(static_cast<short>(nodeContext));

  for (TMilitaryUnit* unit = StationedUnitChainAt(nodeContext); unit != 0;
       unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
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
// vtable. Inlined into the mission factory (CreateMissionObjectByKindAndNodeContext,
// case 3, param_4 == 0); has no standalone address of its own.
TDefendProvinceMission::TDefendProvinceMission(int nodeKey) : TArmyMission(nodeKey) {}

namespace {

// Order-list items (orderListAt18) are a not-yet-recovered mission/order
// subtype whose instance size exceeds every currently-modelled mission class;
// only its owner back-pointer at +0x40 is known. Real type/name TBD via
// further class recovery (see TArmyMission.cpp for the sibling definition).
struct TDefendProvinceMissionOrderItemLayout {
  char pad_00[0x40];
  TMission* owner; // +0x40
};

} // namespace

// FUNCTION: IMPERIALISM 0x0053ebe0
void TDefendProvinceMission::Free() {
  // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
  nationState->AssertValid();

  nationState->SetMapStateByteFlag970WithRuntimeGate(field_14, 0);

  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* current = iter.Reset();
    while (iter.More()) {
      reinterpret_cast<TDefendProvinceMissionOrderItemLayout*>(current)->owner = nullptr;
      current = iter.Advance();
    }

    orderListAt18->RemoveAll();
    orderListAt18->FreePayloadsAndDestroy();
    orderListAt18 = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053ecc0
void TDefendProvinceMission::SetStateByte8To2() {
  TGreatPower* nation = g_apNationStates[nationId04];
  short val = nation->GetHomeRegionCityRecordIndex();
  if (val == field_14) {
    state08 = 0;
  } else {
    state08 = 2;
  }
}

// FUNCTION: IMPERIALISM 0x0053ed00
void TDefendProvinceMission::ResetValue0CToZero() {
  int tileIndex = field_14;
  const TGlobalMapCityScoreRecord& cityRecord = g_pGlobalMapState->cityScoreTable[tileIndex];

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

  value0c = local_8 / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x0053edf0
void TDefendProvinceMission::NoOpSlot3C() {
  // These AI pressure scores live in TAutoGreatPower's derived-only tail.
  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
  nationState->AssertValid();

  float fStack_c = nationState->averageUnitDivergencePerOwnedRegionB68;
  static const double* const p_neg_one_0065A9F0 = reinterpret_cast<const double*>(0x0065a9f0);
  static const float* const p_1_0_0065A9B8 = reinterpret_cast<const float*>(0x0065a9b8);

  if (fStack_c <= static_cast<float>(*p_neg_one_0065A9F0)) {
    fStack_c = *p_1_0_0065A9B8;
  }

  int compat = IsMapTileCompatibleWithCurrentTerrainOrActionContext(field_14);

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
      sumCosts += GetNormalizedCityActionResourceCostPercent(bVar8, static_cast<short>(i));
    }

    for (i = 0; i < 5; ++i) {
      short cost = GetNormalizedCityActionResourceCostPercent(bVar8, static_cast<short>(i));
      resourceWeights[i] = (static_cast<float>(cost) * fStack_c) / static_cast<float>(sumCosts);
    }
    return;
  }

  char hasWar = g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(nationId04);
  float unaff_EBX = nationState->expansionPressurePerCompatibleRegionB64 + fStack_c;

  if (hasWar != 0) {
    float crossScore = ComputeCrossNationSupportVectorScore(field_14);
    float factor = *reinterpret_cast<const float*>(0x0065a8f8);
    if (unaff_EBX < crossScore * factor) {
      unaff_EBX = crossScore * factor;
    }
  }

  char* cityScoreTable = reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable);
  char tileByte3 = cityScoreTable[3 + field_14 * 0xa8];
  int offset = (tileByte3 < 1) ? 0 : 15;
  unsigned short* psVar5 = g_awTacticalCompositionReferenceProfiles_00697870 + offset;

  for (int j = 0; j < 5; ++j) {
    short val = psVar5[j];
    resourceWeights[j] = static_cast<float>(val) * unaff_EBX *
                         static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
  }
}

// FUNCTION: IMPERIALISM 0x0053eff0
void TDefendProvinceMission::Call30() {
  marker11 = 0;
}

// FUNCTION: IMPERIALISM 0x0053f010
char TDefendProvinceMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if ((kind == 3) && (key == static_cast<int>(field_14))) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053f040
TMission* TDefendProvinceMission::GetReplacementSlot48() {
  short tileOwnerNationCode = g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(field_14);
  return (tileOwnerNationCode == nationId04) ? this : nullptr;
}
