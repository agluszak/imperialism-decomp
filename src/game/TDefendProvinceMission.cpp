// TDefendProvinceMission implementations.

#include "game/TDefendProvinceMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TStationedUnitNode.h"
#include "game/TList.h"
#include "game/TGreatPower.h"
#include "game/global_data_tables.h"
#include "game/TTechMgr.h"

IMPLEMENT_SERIAL(TDefendProvinceMission, TArmyMission, 1)

extern "C" {
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F8;
extern double g_Recompute_Nation_Order_LookupTable_0065AA00;
extern double g_Recompute_Nation_Order_LookupTable_0065AA08;
extern unsigned short g_Recompute_Nation_Order_LookupTable_00697870[];
}

#include "game/CIterator.h"

short GetTileNormalizedMovementClassId(int tileIndex);

// Global factory function
// FUNCTION: IMPERIALISM 0x0053e5f0
TMission* CreateTDefendProvinceMission() {
  return new TDefendProvinceMission();
}

// Global metadata name pointer
// FUNCTION: IMPERIALISM 0x0053e670
void* GetTDefendProvinceMissionClassNamePointer() {
  return &TDefendProvinceMission::classTDefendProvinceMission;
}

namespace {

char* NationContextRecordBytes(int regionIndex) {
  return reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + regionIndex * 0xa8;
}

TStationedUnitNode* StationedUnitChainAt(int regionIndex) {
  if (regionIndex < 0 || regionIndex > 0x17f) {
    return 0;
  }
  return *reinterpret_cast<TStationedUnitNode**>(NationContextRecordBytes(regionIndex) + 0x98);
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

void AccumulatePriorityVectorFromStationedUnit(TStationedUnitNode* unitNode, float* vector) {
  short movementClassId = unitNode->GetUnitMovementClassId();
  if (movementClassId <= 0) {
    return;
  }
  // AccumulateUnitOrderPriorityVectorContribution is at 0x535a30
  typedef void (__cdecl *AccumulateUnitOrderPriorityVectorContribution_t)(void*, float*, int, int);
  AccumulateUnitOrderPriorityVectorContribution_t AccumulateUnitOrderPriorityVectorContribution_fn =
      reinterpret_cast<AccumulateUnitOrderPriorityVectorContribution_t>(0x535a30);
  AccumulateUnitOrderPriorityVectorContribution_fn(unitNode, vector, 0x3f800000,
                                                   static_cast<int>(movementClassId));
}

} // namespace

// FUNCTION: IMPERIALISM 0x0053e6e0
float TDefendProvinceMission::ComputeCrossNationSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  int remainingBudgetByNation[7] = {0, 0, 0, 0, 0, 0, 0};
  
  // NoOpRuntimeCallback_005184e0 is at 0x5184e0
  typedef void (__cdecl *NoOpRuntimeCallback_005184e0_t)(void);
  reinterpret_cast<NoOpRuntimeCallback_005184e0_t>(0x5184e0)();

  char* nationContextTable = reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable);
  int sourceNation =
      static_cast<int>(static_cast<signed char>(nationContextTable[nodeContext * 0xa8]));
  
  // ComputeAggregateWeightedChildCostForMatchingType5NavyOrders is at 0x53ac30
  typedef short (__cdecl *ComputeAggregateWeightedChildCostForMatchingType5NavyOrders_t)(void);
  ComputeAggregateWeightedChildCostForMatchingType5NavyOrders_t ComputeAggregateWeightedChildCostForMatchingType5NavyOrders_fn =
      reinterpret_cast<ComputeAggregateWeightedChildCostForMatchingType5NavyOrders_t>(0x53ac30);

  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    short navyBudget = ComputeAggregateWeightedChildCostForMatchingType5NavyOrders_fn();
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
        
        // TileHasMovementClassId is at 0x5140e0
        typedef char (__cdecl *TileHasMovementClassId_t)(void);
        char tileHasMovementClass = reinterpret_cast<TileHasMovementClassId_t>(0x5140e0)();
        
        if (tileHasMovementClass == 0) {
          if (remainingBudgetByNation[candidateNationIndex] > 0) {
            
            // AreAllLinkedEntriesTerrainFlagBit2Clear is at 0x514000
            typedef char (__cdecl *AreAllLinkedEntriesTerrainFlagBit2Clear_t)(void);
            char linkedTerrainClear = reinterpret_cast<AreAllLinkedEntriesTerrainFlagBit2Clear_t>(0x514000)();
            
            if (linkedTerrainClear != 0) {
              for (TStationedUnitNode* unit = StationedUnitChainAt(regionIndex); unit != 0;
                   unit = unit->next14) {
                
                // GetCityActionGateValueFromOrderTemplate is at 0x4e87d0
                typedef short (__cdecl *GetCityActionGateValueFromOrderTemplate_t)(void);
                short gateValue = reinterpret_cast<GetCityActionGateValueFromOrderTemplate_t>(0x4e87d0)();
                
                short movementClassId = unit->GetUnitMovementClassId();
                if (gateValue > 0) {
                  int remainingBudget = remainingBudgetByNation[candidateNationIndex];
                  if (movementClassId < remainingBudget) {
                    typedef void (__cdecl *AccumulateUnitOrderPriorityVectorContribution_t)(void*, float*, int, int);
                    AccumulateUnitOrderPriorityVectorContribution_t AccumulateUnitOrderPriorityVectorContribution_fn =
                        reinterpret_cast<AccumulateUnitOrderPriorityVectorContribution_t>(0x535a30);
                    AccumulateUnitOrderPriorityVectorContribution_fn(
                        unit, vector, 0x3f800000, static_cast<int>(movementClassId));
                    remainingBudgetByNation[candidateNationIndex] =
                        remainingBudget - movementClassId;
                  }
                }
              }
            }
          }
        } else {
          for (TStationedUnitNode* unit = StationedUnitChainAt(regionIndex); unit != 0;
               unit = unit->next14) {
            short movementClassId = unit->GetUnitMovementClassId();
            if (movementClassId > 0) {
              typedef void (__cdecl *AccumulateUnitOrderPriorityVectorContribution_t)(void*, float*, int, int);
              AccumulateUnitOrderPriorityVectorContribution_t AccumulateUnitOrderPriorityVectorContribution_fn =
                  reinterpret_cast<AccumulateUnitOrderPriorityVectorContribution_t>(0x535a30);
              AccumulateUnitOrderPriorityVectorContribution_fn(unit, vector, 0x3f800000,
                                                             static_cast<int>(movementClassId));
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
      g_Recompute_Nation_Order_LookupTable_00697870 + lookupGroup * 5;
  return NormalizeFiveComponentPriorityVector(vector, sum, lookupTable);
}

// FUNCTION: IMPERIALISM 0x0053ea70
float TDefendProvinceMission::ComputeLocalSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  
  typedef void (__cdecl *NoOpRuntimeCallback_005184e0_t)(void);
  reinterpret_cast<NoOpRuntimeCallback_005184e0_t>(0x5184e0)();

  for (TStationedUnitNode* unit = StationedUnitChainAt(nodeContext); unit != 0;
       unit = unit->next14) {
    AccumulatePriorityVectorFromStationedUnit(unit, vector);
  }

  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 5; ++componentIndex) {
    sum += vector[componentIndex];
  }

  return NormalizeFiveComponentPriorityVector(vector, sum,
                                              g_Recompute_Nation_Order_LookupTable_00697870);
}

// Default constructor
TDefendProvinceMission::TDefendProvinceMission() : TArmyMission() {}

// Destructor
TDefendProvinceMission::~TDefendProvinceMission() {}

// FUNCTION: IMPERIALISM 0x00535370
void TDefendProvinceMission::Call30() {
  marker11 = 0;
}

// FUNCTION: IMPERIALISM 0x0053ebe0
void TDefendProvinceMission::CleanupTArmyMissionAndReleaseChildContext() {
  TGreatPower* nationState = g_apNationStates[nationId04];
  nationState->AssertValid();
  
  typedef void (__fastcall *SetMapStateByteFlag970WithRuntimeGate_t)(void* self, int dummyEdx, int arg1, int arg2);
  SetMapStateByteFlag970WithRuntimeGate_t SetMapStateByteFlag970WithRuntimeGate_fn =
      reinterpret_cast<SetMapStateByteFlag970WithRuntimeGate_t>(0x4e8b50);
  SetMapStateByteFlag970WithRuntimeGate_fn(nationState, 0, field_14, 0);

  TSortedList* orderList = reinterpret_cast<TSortedList*>(orderListAt18);
  if (orderList != nullptr) {
    CIterator iter(orderList);
    void* current = iter.Reset();
    while (iter.More()) {
      *reinterpret_cast<int*>(reinterpret_cast<char*>(current) + 0x40) = 0;
      current = iter.Advance();
    }
  }

  TList* list = reinterpret_cast<TList*>(orderListAt18);
  if (list != nullptr) {
    list->RemoveAllSlot5C();
    list->FreePayloadsAndDestroySlot58();
    orderListAt18 = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053ecc0
void TDefendProvinceMission::UpdateDefendProvinceMissionStateByNationTargetMatch() {
  TGreatPower* nation = g_apNationStates[nationId04];
  short val = nation->GetHomeRegionCityRecordIndex();
  if (val == field_14) {
    state08 = 0;
  } else {
    state08 = 2;
  }
}

// FUNCTION: IMPERIALISM 0x0053ed00
void TDefendProvinceMission::ComputeDefendProvinceMissionTerrainAdjacencyScoreFromTile14() {
  int tileIndex = field_14;
  char* cityScoreTable = reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable);
  
  float local_8 = *reinterpret_cast<float*>(cityScoreTable + 0x9c + tileIndex * 0xa8);
  int adjacentCount = static_cast<int>(g_pGlobalMapState->cityScoreTable[tileIndex].adjacentRegionCount08);
  int local_c = 0;
  
  if (adjacentCount > 0) {
    const short* adjArray = g_pGlobalMapState->cityScoreTable[tileIndex].adjacentRegionIds0A;
    for (int i = 0; i < adjacentCount; ++i) {
      short adjTileIndex = adjArray[i];
      short movementClass = GetTileNormalizedMovementClassId(adjTileIndex);
      if (nationId04 == movementClass) {
        local_c++;
      }
    }
    
    static const double* const p_neg_one_0065A9E0 = reinterpret_cast<const double*>(0x0065a9e0);
    local_8 = (static_cast<float>(local_c) / static_cast<float>(adjacentCount) - static_cast<float>(*p_neg_one_0065A9E0)) * local_8;
  }
  
  static const float* const p_5000_0065A9C0 = reinterpret_cast<const float*>(0x0065a9c0);
  *reinterpret_cast<float*>(&value0c) = local_8 / (*p_5000_0065A9C0);
}

// FUNCTION: IMPERIALISM 0x0053edf0
void TDefendProvinceMission::PopulateDefendProvinceMissionResourceWeightsByDiplomacyContext() {
  TGreatPower* nationState = g_apNationStates[nationId04];
  nationState->AssertValid();

  float fStack_c = nationState->floatB68;
  static const double* const p_neg_one_0065A9F0 = reinterpret_cast<const double*>(0x0065a9f0);
  static const float* const p_1_0_0065A9B8 = reinterpret_cast<const float*>(0x0065a9b8);

  if (fStack_c <= static_cast<float>(*p_neg_one_0065A9F0)) {
    fStack_c = *p_1_0_0065A9B8;
  }

  typedef int (__cdecl *IsMapTileCompatibleWithCurrentTerrainOrActionContext_t)(int tileIndex);
  IsMapTileCompatibleWithCurrentTerrainOrActionContext_t IsMapTileCompatibleWithCurrentTerrainOrActionContext_fn =
      reinterpret_cast<IsMapTileCompatibleWithCurrentTerrainOrActionContext_t>(0x4016d6);
  int compat = IsMapTileCompatibleWithCurrentTerrainOrActionContext_fn(field_14);

  if (compat == 0) {
    unsigned char bVar8;
    if (g_pCityOrderCapabilityState->militaryCapRows39d[nationId04].eliteRecruitFlag == 0) {
      bVar8 = (g_pCityOrderCapabilityState->militaryCapRows39d[nationId04].recruitTierFlag != 0) ? 8 : 0;
    } else {
      bVar8 = 0x10;
    }

    typedef short (__cdecl *GetNormalizedCityActionResourceCostPercent_t)(int capFlag, int index);
    GetNormalizedCityActionResourceCostPercent_t GetNormalizedCityActionResourceCostPercent_fn =
        reinterpret_cast<GetNormalizedCityActionResourceCostPercent_t>(0x4e8720);

    int i;
    int sumCosts = 0;
    for (i = 0; i < 5; ++i) {
      sumCosts += GetNormalizedCityActionResourceCostPercent_fn(bVar8, i);
    }

    for (i = 0; i < 5; ++i) {
      short cost = GetNormalizedCityActionResourceCostPercent_fn(bVar8, i);
      resourceWeights[i] = (static_cast<float>(cost) * fStack_c) / static_cast<float>(sumCosts);
    }
    return;
  }

  char hasWar = g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(nationId04);
  float unaff_EBX = nationState->floatB64 + fStack_c;

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
  unsigned short* psVar5 = g_Recompute_Nation_Order_LookupTable_00697870 + offset;

  for (int j = 0; j < 5; ++j) {
    short val = psVar5[j];
    resourceWeights[j] = static_cast<float>(val) * unaff_EBX * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
  }
}

// FUNCTION: IMPERIALISM 0x0053f010
bool TDefendProvinceMission::HandleInvadeMissionActionType3ForTargetTile(int param_1, int param_2) {
  if ((param_1 == 3) && (param_2 == static_cast<int>(field_14))) {
    return true;
  }
  return false;
}
