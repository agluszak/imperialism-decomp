#include "game/TDefendProvinceMission.h"

#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TStationedUnitNode.h"
#include "game/global_data_tables.h"

extern "C" {
extern float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F0;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F8;
extern double g_Recompute_Nation_Order_LookupTable_0065AA00;
extern double g_Recompute_Nation_Order_LookupTable_0065AA08;
extern unsigned short g_Recompute_Nation_Order_LookupTable_00697870[];
}

undefined4 NoOpRuntimeCallback_005184e0(void);
undefined4 AccumulateUnitOrderPriorityVectorContribution(void);
undefined4 ComputeAggregateWeightedChildCostForMatchingType5NavyOrders(void);
undefined4 TileHasMovementClassId(void);
undefined4 AreAllLinkedEntriesTerrainFlagBit2Clear(void);
undefined4 GetCityActionGateValueFromOrderTemplate(void);

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
  reinterpret_cast<void(__cdecl*)(void*, float*, int, int)>(
      AccumulateUnitOrderPriorityVectorContribution)(unitNode, vector, 0x3f800000,
                                                     static_cast<int>(movementClassId));
}

} // namespace

// FUNCTION: IMPERIALISM 0x0053e6e0
float TDefendProvinceMission::ComputeCrossNationSupportVectorScore(int nodeContext) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  int remainingBudgetByNation[7] = {0, 0, 0, 0, 0, 0, 0};
  reinterpret_cast<void(__cdecl*)(void)>(NoOpRuntimeCallback_005184e0)();

  char* nationContextTable = reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable);
  int sourceNation =
      static_cast<int>(static_cast<signed char>(nationContextTable[nodeContext * 0xa8]));
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    short navyBudget = reinterpret_cast<short(__cdecl*)(void)>(
        ComputeAggregateWeightedChildCostForMatchingType5NavyOrders)();
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
            reinterpret_cast<char(__cdecl*)(void)>(TileHasMovementClassId)();
        if (tileHasMovementClass == 0) {
          if (remainingBudgetByNation[candidateNationIndex] > 0) {
            char linkedTerrainClear =
                reinterpret_cast<char(__cdecl*)(void)>(AreAllLinkedEntriesTerrainFlagBit2Clear)();
            if (linkedTerrainClear != 0) {
              for (TStationedUnitNode* unit = StationedUnitChainAt(regionIndex); unit != 0;
                   unit = unit->next14) {
                short gateValue = reinterpret_cast<short(__cdecl*)(void)>(
                    GetCityActionGateValueFromOrderTemplate)();
                short movementClassId = unit->GetUnitMovementClassId();
                if (gateValue > 0) {
                  int remainingBudget = remainingBudgetByNation[candidateNationIndex];
                  if (movementClassId < remainingBudget) {
                    reinterpret_cast<void(__cdecl*)(void*, float*, int, int)>(
                        AccumulateUnitOrderPriorityVectorContribution)(
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
              reinterpret_cast<void(__cdecl*)(void*, float*, int, int)>(
                  AccumulateUnitOrderPriorityVectorContribution)(unit, vector, 0x3f800000,
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
  reinterpret_cast<void(__cdecl*)(void)>(NoOpRuntimeCallback_005184e0)();

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
