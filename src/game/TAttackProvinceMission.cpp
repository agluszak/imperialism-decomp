// TAttackProvinceMission implementations.

#include <math.h>

#include "game/TAttackProvinceMission.h"
#include "game/CIterator.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TStationedUnitNode.h"
#include "game/TStream.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TAttackProvinceMission, TArmyMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053d710
// TAttackProvinceMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053d7c0
// TAttackProvinceMission::`scalar deleting destructor'

// Not-yet-recovered free functions/subsystems this file calls into. Generic
// stub signature per the autogen stub definition; real signature applied via
// a typed cast at each call site so the linker resolves the correct symbol.
extern undefined4 GetTileNormalizedMovementClassId(void);
extern undefined4 AccumulateMissionUnitPriorityVectorWithOptionalFilter(void);
extern undefined4 GetUnitMovementClassId(void);
// TGreatPower method, not yet ported (operates on this+0x970 -- see
// TDefendProvinceMission.cpp for the identical bridge).
extern undefined4 SetMapStateByteFlag970WithRuntimeGate(void);

namespace {
// See TArmyMission.cpp's identical TArmyMissionOrderItemLayout/OwnerOf --
// orderListAt18 payloads are an unrecovered subtype; only the owner
// back-pointer at +0x40 is known.
struct TAttackProvinceMissionOrderItemLayout {
  char pad_00[0x40];
  TMission* owner; // +0x40
};

TMission*& OwnerOf(TMission* item) {
  return reinterpret_cast<TAttackProvinceMissionOrderItemLayout*>(item)->owner;
}
} // namespace

// FUNCTION: IMPERIALISM 0x0053d6f0
char TAttackProvinceMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053d780
TAttackProvinceMission::TAttackProvinceMission() : TArmyMission(0xffff) {
  targetProvince30 = static_cast<short>(0xffff);
  amassingProvince32 = static_cast<short>(0xffff);
}

// Same address as the default ctor above (0x0053d780 owns that marker);
// this overload is not separately exposed in the original binary.
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
  TGreatPower* nationState = g_apNationStates[nationId04];
  nationState->AssertValid();

  typedef void(__fastcall * SetMapStateByteFlag970WithRuntimeGate_t)(void* self, int dummyEdx,
                                                                     int arg1, int arg2);
  SetMapStateByteFlag970WithRuntimeGate_t SetMapStateByteFlag970WithRuntimeGate_fn =
      reinterpret_cast<SetMapStateByteFlag970WithRuntimeGate_t>(
          (void*)&SetMapStateByteFlag970WithRuntimeGate);
  SetMapStateByteFlag970WithRuntimeGate_fn(nationState, 0, targetProvince30, 0);

  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* current = iter.Reset();
    while (iter.More()) {
      OwnerOf(static_cast<TMission*>(current)) = nullptr;
      current = iter.Advance();
    }

    orderListAt18->RemoveAllSlot5C();
    orderListAt18->FreePayloadsAndDestroySlot58();
    orderListAt18 = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053d950
char TAttackProvinceMission::ReturnFalseSlot98() {
  return TArmyMission::ReturnFalseSlot98();
}

// FUNCTION: IMPERIALISM 0x0053db60
char TAttackProvinceMission::TryResolveTargetTerrainClass() {
  field_14 = static_cast<short>(0xffff);
  float bestScore = 0.0f;

  const TGlobalMapCityScoreRecord& targetRecord =
      g_pGlobalMapState->cityScoreTable[targetProvince30];
  typedef short(__cdecl * GetTileNormalizedMovementClassId_t)(int);
  GetTileNormalizedMovementClassId_t GetTileNormalizedMovementClassId_fn =
      reinterpret_cast<GetTileNormalizedMovementClassId_t>(
          (void*)&GetTileNormalizedMovementClassId);

  for (int i = 0; i < targetRecord.adjacentRegionCount08; ++i) {
    short candidateTile = targetRecord.adjacentRegionIds0A[i];
    short movementClass = GetTileNormalizedMovementClassId_fn(candidateTile);
    if (movementClass != nationId04) {
      continue;
    }

    const TGlobalMapCityScoreRecord& candidateRecord =
        g_pGlobalMapState->cityScoreTable[candidateTile];
    float candidateScore = static_cast<float>(candidateRecord.cityScoreValue);
    int matchCount = 0;
    int adjacentCount = candidateRecord.adjacentRegionCount08;
    for (int j = 0; j < adjacentCount; ++j) {
      short adjMovementClass =
          GetTileNormalizedMovementClassId_fn(candidateRecord.adjacentRegionIds0A[j]);
      if (adjMovementClass == nationId04) {
        matchCount++;
      }
    }
    if (adjacentCount > 0) {
      candidateScore = (static_cast<float>(matchCount) / static_cast<float>(adjacentCount) -
                        *reinterpret_cast<const float*>(0x0065a9e0)) *
                       candidateScore;
    }
    candidateScore = candidateScore / *reinterpret_cast<const float*>(0x0065a9c0);

    if (field_14 != -1 && candidateScore <= bestScore) {
      continue;
    }
    field_14 = candidateTile;
    bestScore = candidateScore;
  }

  return field_14 != -1;
}

// FUNCTION: IMPERIALISM 0x0053de00
void TAttackProvinceMission::MissionSlot44() {
  if (field_14 == -1) {
    TryResolveTargetTerrainClass();
  }

  short contextId = GetMissionTargetContextIdFromField14();
  float vector[5];
  typedef void(__cdecl * AccumulateMissionUnitPriorityVectorWithOptionalFilter_t)(float*, int, int);
  AccumulateMissionUnitPriorityVectorWithOptionalFilter_t
      AccumulateMissionUnitPriorityVectorWithOptionalFilter_fn =
          reinterpret_cast<AccumulateMissionUnitPriorityVectorWithOptionalFilter_t>(
              (void*)&AccumulateMissionUnitPriorityVectorWithOptionalFilter);
  AccumulateMissionUnitPriorityVectorWithOptionalFilter_fn(vector, contextId, 0);

  float total = 0.0f;
  float weighted = 0.0f;
  for (int i = 0; i < 5; ++i) {
    total += resourceWeights[i];
    weighted += sqrtf(vector[i] * resourceWeights[i]);
  }

  if (*reinterpret_cast<const float*>(0x0065a8f0) < weighted / total) {
    short targetOwnerNation = g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00;
    if (g_pDiplomacyTurnStateManager->HasOutdatedWarRelationSlot48(targetOwnerNation, nationId04)) {
      // Original also walks a global "queued mission" cursor here, updating
      // every sibling mission whose context matches field_14 via a vtable
      // slot on a not-yet-recovered node type (distinct field layout from
      // TMission -- pending further class recovery of that queue).
    } else if (!g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(targetOwnerNation,
                                                                        nationId04)) {
      // Original also gates on a per-nation "need already queued" cache
      // (needCurrentByType) before dispatching; omitted pending recovery of
      // that table's real index range.
      g_apNationStates[nationId04]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          targetOwnerNation, 0x131);
    }
  }

  // See note above -- the trailing cursor pass (retargeting every other
  // queued sibling mission to field_14) is pending recovery of that queue's
  // owning class.
}

// FUNCTION: IMPERIALISM 0x0053e050
TMission* TAttackProvinceMission::GetReplacementSlot48() {
  if (field_14 == -1) {
    TryResolveTargetTerrainClass();
  }
  if (field_14 == -1) {
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
    typedef short(__cdecl * GetTileNormalizedMovementClassId_t)(int);
    GetTileNormalizedMovementClassId_t GetTileNormalizedMovementClassId_fn =
        reinterpret_cast<GetTileNormalizedMovementClassId_t>(
            (void*)&GetTileNormalizedMovementClassId);
    short movementClass = GetTileNormalizedMovementClassId_fn(field_14);
    if (movementClass == pathMarker06) {
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
void TAttackProvinceMission::ResetValue0CToZero() {
  const TGlobalMapCityScoreRecord& targetRecord =
      g_pGlobalMapState->cityScoreTable[targetProvince30];
  float score = static_cast<float>(targetRecord.cityScoreValue);

  int matchCount = 0;
  int adjacentCount = targetRecord.adjacentRegionCount08;
  if (adjacentCount > 0) {
    typedef short(__cdecl * GetTileNormalizedMovementClassId_t)(int);
    GetTileNormalizedMovementClassId_t GetTileNormalizedMovementClassId_fn =
        reinterpret_cast<GetTileNormalizedMovementClassId_t>(
            (void*)&GetTileNormalizedMovementClassId);
    for (int i = 0; i < adjacentCount; ++i) {
      short movementClass =
          GetTileNormalizedMovementClassId_fn(targetRecord.adjacentRegionIds0A[i]);
      if (movementClass == nationId04) {
        matchCount++;
      }
    }
    score = (static_cast<float>(matchCount) / static_cast<float>(adjacentCount) -
             *reinterpret_cast<const float*>(0x0065a9e0)) *
            score;
  }
  *reinterpret_cast<float*>(&value0c) = score / *reinterpret_cast<const float*>(0x0065a9c0);
}

// Shared with TInvadeMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x0053e290
void TAttackProvinceMission::NoOpSlot3C() {
  extern undefined4 NoOpRuntimeCallback_005184e0(void);
  extern undefined4 AccumulateUnitOrderPriorityVectorContribution(void);

  typedef short(__cdecl * NoOpRuntimeCallback_005184e0_t)(short);
  short movementClassWeight = reinterpret_cast<NoOpRuntimeCallback_005184e0_t>(
      (void*)&NoOpRuntimeCallback_005184e0)(targetProvince30);

  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  if (targetProvince30 >= 0 && targetProvince30 <= 0x17f) {
    typedef void(__cdecl * AccumulateUnitOrderPriorityVectorContribution_t)(void*, float*, int,
                                                                            float);
    AccumulateUnitOrderPriorityVectorContribution_t
        AccumulateUnitOrderPriorityVectorContribution_fn =
            reinterpret_cast<AccumulateUnitOrderPriorityVectorContribution_t>(
                (void*)&AccumulateUnitOrderPriorityVectorContribution);
    for (TStationedUnitNode* unit =
             g_pGlobalMapState->cityScoreTable[targetProvince30].stationedUnitChain98;
         unit != nullptr; unit = unit->next14) {
      AccumulateUnitOrderPriorityVectorContribution_fn(unit, vector, 0x3f800000,
                                                       static_cast<float>(movementClassWeight));
    }
  }

  // NOTE: the original also re-weights this vector against a per-resource-type
  // lookup table selected by the target province's development-stage byte
  // (fortLevel03 in TGlobalMapCityScoreRecord) before storing it; that lookup table
  // is not yet catalogued in global_data_tables, so the accumulated priority
  // vector is stored directly pending further recovery.
  for (int i = 0; i < 5; ++i) {
    resourceWeights[i] = vector[i];
  }
}

// Shared with TInvadeMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x0053e500
float TAttackProvinceMission::ReturnZeroFloatSlot78(TMission* candidate, float* referenceVector) {
  if (*reinterpret_cast<float*>(&value0c) > 0.0f) {
    typedef short(__cdecl * NoOpRuntimeCallback_005c3530_t)(int);
    extern undefined4 NoOpRuntimeCallback_005c3530(void);
    short threatLevel =
        reinterpret_cast<NoOpRuntimeCallback_005c3530_t>((void*)&NoOpRuntimeCallback_005c3530)(2);
    if (threatLevel < 10) {
      return *reinterpret_cast<const float*>(0x0065a9c4);
    }
  }
  return TArmyMission::ReturnZeroFloatSlot78(candidate, referenceVector);
}

// FUNCTION: IMPERIALISM 0x0053e570
void TAttackProvinceMission::Call30() {
  flag10 = 1;
  if (targetProvince30 != -1) {
    pathMarker06 =
        static_cast<short>(g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00);
  }
}

// FUNCTION: IMPERIALISM 0x0053e5b0
char TAttackProvinceMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if ((kind == 0 || kind == 1) && key == static_cast<int>(targetProvince30)) {
    return 1;
  }
  return 0;
}
