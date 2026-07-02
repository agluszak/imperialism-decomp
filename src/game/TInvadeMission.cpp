// TInvadeMission implementations.

#include "game/TInvadeMission.h"
#include "game/TBeachheadMission.h"
#include "game/TGlobalMapState.h"
#include "game/TStream.h"

IMPLEMENT_SERIAL(TInvadeMission, TAttackProvinceMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053f260
// TInvadeMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053f3c0
// TInvadeMission::`scalar deleting destructor'

// Not-yet-recovered free functions/subsystems this file calls into.
extern undefined4 GetTileNormalizedMovementClassId(void);
extern undefined4 AccumulateUnitOrderPriorityVectorContribution(void);
extern undefined4 InitializeLinkedListCursorFromOwnerHead(void);
extern undefined4 LinkedListCursorHasCurrent(void);
extern undefined4 AdvanceLinkedListCursor(void);
extern undefined4 GetUnitMovementClassId(void);

TInvadeMission::TInvadeMission() : TAttackProvinceMission(), beachhead34(nullptr) {}

TInvadeMission::TInvadeMission(short targetProvince, short amassingProvince)
    : TAttackProvinceMission(targetProvince, amassingProvince), beachhead34(nullptr) {}

// FUNCTION: IMPERIALISM 0x0053f120
int TInvadeMission::ReturnZeroSlot5C() {
  return reinterpret_cast<int>(beachhead34);
}

// FUNCTION: IMPERIALISM 0x0053f140
char TInvadeMission::ReturnFalseSlot54() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053f160
void TInvadeMission::NoOpSlot90(int a) {
  if (beachhead34 != nullptr) {
    beachhead34->NoOpSlot90(a);
  }
}

// FUNCTION: IMPERIALISM 0x0053f190
void TInvadeMission::NoOpSlot84(int a, int b) {
  if (beachhead34 != nullptr) {
    beachhead34->NoOpSlot84(a, b);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1c0
void TInvadeMission::NoOpSlot8C(int a, int b) {
  if (beachhead34 != nullptr) {
    beachhead34->NoOpSlot8C(a, b);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1f0
float TInvadeMission::ReturnZeroFloatSlot6C() {
  // TODO: ComputeInvadeMissionCompositeScoreWithBeachhead -- pending recovery
  // of the g_697980 dot-product profile table.
  float score = 0.0f;
  if (beachhead34 != nullptr) {
    score = beachhead34->ReturnZeroFloatSlot6C();
  }
  return score;
}

// FUNCTION: IMPERIALISM 0x0053f240
char TInvadeMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053f410
void TInvadeMission::Free() {
  if (beachhead34 != nullptr) {
    beachhead34->Free();
    beachhead34 = nullptr;
  }
  TAttackProvinceMission::Free();
}

// FUNCTION: IMPERIALISM 0x0053f4e0
char TInvadeMission::ReturnFalseSlot98() {
  // TODO: EvaluateInvadeMissionBeachheadAndQueueEligibleUnits -- pending
  // recovery of the beachhead-gated unit-queueing cursor loop.
  if (beachhead34 == nullptr) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053f580
void TInvadeMission::Call30() {
  // InitializeInvadeMissionFromNationAndTargetTile: resets pathMarker06 (not
  // TAttackProvinceMission::Call30's owner-nation lookup).
  pathMarker06 = static_cast<short>(0xffff);
  marker11 = 1;
  if (targetProvince30 != -1) {
    // Byte at cityScoreTable[targetProvince30]+0x10 -- not yet a named field
    // on TGlobalMapCityScoreRecord; read via raw offset pending recovery.
    const char* recordBytes =
        reinterpret_cast<const char*>(&g_pGlobalMapState->cityScoreTable[targetProvince30]);
    pathMarker06 = static_cast<short>(recordBytes[0x10]);
  }
  marker11 = 3;
}

// FUNCTION: IMPERIALISM 0x0053f5f0
void TInvadeMission::SetStateByte8To2() {
  state08 = 2;
}

// FUNCTION: IMPERIALISM 0x0053f610
void TInvadeMission::NoOpSlot3C() {
  TAttackProvinceMission::NoOpSlot3C();
  if (beachhead34 != nullptr) {
    beachhead34->NoOpSlot3C();
  }
}

// FUNCTION: IMPERIALISM 0x0053f640
void TInvadeMission::WriteTo(TStream* stream) {
  TAttackProvinceMission::WriteTo(stream);
  if (beachhead34 != nullptr) {
    beachhead34->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x0053f690
void TInvadeMission::ReadFrom(TStream* stream) {
  TAttackProvinceMission::ReadFrom(stream);
  if (beachhead34 != nullptr) {
    beachhead34->ReadFrom(stream);
  }
}

// FUNCTION: IMPERIALISM 0x0053f780
void TInvadeMission::MissionSlot44() {
  if (beachhead34 != nullptr) {
    beachhead34->MissionSlot44();
  }
  // Per-region, per-nation dispatch-dirty bitmask gate (byte at record+0xa1,
  // bit index nationId04) -- pending exact TGlobalMapCityScoreRecord field
  // recovery for that byte; approximated via raw offset access for now.
  const unsigned char* recordBytes =
      reinterpret_cast<const unsigned char*>(&g_pGlobalMapState->cityScoreTable[targetProvince30]);
  if (recordBytes[0xa1] & (1 << (nationId04 & 0x1f))) {
    TAttackProvinceMission::MissionSlot44();
  }
}

// FUNCTION: IMPERIALISM 0x0053f7d0
void TInvadeMission::RefreshSlot40() {
  if (beachhead34 != nullptr) {
    beachhead34->RefreshSlot40();
  }
  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();
}

// FUNCTION: IMPERIALISM 0x0053faa0
char TInvadeMission::ReturnFalseSlot50() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053fac0
float TInvadeMission::ReturnZeroFloatSlot70(TMilitaryUnit* candidateUnit) {
  // TODO: ComputeInvadeMissionWeightedScoreDelta -- simplified passthrough
  // pending recovery of the beachhead-relative scaling logic.
  return TArmyMission::ReturnZeroFloatSlot70(candidateUnit);
}

// FUNCTION: IMPERIALISM 0x0053fb60
float TInvadeMission::ReturnZeroFloatSlot74() {
  if (flag10 != 0) {
    return 0.0f;
  }
  if (beachhead34 != nullptr) {
    return beachhead34->ReturnZeroFloatSlot74();
  }
  return 0.0f;
}

// FUNCTION: IMPERIALISM 0x0053fb90
void TInvadeMission::SetFlag10FromArgSlot94(unsigned char value) {
  flag10 = value;
  if (beachhead34 != nullptr) {
    beachhead34->SetFlag10FromArgSlot94(value);
  }
}

// FUNCTION: IMPERIALISM 0x0053fbc0
char TInvadeMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  if (kind == 2 && key == targetProvince30 && beachhead34 != nullptr) {
    if (beachhead34->MatchesMissionKeySlot4C(2, key, mode) != 0) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053fc10
int TInvadeMission::ReturnZeroSlot2C(int* outBuffer, int unused) {
  // TODO: BuildInvadeMissionUnitPriorityVectorAndScore -- pending recovery of
  // the shared unit-priority-vector accumulation cursor; delegate for now.
  return TArmyMission::ReturnZeroSlot2C(outBuffer, unused);
}

// FUNCTION: IMPERIALISM 0x0053fdc0
char TInvadeMission::TryResolveTargetTerrainClass() {
  field_14 = static_cast<short>(0xffff);
  if (TAttackProvinceMission::TryResolveTargetTerrainClass() != 0) {
    field_14 = static_cast<short>(0xffff);
    return 0;
  }
  // TODO: else-branch resolves field_14 from the owning nation's own terrain
  // descriptor via an unrecovered TCountry vtable slot (0x4d87b0); pending
  // that virtual's recovery, field_14 stays -1 and this reports failure.
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053fe10
TMission* TInvadeMission::GetReplacementSlot48() {
  field_14 = static_cast<short>(0xffff);
  return TAttackProvinceMission::GetReplacementSlot48();
}
