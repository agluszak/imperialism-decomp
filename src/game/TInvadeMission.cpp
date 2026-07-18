// TInvadeMission implementations.

#include "game/TInvadeMission.h"

#include "game/global_data_tables.h"
#include "game/CIterator.h"
#include "game/TBeachheadMission.h"
#include "game/TGlobalMapState.h"
#include "game/TMilitaryUnit.h"
#include "game/TStream.h"

IMPLEMENT_SERIAL(TInvadeMission, TAttackProvinceMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053f080
// TInvadeMission::CreateObject

// FUNCTION: IMPERIALISM 0x0053f120
TMission* TInvadeMission::ReturnZeroSlot5C() {
  return beachhead34;
}

// FUNCTION: IMPERIALISM 0x0053f140
char TInvadeMission::ReturnFalseSlot54() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053f160
void TInvadeMission::NoOpSlot90(void* a) {
  if (beachhead34 != nullptr) {
    beachhead34->NoOpSlot90(a);
  }
}

// FUNCTION: IMPERIALISM 0x0053f190
void TInvadeMission::NoOpSlot84(void* a, int b) {
  if (beachhead34 != nullptr) {
    beachhead34->NoOpSlot84(a, b);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1c0
void TInvadeMission::NoOpSlot8C(void* a, int b) {
  if (beachhead34 != nullptr) {
    beachhead34->NoOpSlot8C(a, b);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1f0
float TInvadeMission::ReturnZeroFloatSlot6C() {
  return TArmyMission::ReturnZeroFloatSlot6C() + beachhead34->ReturnZeroFloatSlot6C();
}

// FUNCTION: IMPERIALISM 0x0053f240
char TInvadeMission::ReturnFalseSlot64() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x0053f260
// TInvadeMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x0053f2d0
TInvadeMission::TInvadeMission(short targetProvince, TZone* beachheadZone)
    : TAttackProvinceMission(targetProvince, -1), beachhead34(nullptr) {
  if (beachheadZone != nullptr) {
    beachhead34 = new TBeachheadMission(beachheadZone, this);
  }
}
// SYNTHETIC: IMPERIALISM 0x0053f3c0
// TInvadeMission::`scalar deleting destructor'

TInvadeMission::TInvadeMission() : TAttackProvinceMission(), beachhead34(nullptr) {}

// FUNCTION: IMPERIALISM 0x0053f410
void TInvadeMission::Free() {
  if (beachhead34 != nullptr) {
    beachhead34->Free();
    beachhead34 = nullptr;
  }
  TAttackProvinceMission::Free();
}

// Matches the original exactly: unconditionally dereferences beachhead34 (no null check),
// so this is only ever called on an instance with a live beachhead child.
// FUNCTION: IMPERIALISM 0x0053f4e0
char TInvadeMission::ReturnFalseSlot98() {
  if (!beachhead34->ReturnFalseSlot98()) {
    return 0;
  }
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->GetUnitMovementClassId() != 0) {
      NoOpSlot88(unit, 1);
    }
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
  beachhead34->RefreshSlot40();
  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();
}

// FUNCTION: IMPERIALISM 0x0053faa0
char TInvadeMission::ReturnFalseSlot50() {
  return 1;
}

// Same shape as TArmyMission::ReturnZeroFloatSlot70, but the "not this mission's own unit"
// branch is scaled down by 0.1 unless ReturnFalseSlot50() says otherwise (TInvadeMission's
// own override always returns true, so the scale-down never actually triggers here -- kept
// as a real virtual dispatch to match the original rather than hardcoding).
// FUNCTION: IMPERIALISM 0x0053fac0
float TInvadeMission::ReturnZeroFloatSlot70(TMilitaryUnit* candidateUnit) {
  float delta;
  if (flag10 != 0) {
    delta = 0.0f;
  } else if (candidateUnit->ownerMission40 == this) {
    delta = ReturnZeroFloatSlot68() -
            ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(candidateUnit);
  } else {
    delta = ComputeArmyMissionScoreDeltaWithCandidateUnit(candidateUnit) - ReturnZeroFloatSlot68();
  }

  if (!ReturnFalseSlot50()) {
    delta *= 0.1f;
  }
  return delta;
}

// FUNCTION: IMPERIALISM 0x0053fb60
float TInvadeMission::ReturnZeroFloatSlot74(void* candidate) {
  if (flag10 != 0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  return beachhead34->ReturnZeroFloatSlot74(candidate);
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

// Same vector-accumulation + truncate-to-outBuffer shape as TArmyMission::ReturnZeroSlot2C
// (inlined here rather than calling the shared helper, matching this file's established
// per-callsite-inlining pattern), plus this override's own addition: the running total also
// folds in beachhead34->ReturnZeroSlot2C(outBuffer, unused) (vtable slot 0x2c, same slot).
// NOTE: the original's per-element rounding is a custom FPU round-half rule, not plain
// truncation (0x53fce9-0x53fd1c); approximated here as truncation pending that recovery.
// FUNCTION: IMPERIALISM 0x0053fc10
int TInvadeMission::ReturnZeroSlot2C(int* outBuffer, int unused) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
      TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
      unit->AssertValid();
      short weightIndex = unit->IsNotStationedInProvince(GetMissionTargetContextIdFromField14());
      if (weightIndex > 5) {
        weightIndex = 5;
      }
      AccumulateUnitOrderPriorityVectorContribution(
          unit, vector, g_ArmyMissionOrderWeightTable_006978c8[weightIndex],
          static_cast<float>(GetProvinceUnitOrderWeight(GetMissionTargetContextIdFromField14())));
    }
  }

  int total = 0;
  for (int i = 0; i < 5; ++i) {
    int rounded = static_cast<int>(vector[i]);
    outBuffer[i] = rounded;
    total += rounded;
  }

  return total + beachhead34->ReturnZeroSlot2C(outBuffer, unused);
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
