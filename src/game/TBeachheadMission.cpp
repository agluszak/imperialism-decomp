// TBeachheadMission implementations.
//
// Several overrides here are COMDAT-folded in the original binary with
// TControlSeaZoneMission (and, for ResetValue0CToZero, also
// TBlockadePortMission); TControlSeaZoneMission.cpp owns the `// FUNCTION:`
// marker for those shared addresses (including SetStateByte8To2's
// 0x00538fe0). See the notes there.

#include "game/TBeachheadMission.h"
#include "game/TAttackProvinceMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TZone.h"

IMPLEMENT_SERIAL(TBeachheadMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053a420
// TBeachheadMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053a3d0 (approx -- see symbols.csv)
// TBeachheadMission::`scalar deleting destructor'

TBeachheadMission::TBeachheadMission() : TNavyMission(), parentMission3c(nullptr) {}

TBeachheadMission::TBeachheadMission(TZone* targetZone, TAttackProvinceMission* parentMission)
    : TNavyMission(targetZone), parentMission3c(parentMission) {}

// Shared with TControlSeaZoneMission (COMDAT-folded body; see
// TControlSeaZoneMission::Call30).
void TBeachheadMission::Call30() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());
  marker11 = 0;
  *reinterpret_cast<float*>(&value0c) = score / *reinterpret_cast<const float*>(0x0065a9c0);
}

// Shared with TControlSeaZoneMission (COMDAT-folded body; see
// TControlSeaZoneMission::SetStateByte8To2).
void TBeachheadMission::SetStateByte8To2() {
  state08 = 3;
}

// Shared with TControlSeaZoneMission and TBlockadePortMission (COMDAT-folded
// body; see TControlSeaZoneMission::ResetValue0CToZero).
void TBeachheadMission::ResetValue0CToZero() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());
  *reinterpret_cast<float*>(&value0c) = score / *reinterpret_cast<const float*>(0x0065a9c0);
}

// FUNCTION: IMPERIALISM 0x0053a500
void TBeachheadMission::NoOpSlot3C() {
  // TODO: PopulateBeachheadMissionResourceWeightsFromNavyContext -- pending
  // recovery of the navy-order-list traversal and category tables.
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// Shared with TControlSeaZoneMission (COMDAT-folded body; see
// TControlSeaZoneMission::GetReplacementSlot48).
TMission* TBeachheadMission::GetReplacementSlot48() {
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0053a7b0
char TBeachheadMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if (kind == 2 && key != -1 && parentMission3c != nullptr &&
      static_cast<short>(key) ==
          *reinterpret_cast<short*>(reinterpret_cast<char*>(parentMission3c) + 0x30)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053a920
int TBeachheadMission::ReturnZeroSlot58() {
  return reinterpret_cast<int>(parentMission3c);
}

// FUNCTION: IMPERIALISM 0x0053a3b0
char TBeachheadMission::ReturnFalseSlot60() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053a390
char TBeachheadMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053a940
char TBeachheadMission::ReturnFalseSlot98() {
  // ClearBlockadePortMissionChildOrderLinksIfReady: clears each queued
  // order-child's owner-back-pointer, then frees the chain.
  if (marker11 == 0 && navyField20 != nullptr) {
    return 0;
  }
  orderList24 = nullptr;
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053a800
void TBeachheadMission::NoOpSlot9C() {
  // TODO: TryQueueProvinceOrderFromContextMessage -- pending recovery.
}

// Shared with TControlSeaZoneMission and TBlockadePortMission (COMDAT-folded
// body; see TControlSeaZoneMission::RefreshMissionPortZoneContextForNation).
void TBeachheadMission::RefreshMissionPortZoneContextForNation() {}
