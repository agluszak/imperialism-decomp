// TBeachheadMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBeachheadMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// Call30 / SetStateByte8To2 / ResetValue0CToZero / GetReplacementSlot48 /
// RefreshMissionPortZoneContextForNation are NOT overridden here -- they're
// inherited unchanged from TControlSeaZoneMission, which owns their
// `// FUNCTION:` markers.

#include "game/TBeachheadMission.h"
#include "game/TAttackProvinceMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TZone.h"

IMPLEMENT_SERIAL(TBeachheadMission, TControlSeaZoneMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053a2d0
// TBeachheadMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053a420
// TBeachheadMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053a3d0 (approx -- see symbols.csv)
// TBeachheadMission::`scalar deleting destructor'

TBeachheadMission::TBeachheadMission() : TControlSeaZoneMission(), parentMission3c(nullptr) {}

TBeachheadMission::TBeachheadMission(TZone* targetZone, TAttackProvinceMission* parentMission)
    : TControlSeaZoneMission(targetZone), parentMission3c(parentMission) {}

// FUNCTION: IMPERIALISM 0x0053a390
char TBeachheadMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053a3b0
char TBeachheadMission::ReturnFalseSlot60() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053a500
void TBeachheadMission::NoOpSlot3C() {
  // TODO: PopulateBeachheadMissionResourceWeightsFromNavyContext -- pending
  // recovery of the navy-order-list traversal and category tables.
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
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

// FUNCTION: IMPERIALISM 0x0053a800
void TBeachheadMission::NoOpSlot9C(void* pMapOrderEntry) {
  // TODO: TryQueueProvinceOrderFromContextMessage -- pending recovery (bd 1uj.16.6).
  (void)pMapOrderEntry;
}

// FUNCTION: IMPERIALISM 0x0053a920
int TBeachheadMission::ReturnZeroSlot58() {
  return reinterpret_cast<int>(parentMission3c);
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
