// TBlockadePortMission implementations.
//
// ResetValue0CToZero and RefreshMissionPortZoneContextForNation are
// COMDAT-folded in the original binary with TControlSeaZoneMission (which
// owns those `// FUNCTION:` markers); see the notes there. Call30 here is a
// distinct address (RecomputeAndClearMissionScoreUsingPortZoneContextAverageVariantB)
// even though structurally identical.

#include "game/TBlockadePortMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TZone.h"

IMPLEMENT_SERIAL(TBlockadePortMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053aae0
// TBlockadePortMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053aa90
// TBlockadePortMission::`scalar deleting destructor'

// Not-yet-recovered free functions/subsystems this file calls into.
extern undefined4 FindMapActionContextByNodeId(void);
extern undefined4 GetPortZoneOwnerNationCodeFromMissionField48(void);
extern undefined4 SetByteFlagAtOffsetAF0ByIndex(void);

TBlockadePortMission::TBlockadePortMission() : TNavyMission(), portZoneContext3c(nullptr) {}

TBlockadePortMission::TBlockadePortMission(TZone* targetZone)
    : TNavyMission(targetZone), portZoneContext3c(nullptr) {}

// FUNCTION: IMPERIALISM 0x0053ac60
void TBlockadePortMission::WriteTo(TStream* stream) {
  TNavyMission::WriteTo(stream);
  // TODO: also serializes the port-zone-context node id (via a stream helper
  // at CArchive-like vtable slot 0x88); pending recovery of that helper.
}

// FUNCTION: IMPERIALISM 0x0053aca0
void TBlockadePortMission::ReadFrom(TStream* stream) {
  TNavyMission::ReadFrom(stream);
  typedef void* (__cdecl * FindMapActionContextByNodeId_t)(void);
  portZoneContext3c =
      reinterpret_cast<FindMapActionContextByNodeId_t>((void*)&FindMapActionContextByNodeId)();
}

// FUNCTION: IMPERIALISM 0x0053ace0
void TBlockadePortMission::Call30() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    // See TControlSeaZoneMission::Call30 -- per-zone owner cache not yet modeled.
    (void)zone;
  }

  marker11 = 0;
  *reinterpret_cast<float*>(&value0c) = score / *reinterpret_cast<const float*>(0x0065a9c0);
}

// FUNCTION: IMPERIALISM 0x0053ae90
void TBlockadePortMission::SetStateByte8To2() {
  state08 = 3;
}

// Shared with TBeachheadMission and TControlSeaZoneMission (COMDAT-folded
// body; see TControlSeaZoneMission::ResetValue0CToZero).
void TBlockadePortMission::ResetValue0CToZero() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());
  *reinterpret_cast<float*>(&value0c) = score / *reinterpret_cast<const float*>(0x0065a9c0);
}

// FUNCTION: IMPERIALISM 0x0053aeb0
void TBlockadePortMission::NoOpSlot3C() {
  // TODO: PopulateBlockadePortMissionResourceWeightsFromNavyContext -- pending
  // recovery of the navy-order-list traversal and category tables.
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053adf0
TMission* TBlockadePortMission::GetReplacementSlot48() {
  // TODO: ValidateBlockadePortMissionContextAndRefreshChild -- pending
  // recovery of the per-nation "task force" gate array.
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0053ba10
char TBlockadePortMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if (kind == 4 && key == reinterpret_cast<int>(portZoneContext3c)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053aa70
char TBlockadePortMission::ReturnFalseSlot60() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053aa50
char TBlockadePortMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053ba40
void TBlockadePortMission::NoOpSlot9C() {
  // TODO: QueueMapOrderType6FromContextPointer -- pending recovery.
}

// Shared with TBeachheadMission and TControlSeaZoneMission (COMDAT-folded
// body; see TControlSeaZoneMission::RefreshMissionPortZoneContextForNation).
void TBlockadePortMission::RefreshMissionPortZoneContextForNation() {}
