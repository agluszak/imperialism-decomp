// TBlockadePortMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBlockadePortMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// ResetValue0CToZero and RefreshMissionPortZoneContextForNation are NOT
// overridden here -- they're inherited unchanged from TControlSeaZoneMission,
// which owns their `// FUNCTION:` markers. Call30 here is a genuinely distinct
// own override (RecomputeAndClearMissionScoreUsingPortZoneContextAverageVariantB).

#include "game/TBlockadePortMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TTaskForce.h"
#include "game/TZone.h"

IMPLEMENT_SERIAL(TBlockadePortMission, TControlSeaZoneMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053a990
// TBlockadePortMission::CreateObject

// FUNCTION: IMPERIALISM 0x0053aa50
char TBlockadePortMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053aa70
char TBlockadePortMission::ReturnFalseSlot60() {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0053aa90
// TBlockadePortMission::`scalar deleting destructor'

TBlockadePortMission::TBlockadePortMission()
    : TControlSeaZoneMission(), portZoneContext3c(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x0053aae0
// TBlockadePortMission::GetRuntimeClass

// The mission factory (CreateMissionObjectByKindAndNodeContext, case 4) builds a
// blockade mission from a map-order context node (a TZone). It lazily ensures the
// context's primaryNeighbors array has slot 0 allocated -- that first entry is the
// target port zone -- constructs the TControlSeaZoneMission base on it, back-links
// the context node into portZoneContext3c (+0x3c), and validates the context.
// FUNCTION: IMPERIALISM 0x0053ab50
TBlockadePortMission::TBlockadePortMission(TZone* context)
    : TControlSeaZoneMission(*context->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0)),
      portZoneContext3c(context) {
  context->AssertValid();
}

// FUNCTION: IMPERIALISM 0x0053ac60
void TBlockadePortMission::WriteTo(TStream* stream) {
  TNavyMission::WriteTo(stream);
  // TODO: also serializes the port-zone-context node id (via a stream helper
  // at CArchive-like vtable slot 0x88); pending recovery of that helper.
}

// FUNCTION: IMPERIALISM 0x0053aca0
void TBlockadePortMission::ReadFrom(TStream* stream) {
  TNavyMission::ReadFrom(stream);
  portZoneContext3c = FindMapActionContextByNodeId(stream->ReadShort());
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
  *reinterpret_cast<float*>(&value0c) = score / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x0053adf0
TMission* TBlockadePortMission::GetReplacementSlot48() {
  // TODO: ValidateBlockadePortMissionContextAndRefreshChild -- pending
  // recovery of the per-nation "task force" gate array.
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0053ae90
void TBlockadePortMission::SetStateByte8To2() {
  state08 = 3;
}

// FUNCTION: IMPERIALISM 0x0053aeb0
void TBlockadePortMission::NoOpSlot3C() {
  // TODO: PopulateBlockadePortMissionResourceWeightsFromNavyContext -- pending
  // recovery of the navy-order-list traversal and category tables.
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053ba10
char TBlockadePortMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)key;
  // Original (0x53ba10) compares the third argument against the inherited
  // targetZone14 pointer, not the second argument against portZoneContext3c.
  if (kind == 4 && mode == reinterpret_cast<int>(targetZone14)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053ba40
void TBlockadePortMission::NoOpSlot9C(void* pMapOrderEntry) {
  static_cast<TTaskForce*>(pMapOrderEntry)
      ->SetMapOrderType6AndQueue(reinterpret_cast<int>(portZoneContext3c));
}
