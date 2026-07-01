// TControlSeaZoneMission implementations.
//
// Several overrides here (Call30, ResetValue0CToZero, GetReplacementSlot48,
// RefreshMissionPortZoneContextForNation) are COMDAT-folded in the original
// binary with identical bodies on TBeachheadMission and/or TBlockadePortMission
// (see the `// Shared with ...` notes on each). This file owns the
// `// FUNCTION:` marker for the shared address; the sibling classes implement
// the same logic without redeclaring the marker.
//
// The port-zone-ownership lookup these functions perform walks a lazily
// allocated per-TZone owner cache (TZone::field_0x28/0x2c/0x30 in the Ghidra
// decompile) that is not yet modeled as a TZone member; that cache
// maintenance is approximated here pending TZone recovery of those fields.

#include "game/TControlSeaZoneMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TControlSeaZoneMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x00538780
// TControlSeaZoneMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x005355f0
// TControlSeaZoneMission::`scalar deleting destructor'

extern "C" {
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0;
}

// Not-yet-recovered free functions/subsystems this file calls into.
extern undefined4 GetPortZoneOwnerNationCodeFromMissionField48(void);
extern undefined4 FindFirstPortZoneContextByNation(void);
extern undefined4 SelectBestMapActionContextForNationDiplomacyMask(void);
extern undefined4 SetTaskForceOwnerPointer(void);
extern undefined4 SetMapOrderType3Or4AndQueue(void);
extern undefined4 ContainsPointerArrayEntryMatchingByteKey(void);
extern undefined4 GetShortAtOffset14OrInvalid(void);
extern undefined4 SetByteFlagAtOffsetAF0ByIndex(void);

TControlSeaZoneMission::TControlSeaZoneMission() : TNavyMission() {}

TControlSeaZoneMission::TControlSeaZoneMission(TZone* targetZone) : TNavyMission(targetZone) {}

// Shared with TBeachheadMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x005387f0
void TControlSeaZoneMission::Call30() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    // NOTE: original also refreshes a lazily-allocated per-zone owner cache
    // here (TZone field_0x28/0x2c/0x30); pending TZone recovery of that cache,
    // the owner-nation gate below is approximated as always-false.
    (void)zone;
  }

  marker11 = 0;
  *reinterpret_cast<float*>(&value0c) = score / *reinterpret_cast<const float*>(0x0065a9c0);
}

// Shared with TBeachheadMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x00538fe0
void TControlSeaZoneMission::SetStateByte8To2() {
  state08 = 3;
}

// Shared with TBeachheadMission and TBlockadePortMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x00539290
void TControlSeaZoneMission::ResetValue0CToZero() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    // See Call30 note above re: the per-zone owner cache.
    (void)zone;
  }

  *reinterpret_cast<float*>(&value0c) = score / *reinterpret_cast<const float*>(0x0065a9c0);
}

// FUNCTION: IMPERIALISM 0x005393a0
void TControlSeaZoneMission::NoOpSlot3C() {
  // TODO: PopulateControlSeaZoneMissionResourceWeightsFromAlliedNavyPressure --
  // pending recovery of the navy-order-list traversal and category tables.
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// Shared with TBeachheadMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x00538900
TMission* TControlSeaZoneMission::GetReplacementSlot48() {
  // TODO: ValidateMissionTerrainCoverageAndRefreshTargetContext -- pending
  // recovery of g_apTerrainTypeDescriptorTable diplomacy-match traversal.
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00539600
char TControlSeaZoneMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if ((kind == 0 || kind == 3) && key == reinterpret_cast<int>(targetZone14)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005355d0
char TControlSeaZoneMission::ReturnFalseSlot60() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005355b0
char TControlSeaZoneMission::ReturnFalseSlot64() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00539640
void TControlSeaZoneMission::NoOpSlot9C() {
  // TODO: ResolveAndQueuePortZoneMapOrder -- pending recovery of the
  // nation-bitmask + port-zone-context selection helpers.
}

// Shared with TBeachheadMission and TBlockadePortMission (COMDAT-folded body).
// FUNCTION: IMPERIALISM 0x00539780
void TControlSeaZoneMission::RefreshMissionPortZoneContextForNation() {
  // TODO: ResolveAndCacheMissionPortZoneContextForNationTarget -- pending
  // recovery of the per-zone owner cache and diplomacy-mask selection.
}
