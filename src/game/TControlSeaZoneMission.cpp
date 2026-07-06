// TControlSeaZoneMission implementations.
//
// TBeachheadMission and TBlockadePortMission both derive from this class
// (confirmed via RTTI CRuntimeClass ancestry), not from TNavyMission directly.
// Several overrides here (Call30, SetStateByte8To2, ResetValue0CToZero,
// GetReplacementSlot48, RefreshMissionPortZoneContextForNation) are therefore
// inherited unchanged by TBeachheadMission and/or TBlockadePortMission rather
// than being separately overridden there -- this file owns the `//
// FUNCTION:` marker for each.
//
// The port-zone-ownership lookup these functions perform walks a lazily
// allocated per-TZone owner cache (TZone::field_0x28/0x2c/0x30 in the Ghidra
// decompile) that is not yet modeled as a TZone member; that cache
// maintenance is approximated here pending TZone recovery of those fields.

#include "game/TControlSeaZoneMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TShip.h"
#include "game/TStream.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TControlSeaZoneMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x00538780
// TControlSeaZoneMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x005355f0
// TControlSeaZoneMission::`scalar deleting destructor'

// Not-yet-recovered free functions/subsystems this file calls into.
extern undefined4 GetPortZoneOwnerNationCodeFromMissionField48(void);
extern undefined4 FindFirstPortZoneContextByNation(void);
extern undefined4 SelectBestMapActionContextForNationDiplomacyMask(void);
extern undefined4 SetTaskForceOwnerPointer(void);
extern undefined4 SetMapOrderType3Or4AndQueue(void);
extern undefined4 SetByteFlagAtOffsetAF0ByIndex(void);

TControlSeaZoneMission::TControlSeaZoneMission() : TNavyMission() {}

TControlSeaZoneMission::TControlSeaZoneMission(TZone* targetZone) : TNavyMission(targetZone) {}

// FUNCTION: IMPERIALISM 0x005355b0
char TControlSeaZoneMission::ReturnFalseSlot64() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x005355d0
char TControlSeaZoneMission::ReturnFalseSlot60() {
  return 0;
}

// Inherited unchanged by TBeachheadMission (real base class relationship).
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

// Inherited unchanged by TBeachheadMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00538900
TMission* TControlSeaZoneMission::GetReplacementSlot48() {
  // TODO: ValidateMissionTerrainCoverageAndRefreshTargetContext -- pending
  // recovery of g_apTerrainTypeDescriptorTable diplomacy-match traversal.
  return nullptr;
}

// Inherited unchanged by TBeachheadMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00538fe0
void TControlSeaZoneMission::SetStateByte8To2() {
  state08 = 3;
}

// Inherited unchanged by TBeachheadMission and TBlockadePortMission (real base class relationship).
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
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* node = GetNavyPrimaryOrderListHead(); node != nullptr; node = node->nextOlder24) {
    if (node->field08 != targetZone14) {
      continue;
    }
    if (!g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationId04,
                                                                 node->ownerNationSlot14)) {
      continue;
    }
    short normalizationBase = node->GetNavyOrderNormalizationBaseByNationType();
    float scale = static_cast<float>(node->stockLevel1c / normalizationBase);
    vector[0] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(0)) * scale;
    vector[1] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(1)) * scale;
    vector[2] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(2)) * scale;
    vector[3] += static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(3));
  }

  const unsigned short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
  float sum = vector[0] + vector[1] + vector[2] + vector[3];
  float total = 0.0f;
  if (sum != 0.0f) {
    float delta = 0.0f;
    for (int i = 0; i < 4; ++i) {
      float diff = vector[i] / sum - static_cast<float>(static_cast<short>(lookupTable[i])) * 0.01f;
      if (diff <= 0.0f) {
        diff = -diff;
      }
      delta += diff;
    }
    total = sum * (1.0f - delta * 0.5f);
  }
  total *= 1.1f;
  if (total == 0.0f) {
    total = 100.0f;
  }

  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = static_cast<float>(static_cast<short>(lookupTable[i])) * total * 0.01f;
  }
}

// FUNCTION: IMPERIALISM 0x00539600
char TControlSeaZoneMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if ((kind == 0 || kind == 3) && key == reinterpret_cast<int>(targetZone14)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00539640
void TControlSeaZoneMission::NoOpSlot9C() {
  // TODO: ResolveAndQueuePortZoneMapOrder -- pending recovery of the
  // nation-bitmask + port-zone-context selection helpers.
}

// Inherited unchanged by TBeachheadMission and TBlockadePortMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00539780
void TControlSeaZoneMission::RefreshMissionPortZoneContextForNation() {
  // TODO: ResolveAndCacheMissionPortZoneContextForNationTarget -- pending
  // recovery of the per-zone owner cache and diplomacy-mask selection.
}
