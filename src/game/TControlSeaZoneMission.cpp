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
// RefreshMissionPortZoneContextForNation's per-nation owner cache reuses
// TZone::primaryNeighbors slot 0 (TZone::field_0x28/0x2c/0x30 in the Ghidra
// decompile), now modeled as a real TZonePrimaryNeighborStretch member.

#include "game/TControlSeaZoneMission.h"
#include "game/TAutoGreatPower.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TOcean.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TStream.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TControlSeaZoneMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x005386c0
// TControlSeaZoneMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x00538780
// TControlSeaZoneMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x005355f0
// TControlSeaZoneMission::`scalar deleting destructor'

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
// FUNCTION: IMPERIALISM 0x00535620
TControlSeaZoneMission::~TControlSeaZoneMission() {}

// FUNCTION: IMPERIALISM 0x005387f0
void TControlSeaZoneMission::Call30() {
  float score = static_cast<float>(targetZone14->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    // NOTE: original also refreshes a lazily-allocated per-zone owner cache
    // here (TZone field_0x28/0x2c/0x30); pending TZone recovery of that cache,
    // the owner-nation gate below is approximated as always-false.
    (void)zone;
  }

  marker11 = 0;
  value0c = score / g_fMissionScoreNormalizationDivisor;
}

// Inherited unchanged by TBeachheadMission (real base class relationship).
// Confirms this mission's nation has terrain coverage: scans g_apTerrainTypeDescriptorTable
// for a nation that either IS this mission's nation or has an encoded-slot match with it, then
// checks whether targetZone18 lists that nation among its secondary neighbors. If no terrain
// coverage is found, clears this nation's per-context flag and returns null (mission invalid).
// Otherwise, if targetZone18 is a port zone that doesn't already flag this nation, refreshes
// targetZone18 via RefreshMissionPortZoneContextForNation; returns `this` iff targetZone18 ends
// up non-null.
// FUNCTION: IMPERIALISM 0x00538900
TMission* TControlSeaZoneMission::GetReplacementSlot48() {
  bool foundCoverage = false;
  for (int terrainIndex = 0; terrainIndex < kTerrainTypeDescriptorTableCount; ++terrainIndex) {
    TCountry* nation = g_apTerrainTypeDescriptorTable[terrainIndex];
    if (nation == nullptr) {
      continue;
    }
    if (terrainIndex != nationId04 && !nation->IsEncodedNationSlotMinus200Equal(nationId04)) {
      continue;
    }
    if (targetZone18->HasSecondaryNeighborWithNationTag(static_cast<short>(terrainIndex))) {
      foundCoverage = true;
      break;
    }
  }

  if (!foundCoverage) {
    // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
    TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
    nationState->AssertValid();
    short contextOrdinal = targetZone18->GetContextOrdinalOrInvalid();
    nationState->SetByteFlagAtOffsetAF0ByIndex(contextOrdinal, 0);
    return nullptr;
  }

  if (targetZone18 != nullptr && targetZone18->QueryPortZoneCapability() &&
      !targetZone18->QueryZoneCapabilityFlagD(nationId04)) {
    targetZone18 = RefreshMissionPortZoneContextForNation();
  }

  return (targetZone18 != nullptr) ? this : nullptr;
}

// Inherited unchanged by TBeachheadMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00538fe0
void TControlSeaZoneMission::SetStateByte8To2() {
  state08 = 3;
}

// Inherited unchanged by TBeachheadMission and TBlockadePortMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00539290
void TControlSeaZoneMission::ResetValue0CToZero() {
  float score = static_cast<float>(targetZone14->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    // See Call30 note above re: the per-zone owner cache.
    (void)zone;
  }

  value0c = score / g_fMissionScoreNormalizationDivisor;
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

// Resolves a port-zone context command into a queued order type. `pMapOrderEntry` is the
// TTaskForce map-order entry MissionSlot44's dispatch passed (navyField20). Builds a per-nation
// bitmask of nations with an outdated war-relation timestamp against this mission's nation,
// tracking the first such nation's port-zone context whose cached owner (primaryNeighbors slot
// 0) matches the entry's contextAnchor (reinterpreted as a TZone*). If the entry's own target
// context (also contextAnchor) has none of those nations already flagged AND a matching context
// was found, queues map-order type 6 with that context; otherwise queues type 3.
// FUNCTION: IMPERIALISM 0x00539640
void TControlSeaZoneMission::NoOpSlot9C(void* pMapOrderEntry) {
  TTaskForce* mapOrderEntry = static_cast<TTaskForce*>(pMapOrderEntry);
  mapOrderEntry->ResetOrderTypeAndStrengthDword(1);

  int nationBitmask = 0;
  TZone* firstMatchContext = nullptr;
  for (int nation = 0; nation < 7; ++nation) {
    if (g_pDiplomacyTurnStateManager->HasOutdatedWarRelationSlot48(nation, nationId04)) {
      nationBitmask |= 1 << nation;
      TZone* portZone =
          g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(nation));
      TZone** cachedOwnerSlot = portZone->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0);
      if (*cachedOwnerSlot == reinterpret_cast<TZone*>(mapOrderEntry->contextAnchor)) {
        firstMatchContext =
            g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(nation));
      }
    }
  }

  TZone* entryContext = reinterpret_cast<TZone*>(mapOrderEntry->contextAnchor);
  if ((entryContext->nationKeyMask10 & nationBitmask) == 0 && firstMatchContext != nullptr) {
    mapOrderEntry->SetMapOrderType6AndQueue(reinterpret_cast<int>(firstMatchContext));
    return;
  }
  mapOrderEntry->SetMapOrderType3Or4AndQueue(0);
}

// Inherited unchanged by TBeachheadMission and TBlockadePortMission (real base class relationship).
// Caches this mission's target port zone into the first port zone's primaryNeighbors slot 0
// (a per-nation "current port zone owner" cache slot, not a real neighbor list entry -- ground
// truth forces the slot to exist via EnsureSlotAllocatedAndReturnPointer(0) unconditionally).
// If that cached slot still points at targetZone14, just re-touches the port zone lookup and
// returns its result; otherwise returns the best-scoring neighbor via SelectBestPrimaryNeighbor-
// ForNationDiplomacyMask. GetReplacementSlot48 (0x538900) consumes this return value (stores it
// back into targetZone18), so it is no longer discarded.
// FUNCTION: IMPERIALISM 0x00539780
TZone* TControlSeaZoneMission::RefreshMissionPortZoneContextForNation() {
  TZone* firstPortZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId04);
  TZone** cachedOwnerSlot = firstPortZone->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0);
  if (*cachedOwnerSlot == targetZone14) {
    return g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId04);
  }
  return targetZone14->SelectBestPrimaryNeighborForNationDiplomacyMask(nationId04);
}
