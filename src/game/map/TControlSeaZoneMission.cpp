// TControlSeaZoneMission implementations.
//
// TBeachheadMission and TBlockadePortMission both derive from this class
// (confirmed via RTTI CRuntimeClass ancestry), not from TNavyMission directly.
// Several overrides here (Initialize, SetStateByte8To2, CalculateImportance,
// GetReplacementSlot48, RefreshMissionPortZoneContextForNation) are therefore
// inherited unchanged by TBeachheadMission and/or TBlockadePortMission rather
// than being separately overridden there -- this file owns the `//
// FUNCTION:` marker for each.
//
// RefreshMissionPortZoneContextForNation's per-nation owner cache reuses
// TZone::primaryNeighbors slot 0 (TZone::field_0x28/0x2c/0x30 in the Ghidra
// decompile), now modeled as a real TZonePrimaryNeighborStretch member.

#include "game/map/TControlSeaZoneMission.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/core/TStream.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

// The archive extraction operator below is emitted by IMPLEMENT_SERIAL:
//   CArchive& AFXAPI operator>>(CArchive&, TControlSeaZoneMission*&)
// SYNTHETIC: IMPERIALISM 0x005387c0
// operator>>
IMPLEMENT_SERIAL(TControlSeaZoneMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x005386c0
// TControlSeaZoneMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x00538780
// TControlSeaZoneMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x005355f0
// TControlSeaZoneMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005355b0
bool TControlSeaZoneMission::IsHospitalMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x005355d0
bool TControlSeaZoneMission::IsDefensiveSeaZoneMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x005387f0
void TControlSeaZoneMission::Initialize() {
  float score = static_cast<float>(missionTargetZone->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    TZone** ownerSlot = &zone->primaryNeighbors[0];
    if (*ownerSlot == missionTargetZone) {
      score *= (zone->GetPortZoneOwnerNationCodeFromMissionField48() == nationId04)
                   ? g_PortZoneFriendlyMissionScoreMultiplier_0065AA10
                   : g_PortZoneForeignMissionScoreMultiplier_0065AA18;
    }
  }

  marker11 = 0;
  importanceScore0c = score / g_fMissionScoreNormalizationDivisor;
}

// Inherited unchanged by TBeachheadMission (real base class relationship).
// Confirms this mission's nation has terrain coverage: scans g_apTerrainTypeDescriptorTable
// for a nation that either IS this mission's nation or has an encoded-slot match with it, then
// checks whether missionTargetZone lists that nation among its secondary neighbors. If no terrain
// coverage is found, clears this nation's per-context flag and returns null (mission invalid).
// Otherwise, if resolvedPortZone is a port zone that doesn't already flag this nation, refreshes
// resolvedPortZone via RefreshMissionPortZoneContextForNation; returns `this` iff resolvedPortZone ends
// up non-null.
// FUNCTION: IMPERIALISM 0x00538900
TMission* TControlSeaZoneMission::GetReplacementSlot48() {
  bool foundCoverage = false;
  for (int terrainIndex = 0; terrainIndex < kTerrainTypeDescriptorTableCount; ++terrainIndex) {
    TCountry* nation = g_apTerrainTypeDescriptorTable[terrainIndex];
    if (nation == nullptr) {
      continue;
    }
    if (terrainIndex != nationId04 && !nation->IsColonyOf(nationId04)) {
      continue;
    }
    if (missionTargetZone->HasSecondaryNeighborWithNationTag(static_cast<short>(terrainIndex))) {
      foundCoverage = true;
      break;
    }
  }

  if (!foundCoverage) {
    // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
    TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
    nationState->AssertValid();
    short contextOrdinal = missionTargetZone->GetContextOrdinalOrInvalid();
    nationState->SetByteFlagAtOffsetAF0ByIndex(contextOrdinal, 0);
    return nullptr;
  }

  if (resolvedPortZone != nullptr && resolvedPortZone->QueryPortZoneCapability() &&
      !resolvedPortZone->QueryZoneCapabilityFlagD(nationId04)) {
    resolvedPortZone = RefreshMissionPortZoneContextForNation();
  }

  return (resolvedPortZone != nullptr) ? this : nullptr;
}

// Inherited unchanged by TBeachheadMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00538fe0
void TControlSeaZoneMission::SetStateByte8To2() {
  TZone* homePort = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId04);
  TZone** ownerSlot = &homePort->primaryNeighbors[0];
  if (*ownerSlot == missionTargetZone) {
    float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
      if (ship->location != missionTargetZone ||
          !g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId04, ship->nation)) {
        continue;
      }

      short normalizationBase = ship->GetMaxStrength();
      float scale = static_cast<float>(ship->strength / normalizationBase);
      vector[0] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
          scale;
      vector[1] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
          scale;
      vector[2] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
          scale;
      vector[3] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3));
    }

    float total = vector[0] + vector[1] + vector[2] + vector[3];
    float similarity = 0.0f;
    if (total != 0.0f) {
      float divergence = 0.0f;
      for (int i = 0; i < 4; ++i) {
        float delta = vector[i] / total -
                      static_cast<float>(g_Populate_Beachhead_Mission_LookupTable_00697958[i]) *
                          g_Recompute_Nation_Order_LookupTable_0065A9F8;
        if (delta <= 0.0f) {
          delta = -delta;
        }
        divergence += delta;
      }
      similarity = total * (g_Recompute_Nation_Order_LookupTable_0065AA08 -
                            divergence * g_Recompute_Nation_Order_LookupTable_0065AA00);
    }
    if (similarity > 0.0f) {
      state08 = 1;
      return;
    }
  }
  state08 = 2;
}

// Inherited unchanged by TBeachheadMission and TBlockadePortMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00539290
void TControlSeaZoneMission::CalculateImportance() {
  float score = static_cast<float>(missionTargetZone->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    TZone** ownerSlot = &zone->primaryNeighbors[0];
    if (*ownerSlot == missionTargetZone) {
      score *= (zone->GetPortZoneOwnerNationCodeFromMissionField48() == nationId04)
                   ? g_PortZoneFriendlyMissionScoreMultiplier_0065AA10
                   : g_PortZoneForeignMissionScoreMultiplier_0065AA18;
    }
  }

  importanceScore0c = score / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x005393a0
void TControlSeaZoneMission::CalculateNeeds() {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* node = TShip::GetFirst(); node != nullptr; node = node->next) {
    if (node->location != missionTargetZone) {
      continue;
    }
    if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId04, node->nation)) {
      continue;
    }
    short normalizationBase = node->GetMaxStrength();
    float scale = static_cast<float>(node->strength / normalizationBase);
    vector[0] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(0)) * scale;
    vector[1] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(1)) * scale;
    vector[2] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(2)) * scale;
    vector[3] += static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(3));
  }

  const short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
  float sum = vector[0] + vector[1] + vector[2] + vector[3];
  float total = 0.0f;
  if (sum != 0.0f) {
    float delta = 0.0f;
    for (int i = 0; i < 4; ++i) {
      float diff = vector[i] / sum - static_cast<float>(static_cast<short>(lookupTable[i])) *
                                         g_Recompute_Nation_Order_LookupTable_0065A9F8;
      if (diff <= 0.0f) {
        diff = -diff;
      }
      delta += diff;
    }
    total = sum * (1.0f - delta * 0.5f);
  }
  total *= g_MissionResourceWeightScale_0065A8FC;
  if (total == 0.0f) {
    total = g_MissionEmptyResourceWeight_0065AA24;
  }

  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] = static_cast<float>(static_cast<short>(lookupTable[i])) *
                                        total * g_Recompute_Nation_Order_LookupTable_0065A9F8;
  }
}

// FUNCTION: IMPERIALISM 0x00539600
bool TControlSeaZoneMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  (void)key;
  return (missionType == kMissionTypeAttackProvince || missionType == kMissionTypeDefendProvince) &&
         zoneContext == missionTargetZone;
}

// Resolves a port-zone context command into a queued order type. `pMapOrderEntry` is the
// TTaskForce map-order entry GiveOrders's dispatch passed (taskForce20). Builds a per-nation
// bitmask of nations with an outdated war-relation timestamp against this mission's nation,
// tracking the first such nation's port-zone context whose cached owner (primaryNeighbors slot
// 0) matches the entry's location (a TZone*). If the entry's own target
// context (also location) has none of those nations already flagged AND a matching context
// was found, queues map-order type 6 with that context; otherwise queues type 3.
// FUNCTION: IMPERIALISM 0x00539640
void TControlSeaZoneMission::GiveActionOrders(TTaskForce* mapOrderEntry) {
  mapOrderEntry->SetAggression(1);

  int nationBitmask = 0;
  TZone* firstMatchContext = nullptr;
  for (int nation = 0; nation < 7; ++nation) {
    if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(nation, nationId04)) {
      nationBitmask |= 1 << nation;
      TZone* portZone =
          g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(nation));
      TZone** cachedOwnerSlot = &portZone->primaryNeighbors[0];
      if (*cachedOwnerSlot == mapOrderEntry->location) {
        firstMatchContext =
            g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(nation));
      }
    }
  }

  TZone* entryContext = mapOrderEntry->location;
  if ((entryContext->nationKeyMask10 & nationBitmask) == 0 && firstMatchContext != nullptr) {
    mapOrderEntry->OrderBlockade(firstMatchContext);
    return;
  }
  mapOrderEntry->OrderPatrol(0);
}

// Inherited unchanged by TBeachheadMission and TBlockadePortMission (real base class relationship).
// Caches this mission's target port zone into the first port zone's primaryNeighbors slot 0
// (a per-nation "current port zone owner" cache slot, not a real neighbor list entry -- ground
// truth forces the slot to exist through grow-on-access operator[] unconditionally).
// If that cached slot still points at missionTargetZone, just re-touches the port zone lookup and
// returns its result; otherwise returns the safest nearby zone for the mission nation.
// FUNCTION: IMPERIALISM 0x00539780
TZone* TControlSeaZoneMission::RefreshMissionPortZoneContextForNation() {
  TZone* firstPortZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId04);
  TZone** cachedOwnerSlot = &firstPortZone->primaryNeighbors[0];
  if (*cachedOwnerSlot == missionTargetZone) {
    return g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId04);
  }
  return missionTargetZone->GetSafestNearbyZoneFor(nationId04);
}
