// TBeachheadMission and TBlockadePortMission inherit several of these bodies unchanged.

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

IMPLEMENT_SERIAL(TControlSeaZoneMission, TNavyMission, 1)

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

  for (TZone* zone = TZone::GetFirstPortZone(); zone != NULL; zone = zone->GetNextPortZone()) {
    TZone** ownerSlot = &zone->primaryNeighbors[0];
    if (*ownerSlot == missionTargetZone) {
      score *= (zone->GetPortOwnerNation() == nationId) ? g_PortZoneFriendlyMissionScoreMultiplier
                                                        : g_PortZoneForeignMissionScoreMultiplier;
    }
  }

  marker11 = 0;
  importanceScore = score / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x00538900
TMission* TControlSeaZoneMission::GetReplacement() {
  bool foundCoverage = false;
  for (int terrainIndex = 0; terrainIndex < kTerrainTypeDescriptorTableCount; ++terrainIndex) {
    TCountry* nation = g_apTerrainTypeDescriptorTable[terrainIndex];
    if (nation == NULL) {
      continue;
    }
    if (terrainIndex != nationId && !nation->IsColonyOf(nationId)) {
      continue;
    }
    if (missionTargetZone->HasSecondaryNeighborWithNationTag(static_cast<short>(terrainIndex))) {
      foundCoverage = true;
      break;
    }
  }

  if (!foundCoverage) {
    // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
    TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId]);
    nationState->AssertValid();
    short contextOrdinal = missionTargetZone->GetContextOrdinalOrInvalid();
    nationState->SetZoneStatus(contextOrdinal, kMissionDesirabilityUnmarked);
    return NULL;
  }

  if (resolvedPortZone != NULL && resolvedPortZone->QueryPortZoneCapability() &&
      !resolvedPortZone->QueryZoneCapabilityFlagD(nationId)) {
    resolvedPortZone = RefreshMissionPortZoneContextForNation();
  }

  return (resolvedPortZone != NULL) ? this : NULL;
}

// Inherited unchanged by TBeachheadMission (real base class relationship).
// FUNCTION: IMPERIALISM 0x00538fe0
void TControlSeaZoneMission::SetStateByte8To2() {
  TZone* homePort = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId);
  TZone** ownerSlot = &homePort->primaryNeighbors[0];
  if (*ownerSlot == missionTargetZone) {
    float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (TShip* ship = TShip::GetFirst(); ship != NULL; ship = ship->next) {
      if (ship->location != missionTargetZone ||
          !g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, ship->nation)) {
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
                      static_cast<float>(g_Populate_Beachhead_Mission_LookupTable[i]) * 0.01;
        if (delta <= 0.0f) {
          delta = -delta;
        }
        divergence += delta;
      }
      similarity = total * (1.0 - divergence * 0.5);
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

  for (TZone* zone = TZone::GetFirstPortZone(); zone != NULL; zone = zone->GetNextPortZone()) {
    TZone** ownerSlot = &zone->primaryNeighbors[0];
    if (*ownerSlot == missionTargetZone) {
      score *= (zone->GetPortOwnerNation() == nationId) ? g_PortZoneFriendlyMissionScoreMultiplier
                                                        : g_PortZoneForeignMissionScoreMultiplier;
    }
  }

  importanceScore = score / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x00539600
bool TControlSeaZoneMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  return (missionType == kMissionTypeAttackProvince || missionType == kMissionTypeDefendProvince) &&
         zoneContext == missionTargetZone;
}

// FUNCTION: IMPERIALISM 0x00539640
void TControlSeaZoneMission::GiveActionOrders(TTaskForce* mapOrderEntry) {
  mapOrderEntry->SetAggression(1);

  int nationBitmask = 0;
  TZone* firstMatchContext = NULL;
  for (int nation = 0; nation < kMajorNationCount; ++nation) {
    if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(nation, nationId)) {
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
  if ((entryContext->nationKeyMask & nationBitmask) == 0 && firstMatchContext != NULL) {
    mapOrderEntry->OrderBlockade(firstMatchContext);
    return;
  }
  mapOrderEntry->OrderPatrol(false);
}

// FUNCTION: IMPERIALISM 0x00539780
TZone* TControlSeaZoneMission::RefreshMissionPortZoneContextForNation() {
  TZone* firstPortZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId);
  TZone** cachedOwnerSlot = &firstPortZone->primaryNeighbors[0];
  if (*cachedOwnerSlot == missionTargetZone) {
    return g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId);
  }
  return missionTargetZone->GetSafestNearbyZoneFor(nationId);
}
