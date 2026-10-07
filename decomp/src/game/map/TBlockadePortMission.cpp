#include "game/tactical/TArmyPlayer.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/map/TBlockadePortMission.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/core/TStream.h"
#include "game/navy/TTaskForce.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_SERIAL(TBlockadePortMission, TControlSeaZoneMission, 1)

// FUNCTION: IMPERIALISM 0x0053aa50
bool TBlockadePortMission::IsHospitalMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053aa70
bool TBlockadePortMission::IsDefensiveSeaZoneMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053aac0
TBlockadePortMission::~TBlockadePortMission() {}

// FUNCTION: IMPERIALISM 0x0053ab50
TBlockadePortMission::TBlockadePortMission(TZone* context)
    : TControlSeaZoneMission(context->primaryNeighbors[0]), portZoneContext(context) {
  context->AssertValid();
}

// FUNCTION: IMPERIALISM 0x0053ac60
void TBlockadePortMission::WriteTo(TStream* stream) {
  TNavyMission::WriteTo(stream);
  stream->WriteInteger(portZoneContext->GetContextOrdinalOrInvalid());
}

// FUNCTION: IMPERIALISM 0x0053aca0
void TBlockadePortMission::ReadFrom(TStream* stream) {
  TNavyMission::ReadFrom(stream);
  portZoneContext = FindMapActionContextByNodeId(stream->ReadInteger());
}

// FUNCTION: IMPERIALISM 0x0053ace0
void TBlockadePortMission::Initialize() {
  float score = static_cast<float>(missionTargetZone->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    TZone** ownerSlot = &zone->primaryNeighbors[0];
    if (*ownerSlot == missionTargetZone) {
      score *= (zone->GetPortOwnerNation() == nationId) ? g_PortZoneFriendlyMissionScoreMultiplier
                                                        : g_PortZoneForeignMissionScoreMultiplier;
    }
  }

  marker11 = 0;
  importanceScore = score / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x0053adf0
TMission* TBlockadePortMission::GetReplacement() {
  TAutoGreatPower* nation = static_cast<TAutoGreatPower*>(g_apNationStates[nationId]);
  nation->AssertValid();
  short ownerCode = portZoneContext->GetPortOwnerNation();
  bool hasCoverage = nation->enemyFlags[ownerCode] != 0;

  if (!hasCoverage) {
    short contextOrdinal = portZoneContext->GetContextOrdinalOrInvalid();
    nation->SetZoneStatus(contextOrdinal, kMissionDesirabilityUnmarked);
    return nullptr;
  }

  if (resolvedPortZone != nullptr && resolvedPortZone->QueryPortZoneCapability() &&
      !resolvedPortZone->QueryZoneCapabilityFlagD(nationId)) {
    resolvedPortZone = RefreshMissionPortZoneContextForNation();
  }

  return (resolvedPortZone != nullptr) ? this : nullptr;
}

// FUNCTION: IMPERIALISM 0x0053ae90
void TBlockadePortMission::SetStateByte8To2() {
  state08 = 3;
}

// FUNCTION: IMPERIALISM 0x0053aeb0
void TBlockadePortMission::CalculateNeeds() {
  TControlSeaZoneMission::CalculateNeeds();

  const short* navyDistributionWeights = g_NavyOrderDistributionCategoryWeights;

  float threatScore = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  if (portZoneContext->GetPortOwnerNation() < 7) {
    short targetNationCode = portZoneContext->GetPortOwnerNation();
    float vector[4] = {g_Recompute_Nation_Order_LookupTable_0065A9E8,
                       g_Recompute_Nation_Order_LookupTable_0065A9E8,
                       g_Recompute_Nation_Order_LookupTable_0065A9E8,
                       g_Recompute_Nation_Order_LookupTable_0065A9E8};
    for (TShip* node = TShip::GetFirst(); node != nullptr; node = node->next) {
      if (node->nation == targetNationCode && node->IsInHomePort() &&
          node->GetMaxStrength() <= node->strength) {
        AccumulateNavyOrderCategoryVectorWithScale(node, vector, 1.0f);
      }
    }
    threatScore = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
        vector, navyDistributionWeights, 4);
  } else {
    for (int nation = 0; nation < 7; ++nation) {
      if (g_apNationStates[nation] == nullptr) {
        continue;
      }
      if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, nation)) {
        continue;
      }
      short targetNationCode = portZoneContext->GetPortOwnerNation();
      float vector[4] = {g_Recompute_Nation_Order_LookupTable_0065A9E8,
                         g_Recompute_Nation_Order_LookupTable_0065A9E8,
                         g_Recompute_Nation_Order_LookupTable_0065A9E8,
                         g_Recompute_Nation_Order_LookupTable_0065A9E8};
      for (TShip* node = TShip::GetFirst(); node != nullptr; node = node->next) {
        if (node->nation == targetNationCode && node->IsInHomePort() &&
            node->GetMaxStrength() <= node->strength) {
          AccumulateNavyOrderCategoryVectorWithScale(node, vector, 1.0f);
        }
      }
      float score = ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
          vector, navyDistributionWeights, 4);
      if (threatScore < score) {
        threatScore = score;
      }
    }
  }

  float threatFloor = threatScore * g_BlockadePortMissionThreatScale;
  if (threatFloor <= g_BlockadePortMissionThreatFloor) {
    threatFloor = g_BlockadePortMissionThreatFloor;
  }

  const short* weights = &g_Populate_Beachhead_Mission_LookupTable[4];
  for (int i = 0; i < 4; ++i) {
    float raised = static_cast<float>(weights[i] * threatFloor *
                                      g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (requiredShipEquipageByCategory[i] < raised) {
      requiredShipEquipageByCategory[i] = raised;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0053ba10
bool TBlockadePortMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  (void)key;
  return missionType == kMissionTypeBlockadePort && zoneContext == missionTargetZone;
}

// FUNCTION: IMPERIALISM 0x0053ba40
void TBlockadePortMission::GiveActionOrders(TTaskForce* mapOrderEntry) {
  mapOrderEntry->OrderBlockade(portZoneContext);
}
