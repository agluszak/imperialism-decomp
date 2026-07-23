// TBlockadePortMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBlockadePortMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// CalculateImportance and RefreshMissionPortZoneContextForNation are NOT
// overridden here -- they're inherited unchanged from TControlSeaZoneMission,
// which owns their `// FUNCTION:` markers. Initialize here is a genuinely distinct
// own override (RecomputeAndClearMissionScoreUsingPortZoneContextAverageVariantB).

#include "game/TArmyPlayer.h"
#include "game/TAutoGreatPower.h"
#include "game/TBlockadePortMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TStream.h"
#include "game/TTaskForce.h"
#include "game/TZone.h"
#include "game/globals/prelude.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_SERIAL(TBlockadePortMission, TControlSeaZoneMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053a990
// TBlockadePortMission::CreateObject

// FUNCTION: IMPERIALISM 0x0053aa50
bool TBlockadePortMission::IsHospitalMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053aa70
bool TBlockadePortMission::IsDefensiveSeaZoneMission() const {
  return false;
}
// SYNTHETIC: IMPERIALISM 0x0053aa90
// TBlockadePortMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0053aac0
TBlockadePortMission::~TBlockadePortMission() {}

TBlockadePortMission::TBlockadePortMission()
    : TControlSeaZoneMission(), portZoneContext3c(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x0053aae0
// TBlockadePortMission::GetRuntimeClass

// The mission factory (TMission::CreateMission, case 4) builds a
// blockade mission from a map-order context node (a TZone). It lazily ensures the
// context's primaryNeighbors array has slot 0 allocated -- that first entry is the
// target port zone -- constructs the TControlSeaZoneMission base on it, back-links
// the context node into portZoneContext3c (+0x3c), and validates the context.
// FUNCTION: IMPERIALISM 0x0053ab50
TBlockadePortMission::TBlockadePortMission(TZone* context)
    : TControlSeaZoneMission(context->primaryNeighbors[0]), portZoneContext3c(context) {
  context->AssertValid();
}

// FUNCTION: IMPERIALISM 0x0053ac60
void TBlockadePortMission::WriteTo(TStream* stream) {
  TNavyMission::WriteTo(stream);
  stream->WriteCountSlot88(portZoneContext3c->GetContextOrdinalOrInvalid());
}

// FUNCTION: IMPERIALISM 0x0053aca0
void TBlockadePortMission::ReadFrom(TStream* stream) {
  TNavyMission::ReadFrom(stream);
  portZoneContext3c = FindMapActionContextByNodeId(stream->ReadShort());
}

// FUNCTION: IMPERIALISM 0x0053ace0
void TBlockadePortMission::Initialize() {
  float score = static_cast<float>(targetZone14->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    TZone** ownerSlot = &zone->primaryNeighbors[0];
    if (*ownerSlot == targetZone14) {
      score *= (zone->GetPortZoneOwnerNationCodeFromMissionField48() == nationId04)
                   ? g_PortZoneFriendlyMissionScoreMultiplier_0065AA10
                   : g_PortZoneForeignMissionScoreMultiplier_0065AA18;
    }
  }

  marker11 = 0;
  importanceScore0c = score / g_fMissionScoreNormalizationDivisor;
}

// Same overall shape as TControlSeaZoneMission::GetReplacementSlot48, but the coverage
// check here indexes this nation's candidateNationFlags (a genuine in-bounds TGreatPower
// field at +0x8a0, unrelated to the AI-only tail block SetByteFlagAtOffsetAF0ByIndex
// writes at +0xaf0) by portZoneContext3c's owner-nation-code ordinal, instead of scanning
// g_apTerrainTypeDescriptorTable.
// FUNCTION: IMPERIALISM 0x0053adf0
TMission* TBlockadePortMission::GetReplacementSlot48() {
  // SetByteFlagAtOffsetAF0ByIndex touches the AI-only tail state block, which lives only
  // on TAutoGreatPower (see TAttackProvinceMission::Free); missions are AI-only, so
  // g_apNationStates[nationId04] here is genuinely a TAutoGreatPower.
  TAutoGreatPower* nation = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
  nation->AssertValid();
  short ownerCode = portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48();
  bool hasCoverage = nation->candidateNationFlags[ownerCode] != 0;

  if (!hasCoverage) {
    short contextOrdinal = portZoneContext3c->GetContextOrdinalOrInvalid();
    nation->SetByteFlagAtOffsetAF0ByIndex(contextOrdinal, 0);
    return nullptr;
  }

  if (targetZone18 != nullptr && targetZone18->QueryPortZoneCapability() &&
      !targetZone18->QueryZoneCapabilityFlagD(nationId04)) {
    targetZone18 = RefreshMissionPortZoneContextForNation();
  }

  return (targetZone18 != nullptr) ? this : nullptr;
}

// FUNCTION: IMPERIALISM 0x0053ae90
void TBlockadePortMission::SetStateByte8To2() {
  state08 = 3;
}

// First reproduces the base TControlSeaZoneMission::CalculateNeeds's targetZone14-tagged base
// score (duplicated inline -- see the in-body comment), then computes a second "threat"
// score: either from a single target nation (this blockade's portZoneContext3c owner-
// nation-code, if < 7) or maxed over every nation in g_apNationStates whose diplomacy
// relation with this mission's nation is outdated (TDiplomacyMgr::IsNationPairAtWar).
// Either way the threat score itself is portZoneContext3c's owner-nation-code's navy-order
// distribution score -- the same per-ship walk/accumulate/normalize shape as
// TShip::ComputeNavyOrderDistributionScoreForNation, inlined here rather than calling that
// function (no CALL to 0x53b800 in the raw listing). Finally uses max(threat*0.5, 10.0) to
// raise (never lower) each requiredShipEquipageByCategory[i] via the
// g_Populate_Beachhead_Mission_LookupTable_00697958[4..7] profile (same slice TEscortMission's
// own CalculateNeeds uses).
// FUNCTION: IMPERIALISM 0x0053aeb0
void TBlockadePortMission::CalculateNeeds() {
  // Reproduces the base TControlSeaZoneMission::CalculateNeeds's targetZone14-tagged base score
  // inline -- the two classes are separate translation units with no LTO, so a qualified
  // `TControlSeaZoneMission::CalculateNeeds()` call would emit a real cross-TU CALL rather than
  // reproducing the original's fully-duplicated inlined body, so the body is duplicated here
  // instead (see TBeachheadMission::CalculateNeeds's identical duplication and its longer
  // rationale comment).
  float baseVector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TShip* node = TShip::GetFirst(); node != nullptr; node = node->next) {
    if (node->location != targetZone14) {
      continue;
    }
    if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId04, node->nation)) {
      continue;
    }
    short normalizationBase = node->GetMaxStrength();
    float scale = static_cast<float>(node->strength / normalizationBase);
    baseVector[0] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(0)) * scale;
    baseVector[1] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(1)) * scale;
    baseVector[2] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(2)) * scale;
    baseVector[3] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(3));
  }

  {
    const short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
    float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    int i;
    for (i = 0; i < 4; ++i) {
      sum += baseVector[i];
    }
    float total = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    if (sum != g_Recompute_Nation_Order_LookupTable_0065A9F0) {
      float delta = g_Recompute_Nation_Order_LookupTable_0065A9E8;
      for (i = 0; i < 4; ++i) {
        float diff =
            baseVector[i] / sum - lookupTable[i] * g_Recompute_Nation_Order_LookupTable_0065A9F8;
        if (diff <= g_Recompute_Nation_Order_LookupTable_0065A9F0) {
          diff = -diff;
        }
        delta += diff;
      }
      total = static_cast<float>(sum * (g_Recompute_Nation_Order_LookupTable_0065AA08 -
                                        delta * g_Recompute_Nation_Order_LookupTable_0065AA00));
    }
    total *= g_MissionResourceWeightScale_0065A8FC;
    if (total == 0.0f) {
      total = g_MissionEmptyResourceWeight_0065AA24;
    }
    for (i = 0; i < 4; ++i) {
      requiredShipEquipageByCategory[i] = static_cast<float>(
          lookupTable[i] * total * g_Recompute_Nation_Order_LookupTable_0065A9F8);
    }
  }

  const short* navyDistributionWeights = g_NavyOrderDistributionCategoryWeights_00697978;

  float threatScore = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  if (portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48() < 7) {
    short targetNationCode = portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48();
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
      if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId04, nation)) {
        continue;
      }
      short targetNationCode = portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48();
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

  float threatFloor = threatScore * g_BlockadePortMissionThreatScale_0065A904;
  if (threatFloor <= g_BlockadePortMissionThreatFloor_0065A900) {
    threatFloor = g_BlockadePortMissionThreatFloor_0065A900;
  }

  const short* weights = &g_Populate_Beachhead_Mission_LookupTable_00697958[4];
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
  return missionType == kMissionTypeBlockadePort && zoneContext == targetZone14;
}

// FUNCTION: IMPERIALISM 0x0053ba40
void TBlockadePortMission::GiveActionOrders(TTaskForce* mapOrderEntry) {
  mapOrderEntry->OrderBlockade(portZoneContext3c);
}
