// TEscortMission implementations.

#include "game/map/TEscortMission.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TMinor.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

// The archive extraction operator below is emitted by IMPLEMENT_SERIAL:
//   CArchive& AFXAPI operator>>(CArchive&, TEscortMission*&)
// SYNTHETIC: IMPERIALISM 0x005399f0
// operator>>
IMPLEMENT_SERIAL(TEscortMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x00539840
// TEscortMission::CreateObject

// FUNCTION: IMPERIALISM 0x00539900
TMission* TEscortMission::GetReplacementSlot48() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00539920
bool TEscortMission::IsHospitalMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00539940
bool TEscortMission::IsDefensiveSeaZoneMission() const {
  return false;
}
// SYNTHETIC: IMPERIALISM 0x00539960
// TEscortMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00539990
TEscortMission::~TEscortMission() {}

// SYNTHETIC: IMPERIALISM 0x005399b0
// TEscortMission::GetRuntimeClass

// The original inlines the whole TNavyMission(TZone*) body here (only the TMission()
// base ctor stays an out-of-line call); the recompile emits a call to 0x535470 instead,
// which is the accepted architectural shape until ctor-inlining is modeled.
// FUNCTION: IMPERIALISM 0x00539a20
TEscortMission::TEscortMission(TZone* targetZone) : TNavyMission(targetZone) {}

// FUNCTION: IMPERIALISM 0x00539a70
void TEscortMission::Initialize() {
  marker11 = 0;
  resolvedPortZone = missionTargetZone;
}

// Scales this mission's score by home-nation trade capacity and need pressure: starts from
// the current home port zone's cached-owner (primaryNeighbors slot 0, punned to TGreatPower*
// -- same convention Initialize/CalculateImportance use elsewhere in this file)
// ComputeMapActionContextNodeValueAverage(), then for every OTHER port zone sharing that same
// cached owner multiplies the running score by 1.5 (if that zone's own mission-field-48 owner
// nation matches this mission's nation) or 1.25 (otherwise), and finally scales by
// nation->merchantCapacity / max(nation->transportCapacity, 1) / 5000.
// FUNCTION: IMPERIALISM 0x00539ca0
void TEscortMission::CalculateImportance() {
  TGreatPower* nation = g_apNationStates[nationId04];
  short needCap = (nation != nullptr) ? nation->transportCapacity : 0;
  if (needCap == 0) {
    needCap = 1;
  }

  TZone* homePortZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId04);
  TZone** cachedOwnerSlot = &homePortZone->primaryNeighbors[0];
  TZone* cachedOwner = *cachedOwnerSlot;
  float score = static_cast<float>(cachedOwner->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    TZone** zoneOwnerSlot = &zone->primaryNeighbors[0];
    if (*zoneOwnerSlot == cachedOwner) {
      short ownerNationCode = zone->GetPortZoneOwnerNationCodeFromMissionField48();
      score *= (ownerNationCode == nationId04)
                   ? static_cast<float>(g_PortZoneFriendlyMissionScoreMultiplier_0065AA10)
                   : static_cast<float>(g_PortZoneForeignMissionScoreMultiplier_0065AA18);
    }
  }

  importanceScore0c = (score / g_fMissionScoreNormalizationDivisor) *
                      static_cast<float>(nation->merchantCapacity) / static_cast<float>(needCap);
}

// Walks the 16 minor-nation slots (g_apSecondaryNationStateSlots[7..22]), gating each by
// (a) a scenario-year-derived relation-score threshold when its encodedNationSlot < 200
// (relationStandingScores[i * kNationSlotCount + nationId04] vs. economicTurn/4 + 110), or
// (b) a direct owner-slot match otherwise (the same test as
// TCountry::IsColonyOf). For each eligible minor, resolves its home
// port zone's cached-owner context (FindFirstPortZoneContextByNation +
// primaryNeighbors[0], the same grow-on-access idiom
// CalculateImportance above uses) and scores that context's tagged primary navy order-list
// ships (gated by TDiplomacyMgr::IsNationPairAtWar) into a 4-category vector --
// categories 0-2 scaled by strength/normalizationBase, category 3 unscaled -- via the
// same per-ship math as AccumulateNavyOrderCategoryVectorWithScale, but inlined here rather
// than calling out (no CALL to 0x537c60 in the raw listing; same inlining choice as
// TNavyMission::BuildMissionQueuedOrderCategoryVector). Scores the vector's divergence from
// a {40,30,30,0} weight profile (g_Populate_Beachhead_Mission_LookupTable_00697958[4..7])
// the same way TShip::ComputeNavyOrderDistributionScoreForNation does, and accumulates that
// per-nation score into a running total seeded at 1.0f across every eligible minor. Spreads
// the final total across requiredShipEquipageByCategory[4] via a second, address-distinct {40,30,30,0}
// profile (g_NavyOrderDistributionCategoryWeights_00697978).
// FUNCTION: IMPERIALISM 0x00539e70
void TEscortMission::CalculateNeeds() {
  float total = 1.0f;
  short year = static_cast<short>(g_pSimMgr->economicTurn / 4);
  float yearThreshold = static_cast<float>(year) + 110.0f;

  for (int i = 7; i < 23; ++i) {
    TMinor* nation = g_apSecondaryNationStateSlots[i];
    if (nation == nullptr) {
      continue;
    }

    bool eligible;
    if (nation->encodedNationSlot < 200) {
      eligible =
          static_cast<float>(g_pDiplomacyTurnStateManager
                                 ->relationStandingScores[i * kNationSlotCount + nationId04]) >
          yearThreshold;
    } else {
      short encodedNationSlot = nation->encodedNationSlot;
      if (encodedNationSlot >= 200) {
        eligible = encodedNationSlot - 200 == nationId04;
      } else if (encodedNationSlot >= 100) {
        eligible = encodedNationSlot - 100 == nationId04;
      } else {
        eligible = nation->nationSlot == nationId04;
      }
    }
    if (!eligible) {
      continue;
    }

    TZone* homePortZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(i);
    TZone* targetContext = homePortZone->primaryNeighbors[0];

    float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (TShip* node = TShip::GetFirst(); node != nullptr; node = node->next) {
      if (node->location != targetContext) {
        continue;
      }
      if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId04, node->nation)) {
        continue;
      }
      short normalizationBase = node->GetMaxStrength();
      float scale = static_cast<float>(node->strength / normalizationBase);
      vector[0] +=
          static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
          scale;
      vector[1] +=
          static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
          scale;
      vector[2] +=
          static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
          scale;
      vector[3] +=
          static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(3));
    }

    float sum = vector[0] + vector[1] + vector[2] + vector[3];
    float result;
    if (sum == 0.0f) {
      result = 0.0f;
    } else {
      float delta = 0.0f;
      const short* weights = &g_Populate_Beachhead_Mission_LookupTable_00697958[4];
      for (int c = 0; c < 4; ++c) {
        float diff = vector[c] / sum - static_cast<float>(static_cast<short>(weights[c])) * 0.01f;
        if (diff <= 0.0f) {
          diff = -diff;
        }
        delta += diff;
      }
      result = sum * (1.0f - delta * 0.5f);
    }
    total = result + total;
  }

  for (int c = 0; c < 4; ++c) {
    requiredShipEquipageByCategory[c] =
        static_cast<float>(g_NavyOrderDistributionCategoryWeights_00697978[c]) * total * 0.01f;
  }
}

// FUNCTION: IMPERIALISM 0x0053a250
bool TEscortMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  (void)key;
  return (missionType == kMissionTypeAttackProvince || missionType == kMissionTypeDefendProvince) &&
         zoneContext == missionTargetZone;
}

// FUNCTION: IMPERIALISM 0x0053a290
void TEscortMission::GiveOrders() {
  if (orderList24 != nullptr) {
    orderList24->active = 0;
    orderList24->next->SetChainActiveFlag(0);
  }
  ConsolidateMissionOrderEntriesByTargetAndQueue(missionTargetZone);
}
