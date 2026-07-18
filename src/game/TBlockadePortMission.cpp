// TBlockadePortMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBlockadePortMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// ResetValue0CToZero and RefreshMissionPortZoneContextForNation are NOT
// overridden here -- they're inherited unchanged from TControlSeaZoneMission,
// which owns their `// FUNCTION:` markers. Call30 here is a genuinely distinct
// own override (RecomputeAndClearMissionScoreUsingPortZoneContextAverageVariantB).

#include "game/TArmyPlayer.h"
#include "game/TBlockadePortMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TShip.h"
#include "game/TStream.h"
#include "game/TTaskForce.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

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
  stream->WriteCountSlot88(portZoneContext3c->GetContextOrdinalOrInvalid());
}

// FUNCTION: IMPERIALISM 0x0053aca0
void TBlockadePortMission::ReadFrom(TStream* stream) {
  TNavyMission::ReadFrom(stream);
  portZoneContext3c = FindMapActionContextByNodeId(stream->ReadShort());
}

// FUNCTION: IMPERIALISM 0x0053ace0
void TBlockadePortMission::Call30() {
  float score = static_cast<float>(targetZone14->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    // See TControlSeaZoneMission::Call30 -- per-zone owner cache not yet modeled.
    (void)zone;
  }

  marker11 = 0;
  value0c = score / g_fMissionScoreNormalizationDivisor;
}

// Same overall shape as TControlSeaZoneMission::GetReplacementSlot48, but the coverage
// check here indexes this nation's per-context byte gate array (this+0x8a0, same region
// SetByteFlagAtOffsetAF0ByIndex writes) by portZoneContext3c's owner-nation-code ordinal,
// instead of scanning g_apTerrainTypeDescriptorTable.
// FUNCTION: IMPERIALISM 0x0053adf0
TMission* TBlockadePortMission::GetReplacementSlot48() {
  TGreatPower* nation = g_apNationStates[nationId04];
  nation->AssertValid();
  short ownerCode = portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48();
  bool hasCoverage = *(reinterpret_cast<char*>(nation) + 0x8a0 + ownerCode) != 0;

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

// First reproduces the base TControlSeaZoneMission::NoOpSlot3C's targetZone14-tagged base
// score (duplicated inline -- see the in-body comment), then computes a second "threat"
// score: either from a single target nation (this blockade's portZoneContext3c owner-
// nation-code, if < 7) or maxed over every nation in g_apNationStates whose diplomacy
// relation with this mission's nation is outdated (TDiplomacyMgr::HasPolicyWithNationSlot44).
// Either way the threat score itself is portZoneContext3c's owner-nation-code's navy-order
// distribution score -- the same per-ship walk/accumulate/normalize shape as
// TShip::ComputeNavyOrderDistributionScoreForNation, inlined here rather than calling that
// function (no CALL to 0x53b800 in the raw listing). Finally uses max(threat*0.5, 10.0) to
// raise (never lower) each resourceWeights2c[i] via the
// g_Populate_Beachhead_Mission_LookupTable_00697958[4..7] profile (same slice TEscortMission's
// own NoOpSlot3C uses).
// FUNCTION: IMPERIALISM 0x0053aeb0
void TBlockadePortMission::NoOpSlot3C() {
  // Reproduces the base TControlSeaZoneMission::NoOpSlot3C's targetZone14-tagged base score
  // inline -- the two classes are separate translation units with no LTO, so a qualified
  // `TControlSeaZoneMission::NoOpSlot3C()` call would emit a real cross-TU CALL rather than
  // reproducing the original's fully-duplicated inlined body, so the body is duplicated here
  // instead (see TBeachheadMission::NoOpSlot3C's identical duplication and its longer
  // rationale comment).
  float baseVector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
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
    const unsigned short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
    float sum = baseVector[0] + baseVector[1] + baseVector[2] + baseVector[3];
    float total = 0.0f;
    if (sum != 0.0f) {
      float delta = 0.0f;
      for (int i = 0; i < 4; ++i) {
        float diff =
            baseVector[i] / sum - static_cast<float>(static_cast<short>(lookupTable[i])) * 0.01f;
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

  // Same signed-short storage as the sibling per-category weight table (see the
  // g_NavyOrderDistributionCategoryWeights_00697978 declaration comment); reinterpreted
  // as unsigned short* only to match ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile's
  // parameter type -- the callee immediately re-casts each element back to short.
  unsigned short* navyDistributionWeights = reinterpret_cast<unsigned short*>(
      const_cast<short*>(g_NavyOrderDistributionCategoryWeights_00697978));

  float threatScore = 0.0f;
  if (portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48() < 7) {
    short targetNationCode = portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48();
    float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (TShip* node = GetNavyPrimaryOrderListHead(); node != nullptr; node = node->nextOlder24) {
      if (node->ownerNationSlot14 == targetNationCode && node->field08->QueryPortZoneCapability() &&
          node->GetNavyOrderNormalizationBaseByNationType() <= node->stockLevel1c) {
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
      if (!g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationId04, nation)) {
        continue;
      }
      short targetNationCode = portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48();
      float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
      for (TShip* node = GetNavyPrimaryOrderListHead(); node != nullptr; node = node->nextOlder24) {
        if (node->ownerNationSlot14 == targetNationCode &&
            node->field08->QueryPortZoneCapability() &&
            node->GetNavyOrderNormalizationBaseByNationType() <= node->stockLevel1c) {
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

  float threatFloor = threatScore * 0.5f;
  if (threatFloor <= 10.0f) {
    threatFloor = 10.0f;
  }

  const unsigned short* weights = &g_Populate_Beachhead_Mission_LookupTable_00697958[4];
  for (int i = 0; i < 4; ++i) {
    float raised = static_cast<float>(static_cast<short>(weights[i])) * threatFloor * 0.01f;
    if (resourceWeights2c[i] < raised) {
      resourceWeights2c[i] = raised;
    }
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
