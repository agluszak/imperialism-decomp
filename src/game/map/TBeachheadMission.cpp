// TBeachheadMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBeachheadMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// Initialize / SetStateByte8To2 / CalculateImportance / GetReplacementSlot48 /
// RefreshMissionPortZoneContextForNation are NOT overridden here -- they're
// inherited unchanged from TControlSeaZoneMission, which owns their
// `// FUNCTION:` markers.

#include "game/map/TBeachheadMission.h"
#include "game/military/TAttackProvinceMission.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/military/TInvadeMission.h"
#include "game/map/TMapMgr.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/core/TStream.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_screens/TZone.h"
#include "game/globals/prelude.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

// The archive extraction operator below is emitted by IMPLEMENT_SERIAL:
//   CArchive& AFXAPI operator>>(CArchive&, TBeachheadMission*&)
// SYNTHETIC: IMPERIALISM 0x0053a460
// operator>>
IMPLEMENT_SERIAL(TBeachheadMission, TControlSeaZoneMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053a2d0
// TBeachheadMission::CreateObject

// FUNCTION: IMPERIALISM 0x0053a390
bool TBeachheadMission::IsHospitalMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053a3b0
bool TBeachheadMission::IsDefensiveSeaZoneMission() const {
  return false;
}

// SYNTHETIC: IMPERIALISM 0x0053a3d0 (approx -- see symbols.csv)
// TBeachheadMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0053a400
TBeachheadMission::~TBeachheadMission() {}

// SYNTHETIC: IMPERIALISM 0x0053a420
// TBeachheadMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x0053a490
TBeachheadMission::TBeachheadMission(TZone* targetZone, TInvadeMission* parentMission)
    : TControlSeaZoneMission(targetZone), parentMission3c(parentMission) {}

// Reproduces the base TControlSeaZoneMission::CalculateNeeds's missionTargetZone-tagged base score
// inline -- the two classes are separate translation units with no LTO, so a qualified
// `TControlSeaZoneMission::CalculateNeeds()` call (which the original's own object code shows
// fully duplicated, not a real CALL) would either emit a real cross-TU CALL or, since this
// whole function used to be nothing else, collapse into a bare tail-call JMP -- neither
// matches the original's inlined shape, so the body is duplicated here instead. The original
// then scales the owning invade mission's calculated priority into requiredShipEquipageByCategory[3].
// FUNCTION: IMPERIALISM 0x0053a500
void TBeachheadMission::CalculateNeeds() {
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
      float diff = vector[i] / sum - static_cast<float>(static_cast<short>(lookupTable[i])) * 0.01f;
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
    requiredShipEquipageByCategory[i] =
        static_cast<float>(static_cast<short>(lookupTable[i])) * total * 0.01f;
  }

  float invadePriority = static_cast<float>(g_BeachheadMissionPriorityNormalization_0065AA30 /
                                            GetNavyOrderCategoryBaseline(3)) *
                         parentMission3c->CalculatePriority();
  if (requiredShipEquipageByCategory[3] < invadePriority) {
    requiredShipEquipageByCategory[3] = invadePriority;
  }
}

// FUNCTION: IMPERIALISM 0x0053a7b0
bool TBeachheadMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  return missionType == kMissionTypeInvadeProvince && key != -1 &&
         key == parentMission3c->targetProvince30 && zoneContext == missionTargetZone;
}

// this->parentMission3c->targetProvince30 (city/region record index) reads
// g_pGlobalMapState->cityScoreTable[cityId].ownerNationCode00. If that owner has an outdated
// war-relation timestamp with this mission's nation (TDiplomacyMgr::IsNationPairAtWar's slot
// 0x48 sibling), queues map-order type 5 on the passed-in TTaskForce* directly. Otherwise, if
// the two nations aren't currently at war (IsNationPairAtWar/IsNationPairAtWar),
// applies the diplomacy policy state via
// TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks (real vtable slot 0x1d0/116),
// unless the owner's diplomacyPolicyByNation entry already carries the declaration-of-war code.
// FUNCTION: IMPERIALISM 0x0053a800
void TBeachheadMission::GiveActionOrders(TTaskForce* mapOrderEntry) {
  signed char ownerCode =
      g_pGlobalMapState->cityScoreTable[parentMission3c->targetProvince30].ownerNationCode00;
  if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(nationId04, ownerCode)) {
    mapOrderEntry->OrderSendInTheMarines(
        &g_pGlobalMapState->cityScoreTable[parentMission3c->targetProvince30]);
    return;
  }

  ownerCode =
      g_pGlobalMapState->cityScoreTable[parentMission3c->targetProvince30].ownerNationCode00;
  if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId04, ownerCode)) {
    return;
  }

  ownerCode =
      g_pGlobalMapState->cityScoreTable[parentMission3c->targetProvince30].ownerNationCode00;
  if (g_apNationStates[nationId04]->diplomacyPolicyByNation[ownerCode] !=
      kDiplomacyProposalDeclareWar) {
    g_apNationStates[nationId04]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
        ownerCode, kDiplomacyProposalDeclareWar);
  }
}

// FUNCTION: IMPERIALISM 0x0053a920
TMission* TBeachheadMission::GetArmyMission() {
  return parentMission3c;
}

// FUNCTION: IMPERIALISM 0x0053a940
char TBeachheadMission::SmokeEmIfYouGotEm() {
  // ClearBlockadePortMissionChildOrderLinksIfReady: clears each queued
  // order-child's owner-back-pointer, then frees the chain.
  if (marker11 == 0 && taskForce20 != nullptr) {
    return 0;
  }
  orderList24 = nullptr;
  return 1;
}
