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
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

// The archive extraction operator below is emitted by IMPLEMENT_SERIAL:
//   CArchive& AFXAPI operator>>(CArchive&, TBeachheadMission*&)
IMPLEMENT_SERIAL(TBeachheadMission, TControlSeaZoneMission, 1)

// FUNCTION: IMPERIALISM 0x0053a390
bool TBeachheadMission::IsHospitalMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053a3b0
bool TBeachheadMission::IsDefensiveSeaZoneMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053a400
TBeachheadMission::~TBeachheadMission() {}

// FUNCTION: IMPERIALISM 0x0053a490
TBeachheadMission::TBeachheadMission(TZone* targetZone, TInvadeMission* parentMission)
    : TControlSeaZoneMission(targetZone), parentMission3c(parentMission) {}

// FUNCTION: IMPERIALISM 0x0053a500
void TBeachheadMission::CalculateNeeds() {
  TControlSeaZoneMission::CalculateNeeds();

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
  if (flag10 == 0 && navyState28 != 0) {
    return 0;
  }
  while (orderList != 0) {
    orderList->payload->mission = 0;
    orderList = orderList->DeleteMapOrderChildLinkAndReturnNext();
  }
  return 1;
}
