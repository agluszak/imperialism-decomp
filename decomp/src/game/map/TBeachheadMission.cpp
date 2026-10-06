// TBeachheadMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBeachheadMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// Initialize / SetStateByte8To2 / CalculateImportance / GetReplacement /
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
    : TControlSeaZoneMission(targetZone), parentMission(parentMission) {}

// FUNCTION: IMPERIALISM 0x0053a500
void TBeachheadMission::CalculateNeeds() {
  TControlSeaZoneMission::CalculateNeeds();

  float invadePriority = static_cast<float>(g_BeachheadMissionPriorityNormalization_0065AA30 /
                                            GetNavyOrderCategoryBaseline(3)) *
                         parentMission->CalculatePriority();
  if (requiredShipEquipageByCategory[3] < invadePriority) {
    requiredShipEquipageByCategory[3] = invadePriority;
  }
}

// FUNCTION: IMPERIALISM 0x0053a7b0
bool TBeachheadMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  return missionType == kMissionTypeInvadeProvince && key != -1 &&
         key == parentMission->targetProvince30 && zoneContext == missionTargetZone;
}

// FUNCTION: IMPERIALISM 0x0053a800
void TBeachheadMission::GiveActionOrders(TTaskForce* mapOrderEntry) {
  signed char ownerCode =
      g_pGlobalMapState->cityScoreTable[parentMission->targetProvince30].ownerNationCode00;
  if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(nationId, ownerCode)) {
    mapOrderEntry->OrderSendInTheMarines(
        &g_pGlobalMapState->cityScoreTable[parentMission->targetProvince30]);
    return;
  }

  ownerCode = g_pGlobalMapState->cityScoreTable[parentMission->targetProvince30].ownerNationCode00;
  if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, ownerCode)) {
    return;
  }

  ownerCode = g_pGlobalMapState->cityScoreTable[parentMission->targetProvince30].ownerNationCode00;
  if (g_apNationStates[nationId]->diplomacyPolicyByNation[ownerCode] !=
      kDiplomacyProposalDeclareWar) {
    g_apNationStates[nationId]->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
        ownerCode, kDiplomacyProposalDeclareWar);
  }
}

// FUNCTION: IMPERIALISM 0x0053a920
TMission* TBeachheadMission::GetArmyMission() {
  return parentMission;
}

// FUNCTION: IMPERIALISM 0x0053a940
char TBeachheadMission::SmokeEmIfYouGotEm() {
  if (flag10 == 0 && navyState != 0) {
    return 0;
  }
  while (orderList != 0) {
    orderList->payload->mission = 0;
    orderList = orderList->DeleteMapOrderChildLinkAndReturnNext();
  }
  return 1;
}
