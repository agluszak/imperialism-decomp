#include "NativeTransition.h"
#include "JsonObject.h"

#include "game/globals/shared_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

void ClearScheduledUnlocksExcept(int keepTechId, short economicTurn) {
  g_pSimMgr->economicTurn = economicTurn;
  for (int techId = 3; techId < 0x1d; ++techId) {
    if (techId == keepTechId) {
      continue;
    }
    if (g_pTechMgr->perTechUnlockFlag180[techId] == 0) {
      g_pTechMgr->prioritySlots04[techId] = 0;
    }
  }
}

} // namespace

RuntimeActionResult RunCheckTechnologyAdvances(NativeTransition& transition) {
  if (g_pTechMgr == 0 || g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("technology state is unavailable");
  }

  const short economicTurn = 1234;
  ClearScheduledUnlocksExcept(4, economicTurn);
  g_pTechMgr->perTechUnlockFlag180[4] = 0;
  g_pTechMgr->prioritySlots04[4] = economicTurn;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pTechMgr->CheckForAdvances();
  return transition.Finish();
}

RuntimeActionResult RunCheckTechnologyAdvancesAiPurchase(NativeTransition& transition) {
  if (g_pTechMgr == 0 || g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("technology state is unavailable");
  }

  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  const short aiNationSlot = activeNationSlot == 0 ? 1 : 0;
  TGreatPower* aiNation = g_apNationStates[aiNationSlot];
  if (aiNation == 0) {
    return RuntimeActionResult::Failure("the loaded game has no AI great-power slot");
  }

  g_pSimMgr->economicTurn = 1;
  for (int techId = 3; techId < 0x1d; ++techId) {
    g_pTechMgr->perTechUnlockFlag180[techId] = 0;
    g_pTechMgr->prioritySlots04[techId] = 0;
    g_pTechMgr->orderCapRows277[aiNationSlot].techStatusByTechId[techId] = 2;
  }
  g_pTechMgr->perTechUnlockFlag180[3] = 1;
  g_pTechMgr->orderCapRows277[aiNationSlot].techStatusByTechId[3] = 0;
  aiNation->diplomacyEligibilityA0 = 0;
  aiNation->treasuryValue10 = 50000;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pTechMgr->CheckForAdvances();
  return transition.Finish();
}
