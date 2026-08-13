#include "NativeTransition.h"
#include "JsonObject.h"
#include "RuntimeRun.h"

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

RuntimeActionResult RunTechnologyTurnStop(NativeTransition& transition) {
  if (g_pTechMgr == 0 || g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("technology state is unavailable");
  }

  const int technologyId = 3;
  ClearScheduledUnlocksExcept(-1, 1);
  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  g_pTechMgr->orderCapRows277[activeNationSlot].techStatusByTechId[technologyId] = 1;
  g_pSimMgr->turnStateCode = 0x11;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  RuntimeActionResult finished =
      transition.Finish(json_value_init_string("technology_advance"));
  if (!finished.Succeeded()) {
    return finished;
  }

  JsonObject continuation;
  continuation.Set("TechnologyReport", technologyId);
  if (json_object_dotset_value(transition.Run().Captures(), "after.ephemeral.continuation",
                               continuation.Release()) != JSONSuccess) {
    return RuntimeActionResult::Failure("technology continuation capture failed");
  }
  return finished;
}
