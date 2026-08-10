#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"

#include "game/globals/shared_globals.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"

RuntimeActionResult RunFirstTurnAlertPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  return transition.Finish();
}

RuntimeActionResult RunFirstTurnDiplomacyPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  // Phase 5 has no first-turn alert work. Put the fixture at the exact phase-6 operation
  // boundary so this case observes only diplomacy application and replies.
  g_pSimMgr->turnStateCode = 6;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 7) {
    return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
  }
  if ((g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1) != kTurnEventDiplomacyMap) {
    return RuntimeActionResult::Failure("the diplomacy phase did not show the diplomacy map");
  }

  JsonObject effect;
  effect.Set("kind", "show_diplomacy_map");
  effect.Set("nation", static_cast<int>(g_pSimMgr->activeNationSlot));
  JsonArray effects;
  effects.Add(effect.Release());

  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 6);
  result.Set("to", 7);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}
