#include "FirstTurnPhaseHelpers.h"

#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "screens/RuntimeActionResult.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

RuntimeActionResult AdvanceFirstTurnToPhase(const int* expectedSequence, int expectedCount,
                                            int targetPhase) {
  if (expectedSequence == 0 || expectedCount <= 0) {
    return RuntimeActionResult::Failure("the first-turn phase sequence is empty");
  }
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  for (int index = 0; index < expectedCount; ++index) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != expectedSequence[index]) {
      return RuntimeActionResult::Failure(
          "the prerequisite turn phases did not follow the recovered first-turn sequence");
    }
    if (g_pSimMgr->turnStateCode == targetPhase) {
      return RuntimeActionResult::Success();
    }
  }
  return RuntimeActionResult::Failure("the requested first-turn phase was not reached");
}

RuntimeActionResult CaptureTurnStepBefore(RuntimeRun& run) {
  if (!CaptureGameState(run, "before")) {
    return RuntimeActionResult::Failure("the before game-state capture is unavailable");
  }
  run.SetCapture("case", json_value_init_null());
  if (!run.HasCapture("case")) {
    return RuntimeActionResult::Failure("the void case capture is unavailable");
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CaptureTurnStepContinuesAfter(RuntimeRun& run, int fromPhase, int toPhase) {
  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", fromPhase);
  result.Set("to", toPhase);
  result.Set("effects", effects.Release());
  run.SetCapture("result", result.Release());
  if (!run.HasCapture("result")) {
    return RuntimeActionResult::Failure("the turn outcome capture is unavailable");
  }
  if (!CaptureGameState(run, "after")) {
    return RuntimeActionResult::Failure("the after game-state capture is unavailable");
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult CaptureTurnStepBlockedAfter(RuntimeRun& run, int phase, const char* blockKind,
                                                const char* uiGate) {
  JsonArray effects;
  JsonObject result;
  result.Set("kind", "blocked");
  result.Set("phase", phase);
  JsonObject block;
  block.Set("kind", blockKind);
  if (uiGate != 0) {
    JsonObject request;
    request.Set("kind", uiGate);
    block.Set("request", request.Release());
  }
  result.Set("block", block.Release());
  result.Set("effects", effects.Release());
  run.SetCapture("result", result.Release());
  if (!run.HasCapture("result")) {
    return RuntimeActionResult::Failure("the turn outcome capture is unavailable");
  }
  if (!CaptureGameState(run, "after")) {
    return RuntimeActionResult::Failure("the after game-state capture is unavailable");
  }
  return RuntimeActionResult::Success();
}
