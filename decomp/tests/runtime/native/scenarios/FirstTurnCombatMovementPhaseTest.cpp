#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

// Observe the zero-stack first-turn combat-movement pass from the exact state produced by the
// recovered diplomacy, trade, civilian and military-planning phases.
class FirstTurnCombatMovementPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn combat-movement phase once", AdvanceCombatMovementPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceCombatMovementPhaseOnce() {
    if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
        g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    g_pSimMgr->turnStateCode = 6;
    const int expectedPhases[] = {7, 9, 10, 0x14};
    for (int index = 0; index < 4; ++index) {
      g_pSimMgr->AdvanceGlobalTurnStateMachine();
      if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
        return RuntimeActionResult::Failure(
            "the prerequisite turn phases did not reach combat movement");
      }
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "combat movement did not begin from the retained offer-sheet presentation");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }
    RunState().SetCapture("case", json_value_init_null());
    if (!RunState().HasCapture("case")) {
      return RuntimeActionResult::Failure("the void case capture is unavailable");
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0x15) {
      return RuntimeActionResult::Failure("combat movement did not advance to military cleanup");
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "the zero-stack combat pass unexpectedly changed presentation");
    }

    JsonArray effects;
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 0x14);
    result.Set("to", 0x15);
    result.Set("effects", effects.Release());
    RunState().SetCapture("result", result.Release());
    if (!RunState().HasCapture("result")) {
      return RuntimeActionResult::Failure("the turn outcome capture is unavailable");
    }
    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnCombatMovementPhaseTestCase, FirstTurnCombatMovementPhaseTest)
