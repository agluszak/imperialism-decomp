#include "JsonObject.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "screens/DiplomacyScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

// Observe reconstructed phase 6 from the retail-produced beginning-of-game save. This is
// retail_fixture_oracle evidence: the fixture is retail, while the operation runs here.
class FirstTurnDiplomacyPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn diplomacy phase once", AdvanceDiplomacyPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceDiplomacyPhaseOnce() {
    if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    // Phase 5 has no first-turn alert work. Put the fixture at the exact phase-6 operation
    // boundary so this scenario observes only diplomacy application and replies.
    g_pSimMgr->turnStateCode = 6;
    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    RunState().SetCapture("case", json_value_init_null());
    if (!RunState().HasCapture("case")) {
      return RuntimeActionResult::Failure("the void case capture is unavailable");
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 7) {
      return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
    }
    if (!DiplomacyScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("the diplomacy phase did not display the diplomacy map");
    }

    // The phase dispatches NEXT after displaying the map; the empty transition
    // queue then posts the next-phase command. This is a visible non-blocking
    // event rather than a player-intervention gate.
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 6);
    result.Set("to", 7);
    result.Set("visible_ui", "diplomacy_map");
    RunState().SetCapture("result", result.Release());
    if (!RunState().HasCapture("result")) {
      return RuntimeActionResult::Failure("the phase outcome capture is unavailable");
    }
    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnDiplomacyPhaseTestCase, FirstTurnDiplomacyPhaseTest)
