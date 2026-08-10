#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

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

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(JsonNullValue());
    if (!started.Succeeded()) {
      return started;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 7) {
      return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
    }

    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnDiplomacyPhaseTestCase, FirstTurnDiplomacyPhaseTest)
