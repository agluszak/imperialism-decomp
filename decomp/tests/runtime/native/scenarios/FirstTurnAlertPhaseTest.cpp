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

// Observe one reconstructed phase-5 transition from the retail-produced beginning-of-game save.
// This is retail_fixture_oracle evidence: the fixture is retail, while the operation runs here.
class FirstTurnAlertPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn alert phase once", AdvanceAlertPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceAlertPhaseOnce() {
    if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }
    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(JsonNullValue());
    if (!started.Succeeded()) {
      return started;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnAlertPhaseTestCase, FirstTurnAlertPhaseTest)
