#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

// Observe reconstructed phase 0x15 from the exact post-combat-movement state produced by the
// recovered diplomacy, trade, civilian, military-planning and combat-movement phases.
class FirstTurnMilitaryCleanupPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn military cleanup phase once", AdvanceMilitaryCleanupPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceMilitaryCleanupPhaseOnce() {
    if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
        g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    g_pSimMgr->turnStateCode = 6;
    const int expectedPhases[] = {7, 9, 10, 0x14, 0x15};
    for (int index = 0; index < 5; ++index) {
      g_pSimMgr->AdvanceGlobalTurnStateMachine();
      if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
        return RuntimeActionResult::Failure(
            "the prerequisite turn phases did not reach military cleanup");
      }
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "military cleanup did not begin from the retained offer-sheet presentation");
    }

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(json_value_init_null());
    if (!started.Succeeded()) {
      return started;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0xd) {
      return RuntimeActionResult::Failure(
          "military cleanup did not advance to the diplomatic-offer phase");
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("military cleanup unexpectedly changed presentation");
    }

    JsonArray effects;
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 0x15);
    result.Set("to", 0xd);
    result.Set("effects", effects.Release());
    return capture.Finish(result.Release());
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnMilitaryCleanupPhaseTestCase, FirstTurnMilitaryCleanupPhaseTest)
