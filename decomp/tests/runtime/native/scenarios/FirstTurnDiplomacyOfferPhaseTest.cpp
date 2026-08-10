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
#include "game/military/TArmyMgr.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

// Observe reconstructed phase 0x0d from the exact state produced by the recovered first-turn
// diplomacy, trade, civilian and military phases. This fixture has no pending combat report,
// so the phase advances directly to elimination without changing the retained offer sheet.
class FirstTurnDiplomacyOfferPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn diplomacy-offer phase once", AdvanceDiplomacyOfferPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceDiplomacyOfferPhaseOnce() {
    if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
        g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    g_pSimMgr->turnStateCode = 6;
    const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d};
    for (int index = 0; index < 6; ++index) {
      g_pSimMgr->AdvanceGlobalTurnStateMachine();
      if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
        return RuntimeActionResult::Failure(
            "the prerequisite turn phases did not reach the diplomacy-offer phase");
      }
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "the diplomacy-offer phase did not begin from the retained offer sheet");
    }
    if (g_pMapContextActionManager->GetByteFlagAtOffset8() != 0) {
      return RuntimeActionResult::Failure(
          "the beginning-save fixture unexpectedly has a pending combat report");
    }

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(json_value_init_null());
    if (!started.Succeeded()) {
      return started;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0x19) {
      return RuntimeActionResult::Failure(
          "the diplomacy-offer phase did not advance to elimination");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "the empty diplomacy-offer phase unexpectedly changed presentation");
    }

    JsonArray effects;
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 0x0d);
    result.Set("to", 0x19);
    result.Set("effects", effects.Release());
    return capture.Finish(result.Release());
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnDiplomacyOfferPhaseTestCase, FirstTurnDiplomacyOfferPhaseTest)
