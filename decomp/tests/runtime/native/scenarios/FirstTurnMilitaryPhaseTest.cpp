#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

// Observe reconstructed phase 10 from the exact post-civilian state produced by the recovered
// diplomacy, trade, and civilian phases.
class FirstTurnMilitaryPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn military phase once", AdvanceMilitaryPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceMilitaryPhaseOnce() {
    if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    g_pSimMgr->turnStateCode = 6;
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 7) {
      return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
    }
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 9) {
      return RuntimeActionResult::Failure("the trade phase did not advance to phase 9");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("the civilian phase did not begin from the offer desk");
    }
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 10) {
      return RuntimeActionResult::Failure("the civilian phase did not advance to phase 10");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("the military phase did not begin from the offer desk");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }
    RunState().SetCapture("case", json_value_init_null());
    if (!RunState().HasCapture("case")) {
      return RuntimeActionResult::Failure("the void case capture is unavailable");
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0x14) {
      return RuntimeActionResult::Failure("the military phase did not advance to phase 0x14");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("the military phase unexpectedly changed presentation");
    }

    JsonArray effects;
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 10);
    result.Set("to", 0x14);
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

RUNTIME_TEST_FACTORY(FirstTurnMilitaryPhaseTestCase, FirstTurnMilitaryPhaseTest)
