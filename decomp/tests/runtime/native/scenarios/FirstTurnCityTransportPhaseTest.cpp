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

// Observe reconstructed phase 8 from the exact state produced by the recovered first-turn
// diplomacy, trade, civilian, military and elimination phases. The city-and-transport pass
// advances to great-power pressure while retaining the offer-sheet presentation.
class FirstTurnCityTransportPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn city-and-transport phase once", AdvanceCityTransportPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceCityTransportPhaseOnce() {
    if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    g_pSimMgr->turnStateCode = 6;
    const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d, 0x19, 8};
    for (int index = 0; index < 8; ++index) {
      g_pSimMgr->AdvanceGlobalTurnStateMachine();
      if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
        return RuntimeActionResult::Failure(
            "the prerequisite turn phases did not reach city and transport");
      }
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "city and transport did not begin from the retained offer sheet");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }
    RunState().SetCapture("case", json_value_init_null());
    if (!RunState().HasCapture("case")) {
      return RuntimeActionResult::Failure("the void case capture is unavailable");
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0x0b) {
      return RuntimeActionResult::Failure(
          "city and transport did not advance to great-power pressure");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("city and transport unexpectedly changed presentation");
    }

    JsonArray effects;
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 8);
    result.Set("to", 0x0b);
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

RUNTIME_TEST_FACTORY(FirstTurnCityTransportPhaseTestCase, FirstTurnCityTransportPhaseTest)
