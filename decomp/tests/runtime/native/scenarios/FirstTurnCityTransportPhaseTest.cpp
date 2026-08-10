#include "FirstTurnPhaseHelpers.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"


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
    const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d, 0x19, 8};
    RuntimeActionResult advanced = AdvanceFirstTurnToPhase(expectedPhases, 8, 8);
    if (!advanced.Succeeded()) {
      return advanced;
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "city and transport did not begin from the retained offer sheet");
    }

    RuntimeActionResult before = CaptureTurnStepBefore(RunState());
    if (!before.Succeeded()) {
      return before;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0x0b) {
      return RuntimeActionResult::Failure(
          "city and transport did not advance to great-power pressure");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("city and transport unexpectedly changed presentation");
    }
    return CaptureTurnStepContinuesAfter(RunState(), 8, 0x0b);
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnCityTransportPhaseTestCase, FirstTurnCityTransportPhaseTest)
