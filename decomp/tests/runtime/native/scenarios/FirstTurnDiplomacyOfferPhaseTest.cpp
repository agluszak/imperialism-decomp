#include "FirstTurnPhaseHelpers.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/military/TArmyMgr.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

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
    if (g_pMapContextActionManager == 0) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }
    const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d};
    RuntimeActionResult advanced = AdvanceFirstTurnToPhase(expectedPhases, 6, 0x0d);
    if (!advanced.Succeeded()) {
      return advanced;
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "the diplomacy-offer phase did not begin from the retained offer sheet");
    }
    if (g_pMapContextActionManager->GetByteFlagAtOffset8() != 0) {
      return RuntimeActionResult::Failure(
          "the beginning-save fixture unexpectedly has a pending combat report");
    }

    RuntimeActionResult before = CaptureTurnStepBefore(RunState());
    if (!before.Succeeded()) {
      return before;
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
    return CaptureTurnStepContinuesAfter(RunState(), 0x0d, 0x19);
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnDiplomacyOfferPhaseTestCase, FirstTurnDiplomacyOfferPhaseTest)
