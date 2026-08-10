#include "FirstTurnPhaseHelpers.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

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
    if (g_pMapContextActionManager == 0) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }
    const int expectedPhases[] = {7, 9, 10, 0x14};
    RuntimeActionResult advanced = AdvanceFirstTurnToPhase(expectedPhases, 4, 0x14);
    if (!advanced.Succeeded()) {
      return advanced;
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "combat movement did not begin from the retained offer-sheet presentation");
    }

    RuntimeActionResult before = CaptureTurnStepBefore(RunState());
    if (!before.Succeeded()) {
      return before;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0x15) {
      return RuntimeActionResult::Failure("combat movement did not advance to military cleanup");
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "the zero-stack combat pass unexpectedly changed presentation");
    }
    return CaptureTurnStepContinuesAfter(RunState(), 0x14, 0x15);
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnCombatMovementPhaseTestCase, FirstTurnCombatMovementPhaseTest)
