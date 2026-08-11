#include "FirstTurnPhaseHelpers.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"


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
    const int expectedPhases[] = {7, 9, 10, 0x14, 0x15};
    RuntimeActionResult advanced =
        AdvanceFirstTurnToPhase(expectedPhases, 5, 0x15);
    if (!advanced.Succeeded()) {
      return advanced;
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "military cleanup did not begin from the retained offer-sheet presentation");
    }

    RuntimeActionResult before = CaptureTurnStepBefore(RunState());
    if (!before.Succeeded()) {
      return before;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 0xd) {
      return RuntimeActionResult::Failure(
          "military cleanup did not advance to the diplomatic-offer phase");
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure("military cleanup unexpectedly changed presentation");
    }
    return CaptureTurnStepContinuesAfter(RunState(), 0x15, 0xd);
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnMilitaryCleanupPhaseTestCase, FirstTurnMilitaryCleanupPhaseTest)
