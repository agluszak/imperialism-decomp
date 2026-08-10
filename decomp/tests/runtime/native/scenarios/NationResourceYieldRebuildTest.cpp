#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeDifferentialCapture.h"

#include "game/city/TCity.h"
#include "game/city/TTown.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Rebuild the untouched beginning-save player's complete resource-yield state through the retail
// nation operation. The complete captures retain the target clamps, transport linkage and RNG.
class NationResourceYieldRebuildTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("rebuild the player's resource yields", RebuildResourceYields());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult RebuildResourceYields() {
    const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0 || nation->city->homeTownMarkerB0 == 0) {
      return RuntimeActionResult::Failure(
          "the loaded active nation is not the human beginning-save player");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    nation->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(NationResourceYieldRebuildTestCase, NationResourceYieldRebuildTest)
