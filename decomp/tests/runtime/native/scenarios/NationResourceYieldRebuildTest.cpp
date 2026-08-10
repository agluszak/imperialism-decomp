#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeSemanticCapture.h"

#include "game/city/TCity.h"
#include "game/city/TTown.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TAutoGreatPower.h"
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
    if (nation == 0 || nation->city == 0 || nation->city->homeTownMarkerB0 == 0 ||
        nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) != 0) {
      return RuntimeActionResult::Failure(
          "the loaded active nation is not the human beginning-save player");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    if (!CaptureVoidOpResult(RunState())) {
      return RuntimeActionResult::Failure("the void operation result capture is unavailable");
    }

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(NationResourceYieldRebuildTestCase, NationResourceYieldRebuildTest)
