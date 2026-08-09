#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeSemanticCapture.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Observe the reconstructed rolling-stock rejection from a retail-derived save
// when the city has no lumber.
class RollingStockInsufficientResourcesTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("attempt rolling stock without enough resources", IncreaseRollingStock());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult IncreaseRollingStock() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
    }

    TCity* city = nation->city;
    city->CityStockByType(kResourceLumber) = 0;
    city->CityStockByType(kResourceSteel) = 1;
    nation->transportCapacity = 15;

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    const bool increased = nation->IncreaseRollingStock() != 0;
    if (!CaptureBooleanOpResult(RunState(), increased)) {
      return RuntimeActionResult::Failure("the rolling-stock result capture is unavailable");
    }

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(RollingStockInsufficientResourcesTestCase,
                     RollingStockInsufficientResourcesTest)
