#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

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

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    return capture.Finish(nation->IncreaseRollingStock() != 0);
  }
};

} // namespace

RUNTIME_TEST_FACTORY(RollingStockInsufficientResourcesTestCase,
                     RollingStockInsufficientResourcesTest)
