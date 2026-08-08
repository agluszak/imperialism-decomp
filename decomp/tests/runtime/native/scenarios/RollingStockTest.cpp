#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Turn one lumber and one steel into a transport-capacity point through the retail nation rule.
class RollingStockTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("increase rolling stock", IncreaseRollingStock());
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
    city->CityStockByType(kResourceLumber) = 1;
    city->CityStockByType(kResourceSteel) = 1;
    nation->transportCapacity = 15;
    const short reservedTransportCapacity = nation->reservedTransportCapacity;

    JSON_Value* inputState = 0;
    if (!BuildRuntimeGameState(RunState(), &inputState)) {
      return RuntimeActionResult::Failure(
          "the semantic rolling-stock input capture is unavailable");
    }
    RunState().SetCapture("rolling_stock_input", inputState);

    const char increased = nation->IncreaseRollingStock();
    if (increased == 0 || city->CityStockByType(kResourceLumber) != 0 ||
        city->CityStockByType(kResourceSteel) != 0 || nation->transportCapacity != 16 ||
        nation->reservedTransportCapacity != reservedTransportCapacity) {
      return RuntimeActionResult::Failure("retail rolling stock applied the wrong state change");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(RollingStockTestCase, RollingStockTest)
