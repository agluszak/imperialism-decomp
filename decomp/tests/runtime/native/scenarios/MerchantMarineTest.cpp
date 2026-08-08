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

// Turn three lumber and one fabric into a merchant-capacity point through the retail nation
// rule.
class MerchantMarineTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("increase merchant marine", IncreaseMerchantMarine());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult IncreaseMerchantMarine() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city-and-merchant state");
    }

    TCity* city = nation->city;
    city->CityStockByType(kResourceLumber) = 3;
    city->CityStockByType(kResourceFabric) = 1;
    nation->merchantCapacity = 15;

    JSON_Value* inputState = 0;
    if (!BuildRuntimeGameState(RunState(), &inputState)) {
      return RuntimeActionResult::Failure(
          "the semantic merchant-marine input capture is unavailable");
    }
    RunState().SetCapture("merchant_marine_input", inputState);

    if (nation->IncreaseMerchantMarine() == 0) {
      return RuntimeActionResult::Failure("retail merchant marine could not be increased");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(MerchantMarineTestCase, MerchantMarineTest)
