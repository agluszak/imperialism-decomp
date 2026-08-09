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

// Turn three lumber and one fabric into a merchant-capacity point through the retail nation rule.
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

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    const bool increased = nation->IncreaseMerchantMarine() != 0;
    if (!CaptureBooleanOpResult(RunState(), increased)) {
      return RuntimeActionResult::Failure("the merchant-marine result capture is unavailable");
    }

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(MerchantMarineTestCase, MerchantMarineTest)
