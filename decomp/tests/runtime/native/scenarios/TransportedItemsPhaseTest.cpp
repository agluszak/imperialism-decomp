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

// Commit the active great power's transported-resource ledger to its city.
class TransportedItemsPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("commit transported city resources", AddTransportedItems());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AddTransportedItems() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
    }

    TCity* city = nation->city;
    int resource;
    for (resource = 0; resource < kResourceKindCount; ++resource) {
      nation->transportedItemsByResource[resource] = 0;
    }
    city->CityStockByType(kResourceCotton) = 3;
    city->CityStockByType(kResourceWool) = 2;
    city->CityStockByType(kResourceGold) = 11;
    nation->transportedItemsByResource[kResourceCotton] = 5;
    nation->transportedItemsByResource[kResourceWool] = -7;
    nation->transportedItemsByResource[kResourceGold] = 4;

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->AddTransportedItems();
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

RUNTIME_TEST_FACTORY(TransportedItemsPhaseTestCase, TransportedItemsPhaseTest)
