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

// Allocate one city's steel need. The request exceeds both its available surplus and the
// remaining transport capacity, so retail must apply the two clamps in order.
class DirectTransportTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("directly transport a city resource", DirectTransport());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult DirectTransport() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
    }

    TCity* city = nation->city;
    int resource;
    for (resource = 0; resource < kResourceKindCount; ++resource) {
      nation->needCurrentByType[resource] = 0;
      nation->needTargetByType[resource] = 0;
    }
    nation->needCurrentByType[kResourceCotton] = 7;
    nation->needTargetByType[kResourceCotton] = 7;
    nation->needCurrentByType[kResourceSteel] = 10;
    nation->needTargetByType[kResourceSteel] = 4;
    nation->transportCapacity = 15;
    nation->reservedTransportCapacity = 11;
    city->CityStockByType(kResourceSteel) = 2;

    JSON_Value* inputState = 0;
    if (!BuildRuntimeGameState(RunState(), &inputState)) {
      return RuntimeActionResult::Failure(
          "the semantic direct-transport input capture is unavailable");
    }
    RunState().SetCapture("direct_transport_input", inputState);

    const short transported = city->DirectTransport(kResourceSteel, 9);
    if (transported != 4 || city->CityStockByType(kResourceSteel) != 6 ||
        nation->needTargetByType[kResourceSteel] != 8 || nation->reservedTransportCapacity != 15) {
      return RuntimeActionResult::Failure("retail direct transport applied the wrong allocation");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(DirectTransportTestCase, DirectTransportTest)
