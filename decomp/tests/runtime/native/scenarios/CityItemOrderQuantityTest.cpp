#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

RuntimeActionResult SetClothingOrderQuantity(RuntimeRun& run, bool seedOne, short targetQuantity) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0 || nation->city->productionSummary1d8 == 0) {
    return RuntimeActionResult::Failure("the loaded player has no complete city state");
  }

  TCity* city = nation->city;
  TProductionOrder* base = city->orderSlotsE4[kResourceClothing];
  if (base == 0) {
    return RuntimeActionResult::Failure("the clothing order is absent");
  }
  TItemOrder* order = static_cast<TItemOrder*>(base);
  if (order->ownerCity != city || order->productionSummary != city->productionSummary1d8 ||
      order->resourceTypeIndex != kResourceClothing ||
      order->primaryInputResourceId != kResourceFabric || order->secondaryInputResourceId != -1 ||
      order->productionSlot != 1 || order->quantity != 0 || order->requestedQuantity4c != 0 ||
      order->reservedWorkforce != 0) {
    return RuntimeActionResult::Failure("the retail fixture has an unexpected clothing order");
  }
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    if (order->trackingSlots[resource] != 0) {
      return RuntimeActionResult::Failure(
          "the retail fixture clothing order already tracks reserved resources");
    }
  }
  if (city->productionSummary1d8->strength < 2) {
    return RuntimeActionResult::Failure("the retail fixture has insufficient production labor");
  }

  city->CityStockByType(kResourceFabric) = 2;
  city->productionOrderTable1dc[1] = 1;
  city->productionAccum1fc[1] = 1;
  if (seedOne && !order->SetQuantity(1)) {
    return RuntimeActionResult::Failure("the seeded clothing order was rejected");
  }

  JsonObject caseCapture;
  caseCapture.Set("nation", static_cast<int>(nationSlot));
  caseCapture.Set("output", "clothing");
  caseCapture.Set("quantity", static_cast<int>(targetQuantity));

  RuntimeDifferentialCapture capture(run);
  RuntimeActionResult started = capture.Begin(caseCapture.Release());
  if (!started.Succeeded()) {
    return started;
  }

  return capture.Finish(order->SetQuantity(targetQuantity));
}

class CityItemOrderIncreaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("increase an ordinary city item order", SetClothingOrderQuantity(RunState(), false, 1));
    RT_PASS();

    RT_END();
  }
};

class CityItemOrderDecreaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("release an ordinary city item order", SetClothingOrderQuantity(RunState(), true, 0));
    RT_PASS();

    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(CityItemOrderIncreaseTestCase, CityItemOrderIncreaseTest)
RUNTIME_TEST_FACTORY(CityItemOrderDecreaseTestCase, CityItemOrderDecreaseTest)
