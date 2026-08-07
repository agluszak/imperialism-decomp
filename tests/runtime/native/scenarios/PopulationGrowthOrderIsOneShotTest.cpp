#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/city/TCity.h"
#include "game/city/TPopGrowthOrder.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// A paid population-growth order is consumed by the city's ordinary end-phase order loop. The
// second phase must not add the same workers again after the first phase clears the order.
class PopulationGrowthOrderIsOneShotTestCase : public EasyMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_REQUIRE(OnePaidOrderProducesPopulationOnce());
    RT_PASS();

    RT_END();
  }

private:
  bool OnePaidOrderProducesPopulationOnce() {
    TGreatPower* player = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    TCity* city = player != 0 ? player->city : 0;
    if (city == 0 || city->productionSummary1d8 == 0) {
      return false;
    }

    TPopGrowthOrder* order = static_cast<TPopGrowthOrder*>(city->trailingOrderSlots1b0[9]);
    if (order == 0) {
      return false;
    }

    order->SetQuantity(0);
    city->cityStockFurnitureD2 = static_cast<short>(city->cityStockFurnitureD2 + 1);
    city->cityStockClothingD0 = static_cast<short>(city->cityStockClothingD0 + 1);
    city->cityStockCannedFoodC4 = static_cast<short>(city->cityStockCannedFoodC4 + 1);
    city->productionAccum1fc[0x0f] = static_cast<short>(city->productionAccum1fc[0x0f] + 1);
    if (!order->SetQuantity(1)) {
      return false;
    }

    short populationBefore = city->productionSummary1d8->populationCount08;
    city->EndCityPhase();
    short populationAfterFirstPhase = city->productionSummary1d8->populationCount08;
    city->EndCityPhase();

    return order->quantity == 0 && populationAfterFirstPhase == populationBefore + 1 &&
           city->productionSummary1d8->populationCount08 == populationAfterFirstPhase;
  }
};

} // namespace

RUNTIME_TEST_FACTORY(PopulationGrowthOrderIsOneShotTestCase, PopulationGrowthOrderIsOneShotTest)
