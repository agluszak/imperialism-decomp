#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/trade_ui_globals.h"
#include "game/resource_domain_types.h"
#include "game/ui_widgets/TTradeMgr.h"

namespace {

// Run the retail price pass over a deliberately varied market. The before/after GameState
// captures are the differential oracle.
class TradeMarketPriceTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("calculate new world prices", CalculateNewWorldPrices());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult CalculateNewWorldPrices() {
    if (g_pTradeMgr == 0) {
      return RuntimeActionResult::Failure("the loaded game has no trade market");
    }

    TTradeMgr* tradeManager = g_pTradeMgr;
    for (int resource = kResourceCotton; resource < kResourceManufacturedEnd; ++resource) {
      TTradeMgr::NationMetricCategoryRow& row = tradeManager->categoryRows[resource];
      row.previousPrice = static_cast<short>(100 + resource);
      row.price = static_cast<short>(400 + resource * 17);
      row.basePrice = static_cast<short>(200 + resource * 13);
      row.numRequests = static_cast<short>(20 + resource);
      row.numOffers = static_cast<short>(40 + resource);
      row.amountOffered = static_cast<short>(60 + resource);
      row.adjustedNumOffers = static_cast<double>(resource) + 0.5;
    }

    TTradeMgr::NationMetricCategoryRow& cotton = tradeManager->categoryRows[kResourceCotton];
    cotton.price = 1000;
    cotton.basePrice = 100;
    cotton.numRequests = 1;
    cotton.adjustedNumOffers = 4.5;

    TTradeMgr::NationMetricCategoryRow& wool = tradeManager->categoryRows[kResourceWool];
    wool.price = 50;
    wool.basePrice = 10;
    wool.numRequests = 20;
    wool.adjustedNumOffers = 10.0;

    TTradeMgr::NationMetricCategoryRow& timber = tradeManager->categoryRows[kResourceTimber];
    timber.price = 50;
    timber.basePrice = 1000;
    timber.numRequests = 0;
    timber.adjustedNumOffers = 100.0;

    TTradeMgr::NationMetricCategoryRow& coal = tradeManager->categoryRows[kResourceCoal];
    coal.price = 400;
    coal.basePrice = 100;
    coal.numRequests = 10;
    coal.adjustedNumOffers = 10.0;

    TTradeMgr::NationMetricCategoryRow& iron = tradeManager->categoryRows[kResourceIron];
    iron.price = 800;
    iron.basePrice = 100;
    iron.numRequests = 10;
    iron.adjustedNumOffers = 10.0;

    TTradeMgr::NationMetricCategoryRow& horses = tradeManager->categoryRows[kResourceHorses];
    horses.price = 720;
    horses.basePrice = 100;
    horses.numRequests = 14;
    horses.adjustedNumOffers = 10.5;

    TTradeMgr::NationMetricCategoryRow& oil = tradeManager->categoryRows[kResourceOil];
    oil.price = 20000;
    oil.basePrice = 200;
    oil.numRequests = 10;
    oil.adjustedNumOffers = 10.0;

    TTradeMgr::NationMetricCategoryRow& food = tradeManager->categoryRows[kResourceFood];
    food.price = 500;
    food.basePrice = 50;
    food.numRequests = 3;
    food.adjustedNumOffers = 11.0;

    TTradeMgr::NationMetricCategoryRow& clothing = tradeManager->categoryRows[kResourceClothing];
    clothing.price = 1700;
    clothing.basePrice = 800;
    clothing.numRequests = 19;
    clothing.adjustedNumOffers = 10.25;

    TTradeMgr::NationMetricCategoryRow& furniture = tradeManager->categoryRows[kResourceFurniture];
    furniture.price = 1850;
    furniture.basePrice = 900;
    furniture.numRequests = 5;
    furniture.adjustedNumOffers = 8.5;

    TTradeMgr::NationMetricCategoryRow& hardware = tradeManager->categoryRows[kResourceHardware];
    hardware.price = 900;
    hardware.basePrice = 600;
    hardware.numRequests = 100;
    hardware.adjustedNumOffers = 0.0;

    TTradeMgr::NationMetricCategoryRow& arms = tradeManager->categoryRows[kResourceArms];
    arms.price = 2222;
    arms.basePrice = 1000;
    arms.numRequests = 77;
    arms.adjustedNumOffers = 3.25;

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(JsonNullValue());
    if (!started.Succeeded()) {
      return started;
    }

    tradeManager->CalculateNewWorldPrices();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TradeMarketPriceTestCase, TradeMarketPriceTest)
