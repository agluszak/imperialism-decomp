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

// Prepare the human player's trade phase through the retail virtual.
class PlayerTradePhaseResetTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("reset the player trade phase", ResetPlayerTradePhase());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult ResetPlayerTradePhase() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0 || nation->diplomacyEligibilityA0 == 0) {
      return RuntimeActionResult::Failure("the loaded active nation is not a human great power");
    }

    TCity* city = nation->city;
    for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
      city->orderCountByType5c[slot] = 0;
    }
    city->orderCountByType5c[1] = 2;
    city->orderCountByType5c[5] = 1;
    city->orderCountByType5c[10] = 1;

    for (int resource = 0; resource < kResourceKindCount; ++resource) {
      nation->rememberedTradeOffersByResource[resource] = 0;
      nation->itemPotentials[resource] = 9;
    }
    city->CityStockByType(kResourceCotton) = 3;
    city->CityStockByType(kResourceWool) = 4;
    city->CityStockByType(kResourceTimber) = 5;
    nation->rememberedTradeOffersByResource[kResourceCotton] = 7;
    nation->rememberedTradeOffersByResource[kResourceWool] = -1;
    nation->rememberedTradeOffersByResource[kResourceTimber] = 2;

    nation->unfilledTradeOfferCount = 4;
    nation->budgetPoolBase = 600;
    nation->budgetPoolDelta = -140;
    nation->merchantCapacity = 19;
    nation->availableMerchantCapacity = 7;
    nation->AddAmountToAidAllocationMatrixCellAndTotal(37, kResourceSteel, kMinorNationFirstSlot);

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    nation->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(PlayerTradePhaseResetTestCase, PlayerTradePhaseResetTest)
