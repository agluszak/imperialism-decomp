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

// Restore remembered trade bids, clamp sell offers to the current city stock, and clear the
// aid-allocation matrix.
class RecallTradeBidsTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("recall remembered trade bids", RecallTradeBids());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult RecallTradeBids() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no trade-bid city state");
    }

    TCity* city = nation->city;
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
    const int aidAllocationCount = static_cast<int>(sizeof(nation->aidAllocationMatrix) /
                                                    sizeof(nation->aidAllocationMatrix[0]));
    int matrixIndex;
    for (matrixIndex = 0; matrixIndex < aidAllocationCount; ++matrixIndex) {
      nation->aidAllocationMatrix[matrixIndex] = 0;
    }
    nation->aidAllocationMatrix[0] = 17;
    nation->aidAllocationMatrix[aidAllocationCount - 1] = -9;

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    nation->RecallTradeBids();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(RecallTradeBidsTestCase, RecallTradeBidsTest)
