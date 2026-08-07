#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Exercise the retail bid snapshot and purchased-item commit against a retail-produced save.
// The Rust differential runner replays the same phase sequence and compares the complete state.
class PurchasedItemsPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("commit filled and unfilled trade bids", CommitPurchasedItems());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult CommitPurchasedItems() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no trade-phase city state");
    }

    const short previousFabric = nation->city->cityStockFabricC6;
    const int previousTreasury = nation->treasuryValue10;
    const short previousCapacity = nation->availableMerchantCapacity;
    const int previousPoolBase = nation->budgetPoolBase;
    const int previousPoolDelta = nation->budgetPoolDelta;

    nation->SetItemPotentials(kResourceFabric, -1);
    nation->SetItemPotentials(kResourceClothing, -1);
    nation->RememberTradeBids();
    nation->PurchaseItem(kResourceFabric, 3, 7);
    nation->PurchaseItem(kResourceFood, -30, 1);
    nation->AddPurchasedItems();

    if (nation->itemPotentials[kResourceFabric] != -1 ||
        nation->itemPotentials[kResourceClothing] != -1 ||
        nation->rememberedTradeOffersByResource[kResourceFabric] != -1 ||
        nation->rememberedTradeOffersByResource[kResourceClothing] != -1 ||
        nation->unfilledTradeTurnCountsByResource[kResourceFabric] != 0 ||
        nation->unfilledTradeTurnCountsByResource[kResourceClothing] != 1 ||
        nation->purchasedItemsByResource[kResourceFabric] != 0 ||
        nation->purchasedItemsByResource[kResourceFood] != 0 ||
        nation->city->cityStockFabricC6 != previousFabric + 3 ||
        nation->city->cityStockCannedFoodC4 != 0 ||
        nation->treasuryValue10 != previousTreasury + 9 ||
        nation->availableMerchantCapacity != previousCapacity - 3 ||
        nation->budgetPoolBase != previousPoolBase + 30 ||
        nation->budgetPoolDelta != previousPoolDelta - 21) {
      return RuntimeActionResult::Failure(
          "purchased-item phase commit diverged from the retail state update");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(PurchasedItemsPhaseTestCase, PurchasedItemsPhaseTest)
