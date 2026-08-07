#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Apply one purchase and two sales to the retail-produced beginning-of-game save. The Rust
// differential runner replays the same signed settlements and compares the complete state.
class MajorTradeSettlementTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("settle purchase and both sale classes", SettleTrade());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult SettleTrade() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0) {
      return RuntimeActionResult::Failure("the loaded player has no major-nation state");
    }

    const short previousFabric = nation->purchasedItemsByResource[kResourceFabric];
    const short previousClothing = nation->purchasedItemsByResource[kResourceClothing];
    const int previousTreasury = nation->treasuryValue10;
    const short previousCapacity = nation->availableMerchantCapacity;
    const int previousPoolBase = nation->budgetPoolBase;
    const int previousPoolDelta = nation->budgetPoolDelta;
    const int previousSpecialBalance = nation->field910;

    nation->PurchaseItem(kResourceFabric, 3, 7);
    nation->PurchaseItem(kResourceClothing, -2, 5);
    nation->PurchaseItem(kResourceFabric, -1, 4);

    if (nation->purchasedItemsByResource[kResourceFabric] != previousFabric + 2 ||
        nation->purchasedItemsByResource[kResourceClothing] != previousClothing - 2 ||
        nation->treasuryValue10 != previousTreasury - 7 ||
        nation->availableMerchantCapacity != previousCapacity - 3 ||
        nation->budgetPoolBase != previousPoolBase + 14 ||
        nation->budgetPoolDelta != previousPoolDelta - 21 ||
        nation->field910 != previousSpecialBalance + 2) {
      return RuntimeActionResult::Failure("trade settlement diverged from the retail state update");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(MajorTradeSettlementTestCase, MajorTradeSettlementTest)
