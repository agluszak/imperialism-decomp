#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Exercise the retail bid snapshot and purchased-item commit against a retail-produced save.
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

    nation->SetItemPotentials(kResourceFabric, -1);
    nation->SetItemPotentials(kResourceClothing, -1);

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->RememberTradeBids();
    nation->PurchaseItem(kResourceFabric, 3, 7);
    nation->PurchaseItem(kResourceFood, -30, 1);
    nation->AddPurchasedItems();

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(PurchasedItemsPhaseTestCase, PurchasedItemsPhaseTest)
