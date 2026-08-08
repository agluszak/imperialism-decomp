#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Apply one purchase and two sales to the retail-produced beginning-of-game save. Rust reads
// before/case/after and compares the complete state.
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

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    JsonArray purchases;
    JsonObject buyFabric;
    buyFabric.Set("resource", "fabric");
    buyFabric.Set("amount", 3);
    buyFabric.Set("price", 7);
    purchases.Add(buyFabric.Release());
    JsonObject sellClothing;
    sellClothing.Set("resource", "clothing");
    sellClothing.Set("amount", -2);
    sellClothing.Set("price", 5);
    purchases.Add(sellClothing.Release());
    JsonObject sellFabric;
    sellFabric.Set("resource", "fabric");
    sellFabric.Set("amount", -1);
    sellFabric.Set("price", 4);
    purchases.Add(sellFabric.Release());
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    caseCapture.Set("purchases", purchases.Release());
    RunState().SetCapture("case", caseCapture.Release());

    nation->PurchaseItem(kResourceFabric, 3, 7);
    nation->PurchaseItem(kResourceClothing, -2, 5);
    nation->PurchaseItem(kResourceFabric, -1, 4);

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(MajorTradeSettlementTestCase, MajorTradeSettlementTest)
