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

// Rebuild the active nation's trade capacity from a deliberately small city-order state.
class TradeCapacityRefreshTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("refresh trade capacity from city industry", RefreshTradeCapacity());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult RefreshTradeCapacity() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city-and-trade state");
    }

    TCity* city = nation->city;
    for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
      city->orderCountByType5c[slot] = 0;
    }
    city->orderCountByType5c[1] = 2;
    city->orderCountByType5c[5] = 1;
    city->orderCountByType5c[10] = 1;

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TradeCapacityRefreshTestCase, TradeCapacityRefreshTest)
