#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Set one bilateral policy to the retail 300 score.
class TradePolicySetTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("set trade policy", SetTradePolicy());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult SetTradePolicy() {
    const NationSlot sourceNationSlot = g_pSimMgr->GetActiveNationId();
    const NationSlot targetNationSlot =
        static_cast<NationSlot>((sourceNationSlot + 1) % kMajorNationCount);
    const short grantAmount = 1000;
    const short kBoycottPolicy = 300;
    TGreatPower* nation = g_apNationStates[sourceNationSlot];
    if (nation == 0 || sourceNationSlot == targetNationSlot) {
      return RuntimeActionResult::Failure("the loaded player cannot set a bilateral trade policy");
    }

    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, grantAmount)) {
      return RuntimeActionResult::Failure("retail rejected the preexisting diplomacy grant");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(sourceNationSlot));
    caseCapture.Set("target", static_cast<int>(targetNationSlot));
    caseCapture.Set("policy", static_cast<int>(kBoycottPolicy));
    RunState().SetCapture("case", caseCapture.Release());

    nation->SetTradePolicyTo(targetNationSlot, kBoycottPolicy);

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TradePolicySetTestCase, TradePolicySetTest)
