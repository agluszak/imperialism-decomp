#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Set one bilateral policy to the retail 300 score. That score also clears the existing grant
// through the same retail operation, so the direct game-state captures cover both effects.
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

    JSON_Value* inputState = 0;
    if (!BuildRuntimeGameState(RunState(), &inputState)) {
      return RuntimeActionResult::Failure("the semantic trade-policy input capture is unavailable");
    }
    RunState().SetCapture("trade_policy_set_input", inputState);

    nation->SetTradePolicyTo(targetNationSlot, kBoycottPolicy);
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TradePolicySetTestCase, TradePolicySetTest)
