#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Exercise the one retail policy decrement that depends on treasury: 75 becomes 50 only when
// the nation has more than 10,000 in its treasury. The captured input and result are the
// differential oracle.
class TradePolicyStepTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("decrement one trade policy level", DecrementTradePolicy());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult DecrementTradePolicy() {
    const NationSlot sourceNationSlot = g_pSimMgr->GetActiveNationId();
    const NationSlot targetNationSlot = sourceNationSlot == 0 ? 1 : 0;
    TGreatPower* nation = g_apNationStates[sourceNationSlot];
    if (nation == 0) {
      return RuntimeActionResult::Failure("the loaded player has no major-nation state");
    }

    short needLevelBefore[kNationSlotCount];
    int nationIndex;
    for (nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
      needLevelBefore[nationIndex] = nation->needLevelByNation[nationIndex];
    }
    nation->needLevelByNation[targetNationSlot] = 75;
    nation->treasuryValue10 = 10001;

    JSON_Value* inputState = 0;
    if (!BuildRuntimeGameState(RunState(), &inputState)) {
      return RuntimeActionResult::Failure("the semantic trade-policy input capture is unavailable");
    }
    RunState().SetCapture("trade_policy_step_input", inputState);

    nation->DecrementNeedLevelByNationStep(targetNationSlot);

    if (nation->needLevelByNation[targetNationSlot] != 50 || nation->treasuryValue10 != 10001) {
      return RuntimeActionResult::Failure(
          "retail did not decrement the treasury-gated trade policy");
    }
    for (nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
      if (nationIndex != targetNationSlot &&
          nation->needLevelByNation[nationIndex] != needLevelBefore[nationIndex]) {
        return RuntimeActionResult::Failure("retail changed an unrelated trade policy");
      }
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TradePolicyStepTestCase, TradePolicyStepTest)
