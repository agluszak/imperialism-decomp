#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeSemanticCapture.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Exercise the one retail policy decrement that depends on treasury: 75 becomes 50 only when
// the nation has more than 10,000 in its treasury.
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

    nation->needLevelByNation[targetNationSlot] = 75;
    nation->treasuryValue10 = 10001;

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("source", static_cast<int>(sourceNationSlot));
    caseCapture.Set("target", static_cast<int>(targetNationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->DecrementNeedLevelByNationStep(targetNationSlot);
    if (!CaptureVoidOpResult(RunState())) {
      return RuntimeActionResult::Failure("the void operation result capture is unavailable");
    }

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TradePolicyStepTestCase, TradePolicyStepTest)
