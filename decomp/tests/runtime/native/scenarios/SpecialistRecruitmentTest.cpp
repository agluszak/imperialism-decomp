#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeSemanticCapture.h"

#include "game/city/TCity.h"
#include "game/city/TUnitOrder.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Exercise the specialist branch of TUnitOrder::Produce against the retail-produced
// beginning-of-game save. Rust reads before/case/after and compares the complete state.
class SpecialistRecruitmentTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("produce one specialist military unit", ProduceSpecialist());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult ProduceSpecialist() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0 || nation->militaryUnitList44 == 0 ||
        nation->turnSummaryQueue == 0) {
      return RuntimeActionResult::Failure("the loaded player has no recruitment state");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    caseCapture.Set("unit_kind", "sappers");
    caseCapture.Set("quantity", 1);
    RunState().SetCapture("case", caseCapture.Release());

    TUnitOrder order;
    order.IUnitOrder(nation->city, 24, -1, 0, -1, 0, 0, kHighSkillWorkforceMode, 1);
    order.quantity = 1;
    order.Produce();
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

RUNTIME_TEST_FACTORY(SpecialistRecruitmentTestCase, SpecialistRecruitmentTest)
