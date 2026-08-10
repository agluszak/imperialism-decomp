#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Deliver the active nation's already allocated resources from the retail-produced
// beginning-of-game save.
class CreatedItemsPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("deliver allocated city resources", AddCreatedItems());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AddCreatedItems() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
    }

    JsonObject input;
    input.Set("nation", static_cast<int>(nationSlot));

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(input.Release());
    if (!started.Succeeded()) {
      return started;
    }

    nation->AddCreatedItems();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(CreatedItemsPhaseTestCase, CreatedItemsPhaseTest)
