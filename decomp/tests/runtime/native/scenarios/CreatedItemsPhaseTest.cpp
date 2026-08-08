#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Deliver the active nation's already allocated resources from the retail-produced
// beginning-of-game save. The direct game-state capture is the result oracle.
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

    nation->AddCreatedItems();
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(CreatedItemsPhaseTestCase, CreatedItemsPhaseTest)
