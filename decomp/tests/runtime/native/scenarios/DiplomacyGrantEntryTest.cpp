#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Set one semantic grant on the retail-produced beginning-of-game save. The
// direct game-state capture is the accounting oracle.
class DiplomacyGrantEntryTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("set diplomacy grant", SetGrantEntry());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult SetGrantEntry() {
    const short activeNationSlot = g_pSimMgr->GetActiveNationId();
    const short targetNationSlot = 0;
    const short grantAmount = 10000;
    TGreatPower* nation = g_apNationStates[activeNationSlot];
    if (nation == 0 || activeNationSlot == targetNationSlot) {
      return RuntimeActionResult::Failure("the loaded player cannot make the grant-target check");
    }

    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, grantAmount)) {
      return RuntimeActionResult::Failure("retail rejected the diplomacy grant");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(DiplomacyGrantEntryTestCase, DiplomacyGrantEntryTest)
