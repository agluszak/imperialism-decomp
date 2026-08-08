#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Exercise TGreatPower's grant entry accounting on the retail-produced beginning-of-game save.
// The fixture's active power has 10,000 treasury and 10,500 available diplomacy budget: a
// 10,000 grant leaves exactly 500, so the next standard 1,000 grant must be rejected without
// altering either target's entry or the already committed total.
class DiplomacyGrantEntryTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("set, reject, replace and clear diplomacy grants", ExerciseGrantEntries());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult ExerciseGrantEntries() {
    const short activeNationSlot = g_pSimMgr->GetActiveNationId();
    const short fundedTarget = 0;
    const short rejectedTarget = 1;
    const short initialGrant = 10000;
    const short replacementGrant = 3000;
    const short rejectedGrant = 1000;
    const short clearGrant = -1;
    TGreatPower* nation = g_apNationStates[activeNationSlot];
    if (nation == 0 || activeNationSlot == fundedTarget || activeNationSlot == rejectedTarget) {
      return RuntimeActionResult::Failure("the loaded player cannot make the grant-target checks");
    }

    const int initialTreasury = nation->treasuryValue10;
    const int initialGrantTotal = nation->grantTotalCost;
    if (nation->diplomacyGrantByNation[fundedTarget] != clearGrant ||
        nation->diplomacyGrantByNation[rejectedTarget] != clearGrant || initialGrantTotal != 0 ||
        nation->ComputeAvailableDiplomacyBudget() != initialTreasury + 500 ||
        initialTreasury != initialGrant) {
      return RuntimeActionResult::Failure(
          "the beginning-of-game fixture does not have the expected grant budget state");
    }

    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(fundedTarget, initialGrant) ||
        nation->diplomacyGrantByNation[fundedTarget] != initialGrant ||
        nation->grantTotalCost != initialGrantTotal + initialGrant ||
        nation->treasuryValue10 != initialTreasury - initialGrant) {
      return RuntimeActionResult::Failure("the funded diplomacy grant did not debit the treasury");
    }

    if (nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(rejectedTarget, rejectedGrant) ||
        nation->diplomacyGrantByNation[rejectedTarget] != clearGrant ||
        nation->diplomacyGrantByNation[fundedTarget] != initialGrant ||
        nation->grantTotalCost != initialGrantTotal + initialGrant ||
        nation->treasuryValue10 != initialTreasury - initialGrant) {
      return RuntimeActionResult::Failure(
          "an unaffordable diplomacy grant changed the committed grant state");
    }

    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(fundedTarget, replacementGrant) ||
        nation->diplomacyGrantByNation[fundedTarget] != replacementGrant ||
        nation->grantTotalCost != initialGrantTotal + replacementGrant ||
        nation->treasuryValue10 != initialTreasury - replacementGrant) {
      return RuntimeActionResult::Failure(
          "replacing a diplomacy grant did not refund and debit the treasury correctly");
    }

    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(fundedTarget, clearGrant) ||
        nation->diplomacyGrantByNation[fundedTarget] != clearGrant ||
        nation->grantTotalCost != initialGrantTotal || nation->treasuryValue10 != initialTreasury) {
      return RuntimeActionResult::Failure(
          "clearing a diplomacy grant did not restore the treasury");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(DiplomacyGrantEntryTestCase, DiplomacyGrantEntryTest)
