#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeSemanticCapture.h"

#include "game/diplomacy_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Reset the active nation's posted diplomacy state after seeding one policy and two grants.
class DiplomacyResetTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("reset diplomacy policies and grants", ResetDiplomacyEntries());
    RT_PASS();

    RT_END();
  }

private:
  static short OtherMajorNation(short activeNationSlot, int offset) {
    return static_cast<short>((static_cast<int>(activeNationSlot) + offset) % kMajorNationCount);
  }

  RuntimeActionResult ResetDiplomacyEntries() {
    const short activeNationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[activeNationSlot];
    if (nation == 0) {
      return RuntimeActionResult::Failure("the loaded player has no major-nation state");
    }

    const short policyTarget = OtherMajorNation(activeNationSlot, 1);
    const short oneTimeGrantTarget = OtherMajorNation(activeNationSlot, 2);
    const short recurringGrantTarget = OtherMajorNation(activeNationSlot, 3);
    const short oneTimeGrant = 1000;
    const short recurringGrant = 3000;
    const short kRecurringGrantFlag = 0x4000;
    const short recurringGrantEntry = static_cast<short>(recurringGrant | kRecurringGrantFlag);

    for (short targetNation = 0; targetNation < kNationSlotCount; ++targetNation) {
      if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, -1)) {
        return RuntimeActionResult::Failure("retail rejected clearing a diplomacy grant");
      }
    }

    nation->diplomacyPolicyByNation[policyTarget] = kDiplomacyProposalBuildConsulate;

    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(oneTimeGrantTarget,
                                                                  oneTimeGrant) ||
        !nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(recurringGrantTarget,
                                                                  recurringGrantEntry)) {
      return RuntimeActionResult::Failure("retail rejected the seeded diplomacy grants");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(activeNationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
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

RUNTIME_TEST_FACTORY(DiplomacyResetTestCase, DiplomacyResetTest)
