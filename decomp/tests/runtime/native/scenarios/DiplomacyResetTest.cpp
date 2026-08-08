#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/diplomacy_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Reset the active nation's posted diplomacy state. The retail routine clears every policy and
// one-time grant, while posting recurring grants again through its normal treasury path.
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

    const int treasuryBeforeEntries = nation->treasuryValue10;
    const int grantTotalBeforeEntries = nation->grantTotalCost;
    nation->diplomacyPolicyByNation[policyTarget] = kDiplomacyProposalBuildConsulate;

    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(oneTimeGrantTarget,
                                                                  oneTimeGrant) ||
        !nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(recurringGrantTarget,
                                                                  recurringGrantEntry)) {
      return RuntimeActionResult::Failure("retail rejected the seeded diplomacy grants");
    }

    JSON_Value* inputState = 0;
    if (!BuildRuntimeGameState(RunState(), &inputState)) {
      return RuntimeActionResult::Failure("the semantic diplomacy input capture is unavailable");
    }
    RunState().SetCapture("diplomacy_commitments_input", inputState);

    nation->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();

    for (short resetTargetNation = 0; resetTargetNation < kNationSlotCount; ++resetTargetNation) {
      if (nation->diplomacyPolicyByNation[resetTargetNation] != -1) {
        return RuntimeActionResult::Failure("reset retained a diplomacy policy");
      }
    }
    if (nation->diplomacyGrantByNation[oneTimeGrantTarget] != -1 ||
        nation->diplomacyGrantByNation[recurringGrantTarget] != recurringGrantEntry) {
      return RuntimeActionResult::Failure(
          "reset did not clear one-time and retain recurring grants");
    }
    if (nation->treasuryValue10 != treasuryBeforeEntries - oneTimeGrant - recurringGrant * 2 ||
        nation->grantTotalCost != grantTotalBeforeEntries + oneTimeGrant + recurringGrant * 2) {
      return RuntimeActionResult::Failure(
          "reset did not repost the recurring grant through treasury");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(DiplomacyResetTestCase, DiplomacyResetTest)
