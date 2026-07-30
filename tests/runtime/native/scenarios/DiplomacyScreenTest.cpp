#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/DiplomacyScreen.h"
#include "screens/ModalScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/core/global_data_tables.h"
#include "game/diplomacy_domain_types.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation_domain_types.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// The icon offset the map draws over a nation the player has an alliance posted towards.
const short kAllianceTreatyIcon = 0x30;

// The foreign minister's screen, end to end: inspect a nation, render its relationships, post a
// consulate to a minor nation and an alliance to a major one, then answer two offer sheets --
// one accepted, one rejected -- before returning to the map.
//
// Each treaty action is the same gesture with a different topic selected, and posting a policy
// that is already posted retracts it, which is why every expectation here is a toggle rather
// than a constant.
class DiplomacyScreenTestCase : public EasyMapScriptScenario {
public:
  DiplomacyScreenTestCase()
      : targetNation(-1), policyBeforeAction(-1), allianceTargetNation(-1),
        alliancePolicyBeforeAction(-1) {}

  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }
  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventDiplomacyMap) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

protected:
  void Script() override {
    RT_BEGIN();

    RT_OPEN_TO("open the diplomacy map", StrategicMap().OpenDiplomacy(), DiplomacyScreen);
    RT_REQUIRE(Diplomacy().HasMinisterControls());
    RT_REQUIRE(Diplomacy().ToolbarButtonShowsSelectedArt());
    RT_HOLD_SCREEN("diplomacy");

    targetNation = FirstSelectableMinorNation();
    RT_REQUIRE_NE(-1, targetNation);
    RT_DO("inspect a foreign nation", Diplomacy().SelectNation(targetNation));
    RT_REQUIRE_EQ(targetNation, Diplomacy().SelectedNation());

    RT_ACTIVATE_AND_AWAIT(
        "render that nation's relationships", Diplomacy().ShowRelationshipOverlay(),
        Diplomacy().RelationshipOverlaySourceNation() == targetNation, kObserveUiStateChanged);

    RT_DO("select the treaties topic", Diplomacy().ShowTreaties());
    RT_REQUIRE(Diplomacy().TreatiesTopicIsActive());

    policyBeforeAction = PolicyTowards(targetNation);
    RT_DO("build a consulate in that nation", Diplomacy().SelectNation(targetNation));
    RT_REQUIRE_EQ(TogglePolicy(policyBeforeAction, kDiplomacyProposalBuildConsulate),
                  PolicyTowards(targetNation));
    // A consulate with a minor nation is a valid request, so it commits silently; a modal here
    // would be the rejection notice, which means the target was chosen wrongly.
    RT_REQUIRE(!ModalScreen::AnyPresent());

    RT_DO("select the alliance treaty action", Diplomacy().SelectAllianceAction());
    RT_REQUIRE_EQ(static_cast<int>(kDipActionAlliance), Diplomacy().ActionCode());

    allianceTargetNation = FirstValidAllianceTarget();
    RT_REQUIRE_NE(-1, allianceTargetNation);
    alliancePolicyBeforeAction = PolicyTowards(allianceTargetNation);
    RT_DO("offer that power an alliance", Diplomacy().SelectNation(allianceTargetNation));
    RT_REQUIRE_EQ(ExpectedAlliancePolicy(), PolicyTowards(allianceTargetNation));
    RT_REQUIRE(!ModalScreen::AnyPresent());
    // Retracting a policy leaves nothing to draw, so only a posted alliance has an icon.
    if (ExpectedAlliancePolicy() == kDiplomacyProposalAlliance) {
      RT_REQUIRE_EQ(kAllianceTreatyIcon, Diplomacy().PolicyIconForNation(allianceTargetNation));
    }

    // Posing an offer enters the game's own modal loop, so the answer is armed first. Without
    // that the sheet would never be answered and the run would stop inside PoseOffer.
    RT_REQUIRE(Diplomacy().AcceptPublishesOfferEvent());
    RT_DO("arm the offer sheet's accept", Diplomacy().ArmAcceptResponse());
    RT_DO("pose an offer for acceptance",
          Diplomacy().PoseNonAggressionOffer(ActiveNation(), allianceTargetNation));
    RT_REQUIRE(Diplomacy().LastResponseWasAccept());

    RT_REQUIRE(Diplomacy().RejectPublishesOfferEvent());
    RT_DO("arm the offer sheet's reject", Diplomacy().ArmRejectResponse());
    RT_DO("pose an offer for rejection",
          Diplomacy().PoseNonAggressionOffer(ActiveNation(), allianceTargetNation));
    RT_REQUIRE(Diplomacy().LastResponseWasReject());

    RT_CLOSE_TO_MAP("leave the diplomacy map", Diplomacy().Close());
    RT_PASS();

    RT_END();
  }

private:
  short ActiveNation() const {
    return g_pSimMgr->GetActiveNationId();
  }

  TGreatPower* Player() const {
    return g_apNationStates[ActiveNation()];
  }

  short PolicyTowards(short nationSlot) const {
    TGreatPower* player = Player();
    return player != 0 && nationSlot >= 0 ? player->diplomacyPolicyByNation[nationSlot] : -2;
  }

  // Posting the policy that is already posted retracts it, so the expected result depends on
  // what was there before rather than on the action alone.
  static short TogglePolicy(short previousPolicy, int proposal) {
    return previousPolicy == proposal ? -1 : static_cast<short>(proposal);
  }

  short ExpectedAlliancePolicy() const {
    return TogglePolicy(alliancePolicyBeforeAction, kDiplomacyProposalAlliance);
  }

  // A fresh major-to-major relationship cannot build a consulate: the original's validation
  // requires the pair's side-effect matrix to be clear, which is the initial major-to-minor
  // state. Picking a real minor nation is what makes the consulate commit rather than open the
  // rejection notice.
  short FirstSelectableMinorNation() const {
    for (short nation = kMinorNationFirstSlot; nation < kNationSlotCount; ++nation) {
      if (nation != ActiveNation() && g_apTerrainTypeDescriptorTable[nation] != 0) {
        return nation;
      }
    }
    return -1;
  }

  // An alliance is a major-power treaty, and the game itself decides which targets are legal.
  short FirstValidAllianceTarget() const {
    for (short nation = 0; nation < kMajorNationCount; ++nation) {
      if (nation != ActiveNation() && g_apTerrainTypeDescriptorTable[nation] != 0 &&
          g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              ActiveNation(), nation, kDipActionAlliance)) {
        return nation;
      }
    }
    return -1;
  }

  short targetNation;
  short policyBeforeAction;
  short allianceTargetNation;
  short alliancePolicyBeforeAction;
};

} // namespace

RUNTIME_TEST_FACTORY(DiplomacyScreenTestCase, DiplomacyScreenTest)
