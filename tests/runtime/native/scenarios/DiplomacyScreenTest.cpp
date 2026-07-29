#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/diplomacy_ui/TOffersPanelView.h"
#include "game/globals/global_types.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_manifest_tags.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TControl.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/globals/view_registries.h"

namespace {

class DiplomacyScreenTestCase : public RandomGameScenario {
public:
  DiplomacyScreenTestCase()
      : phase(kActivateDiplomacyScreen), targetNation(-1), policyBeforeAction(-1),
        allianceTargetNation(-1), alliancePolicyBeforeAction(-1) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateDiplomacyScreen;
    EnterScenarioStep("activating_diplomacy_screen",
                      "easy_combined_map_ready_for_diplomacy_screen");
    ContinueAfterAction();
  }

  void AdvanceScenario() override {
    if (phase == kActivateDiplomacyScreen) {
      ActivateDiplomacyScreen();
    } else if (phase == kWaitForDiplomacyScreen) {
      WaitForDiplomacyScreen();
    } else if (phase == kSelectForeignNation) {
      SelectForeignNation();
    } else if (phase == kVerifyForeignNation) {
      VerifyForeignNation();
    } else if (phase == kActivateRelationshipOverlay) {
      ActivateRelationshipOverlay();
    } else if (phase == kVerifyRelationshipOverlay) {
      VerifyRelationshipOverlay();
    } else if (phase == kActivateTreatiesTopic) {
      ActivateTreatiesTopic();
    } else if (phase == kVerifyTreatiesTopic) {
      VerifyTreatiesTopic();
    } else if (phase == kInitiatePrimaryAction) {
      InitiatePrimaryAction();
    } else if (phase == kVerifyPrimaryAction) {
      VerifyPrimaryAction();
    } else if (phase == kSelectAllianceAction) {
      SelectAllianceAction();
    } else if (phase == kInitiateAllianceAction) {
      InitiateAllianceAction();
    } else if (phase == kVerifyAllianceAction) {
      VerifyAllianceAction();
    } else if (phase == kPoseAcceptedOffer) {
      PoseAcceptedOffer();
    } else if (phase == kPoseRejectedOffer) {
      PoseRejectedOffer();
    } else if (phase == kReturnToMap) {
      ReturnToMap();
    } else {
      WaitForMap();
    }
  }

  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventDiplomacyMap) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

private:
  enum Phase {
    kActivateDiplomacyScreen,
    kWaitForDiplomacyScreen,
    kSelectForeignNation,
    kVerifyForeignNation,
    kActivateRelationshipOverlay,
    kVerifyRelationshipOverlay,
    kActivateTreatiesTopic,
    kVerifyTreatiesTopic,
    kInitiatePrimaryAction,
    kVerifyPrimaryAction,
    kSelectAllianceAction,
    kInitiateAllianceAction,
    kVerifyAllianceAction,
    kPoseAcceptedOffer,
    kPoseRejectedOffer,
    kReturnToMap,
    kWaitForMap
  };

  TDiplomacyMapView* DiplomacyView() const {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TDiplomacyMapView)) == 0) {
      return 0;
    }
    return static_cast<TDiplomacyMapView*>(mainView);
  }

  void ActivateDiplomacyScreen() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      AwaitUiChange("\"combined map was not idle before opening diplomacy\"");
      return;
    }
    phase = kWaitForDiplomacyScreen;
    EnterScenarioStep("waiting_for_diplomacy_screen", "activate_diplomacy_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.OpenDiplomacy()) {
      FailScenario("\"diplomacy toolbar control is missing or disabled\"");
      return;
    }
    Await(kObserveRuntimeBarrier, "\"diplomacy screen transition did not reach its barrier\"");
    if (!RuntimeUiDriver::PostBarrier()) {
      FailScenario("\"diplomacy screen barrier could not be posted\"");
    }
  }

  void WaitForDiplomacyScreen() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventDiplomacyMap || diplomacy == 0) {
      AwaitUiChange("\"diplomacy toolbar action did not activate diplomacy orders\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(g_ModalViewStack.GetHead());
      FailScenario("\"diplomacy toolbar action opened an unexpected modal\"");
      return;
    }
    if (diplomacy->ResolveControlByTag(kControlTagInfo) == 0 ||
        diplomacy->ResolveControlByTag(kControlTagTrty) == 0 ||
        diplomacy->ResolveControlByTag(kControlTagMkey) == 0 ||
        diplomacy->ResolveControlByTag(kControlTagEnd) == 0) {
      FailScenario("\"diplomacy orders is missing info, treaty, map-key, or back controls\"");
      return;
    }
    TPicture* diplomacyToolbarControl =
        g_pDisplayMgr == 0 || g_pDisplayMgr->activeDialog == 0
            ? 0
            : static_cast<TPicture*>(
                  g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagDipl));
    if (diplomacyToolbarControl == 0 || diplomacyToolbarControl->glyphBase84 != 0x24ea) {
      FailScenario("\"diplomacy toolbar control did not use its selected picture\"");
      return;
    }
    if (HoldAtScenarioScreen("diplomacy")) {
      RedrawWindow(diplomacy->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
      Pass();
      return;
    }
    phase = kSelectForeignNation;
    EnterScenarioStep("selecting_diplomacy_nation", "click_first_foreign_nation_on_map");
    ContinueAfterAction();
  }

  void SelectForeignNation() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before nation selection\"");
      return;
    }
    const short activeNation = g_pSimMgr->GetActiveNationId();
    // A fresh major-to-major relationship cannot build a consulate: the original
    // validation requires relationSideEffectMatrix == 0, which is the initial
    // major-to-minor state. Pick a real minor nation so the primary treaty action is
    // expected to commit rather than deliberately opening the rejection notice.
    for (short nation = 7; nation < 0x17; ++nation) {
      if (nation != activeNation && g_apTerrainTypeDescriptorTable[nation] != 0) {
        targetNation = nation;
        break;
      }
    }
    if (targetNation < 0) {
      FailScenario("\"diplomacy map has no selectable foreign nation\"");
      return;
    }
    phase = kVerifyForeignNation;
    EnterScenarioStep("verifying_diplomacy_nation", "inspect_selected_foreign_nation");
    diplomacy->ActivateNation(targetNation);
    ContinueAfterAction();
  }

  void VerifyForeignNation() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->RuntimeActiveNation() != targetNation) {
      FailScenario("\"diplomacy map click did not select and inspect the foreign nation\"");
      return;
    }
    phase = kActivateRelationshipOverlay;
    EnterScenarioStep("activating_relationship_overlay", "click_relationship_overlay");
    ContinueAfterAction();
  }

  void ActivateRelationshipOverlay() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before relationship selection\"");
      return;
    }
    phase = kVerifyRelationshipOverlay;
    EnterScenarioStep("verifying_relationship_overlay", "render_selected_nation_relationships");
    if (!RuntimeUiDriver::Activate(
            diplomacy, RuntimeControlSelector(kControlTagOvr0 + 1, RUNTIME_CLASS(TControl)))) {
      FailScenario("\"diplomacy relationship overlay control is missing or cannot receive input\"");
      return;
    }
    Await(kObserveRuntimeBarrier, "\"relationship overlay did not reach its barrier\"");
    if (!RuntimeUiDriver::PostBarrier()) {
      FailScenario("\"relationship overlay barrier could not be posted\"");
    }
  }

  void VerifyRelationshipOverlay() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->RuntimeRelationshipOverlaySourceNation() != targetNation) {
      FailScenario("\"selected foreign nation's relationships were not rendered\"");
      return;
    }
    phase = kActivateTreatiesTopic;
    EnterScenarioStep("activating_diplomacy_treaties", "click_treaties_action_topic");
    ContinueAfterAction();
  }

  void ActivateTreatiesTopic() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before treaty selection\"");
      return;
    }
    phase = kVerifyTreatiesTopic;
    EnterScenarioStep("verifying_diplomacy_treaties", "activate_treaties_action_topic");
    diplomacy->ChangeSelectedActionTopic(1);
    ContinueAfterAction();
  }

  void VerifyTreatiesTopic() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->RuntimeActionTopicIndex() != 1 ||
        diplomacy->actionCodeBC != kDipActionBuildConsulate) {
      FailScenario("\"diplomacy treaties action did not become active\"");
      return;
    }
    TGreatPower* sourceNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (sourceNation == 0) {
      FailScenario("\"active nation has no diplomacy policy state\"");
      return;
    }
    policyBeforeAction = sourceNation->diplomacyPolicyByNation[targetNation];
    phase = kInitiatePrimaryAction;
    EnterScenarioStep("initiating_diplomacy_action", "click_consulate_target_nation");
    ContinueAfterAction();
  }

  void InitiatePrimaryAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || g_apTerrainTypeDescriptorTable[targetNation] == 0) {
      FailScenario("\"diplomacy target disappeared before the consulate action\"");
      return;
    }
    phase = kVerifyPrimaryAction;
    EnterScenarioStep("verifying_diplomacy_action", "apply_consulate_diplomacy_policy");
    diplomacy->ActivateNation(targetNation);
    ContinueAfterAction();
  }

  void VerifyPrimaryAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    TGreatPower* sourceNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    const short expectedPolicy = policyBeforeAction == kDiplomacyProposalBuildConsulate
                                     ? -1
                                     : static_cast<short>(kDiplomacyProposalBuildConsulate);
    if (diplomacy == 0 || sourceNation == 0 ||
        sourceNation->diplomacyPolicyByNation[targetNation] != expectedPolicy) {
      FailScenario("\"diplomacy consulate action did not update the target policy\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(g_ModalViewStack.GetHead());
      FailScenario("\"diplomacy consulate action opened an unexpected modal\"");
      return;
    }
    phase = kSelectAllianceAction;
    EnterScenarioStep("selecting_diplomacy_alliance", "click_alliance_treaty_action");
    ContinueAfterAction();
  }

  void SelectAllianceAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before alliance selection\"");
      return;
    }
    phase = kInitiateAllianceAction;
    EnterScenarioStep("initiating_diplomacy_alliance", "click_alliance_target_nation");
    if (!RuntimeUiDriver::Activate(
            diplomacy, RuntimeControlSelector(kControlTagScr0 + 1, RUNTIME_CLASS(TControl)))) {
      FailScenario("\"diplomacy alliance action is missing or cannot receive input\"");
      return;
    }
    ContinueAfterAction();
  }

  void InitiateAllianceAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->actionCodeBC != kDipActionAlliance) {
      FailScenario("\"diplomacy alliance action did not become active\"");
      return;
    }

    const short activeNation = g_pSimMgr->GetActiveNationId();
    for (short nation = 0; nation < 7; ++nation) {
      if (nation != activeNation && g_apTerrainTypeDescriptorTable[nation] != 0 &&
          g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              activeNation, nation, kDipActionAlliance)) {
        allianceTargetNation = nation;
        break;
      }
    }
    TGreatPower* sourceNation = g_apNationStates[activeNation];
    if (allianceTargetNation < 0 || sourceNation == 0) {
      FailScenario("\"diplomacy map has no valid major-nation alliance target\"");
      return;
    }
    alliancePolicyBeforeAction = sourceNation->diplomacyPolicyByNation[allianceTargetNation];
    if (g_apTerrainTypeDescriptorTable[allianceTargetNation] == 0) {
      FailScenario("\"diplomacy alliance target disappeared before selection\"");
      return;
    }

    phase = kVerifyAllianceAction;
    EnterScenarioStep("verifying_diplomacy_alliance", "render_alliance_policy_icon");
    diplomacy->ActivateNation(allianceTargetNation);
    ContinueAfterAction();
  }

  void VerifyAllianceAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    TGreatPower* sourceNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    const short expectedPolicy = alliancePolicyBeforeAction == kDiplomacyProposalAlliance
                                     ? -1
                                     : static_cast<short>(kDiplomacyProposalAlliance);
    if (diplomacy == 0 || sourceNation == 0 ||
        sourceNation->diplomacyPolicyByNation[allianceTargetNation] != expectedPolicy) {
      FailScenario("\"diplomacy alliance action did not update the target policy\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(g_ModalViewStack.GetHead());
      FailScenario("\"diplomacy alliance action opened an unexpected modal\"");
      return;
    }

    if (expectedPolicy == kDiplomacyProposalAlliance &&
        diplomacy->RuntimeDrawPolicyIconForNation(allianceTargetNation) != 0x30) {
      FailScenario("\"diplomacy alliance policy did not render its treaty icon\"");
      return;
    }

    phase = kPoseAcceptedOffer;
    EnterScenarioStep("posing_diplomacy_offer", "pose_offer_for_acceptance");
    ContinueAfterAction();
  }

  TOffersPanelView* OffersPanel() const {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      return 0;
    }
    TView* panel = diplomacy->ResolveControlByTag(kControlTagOffr);
    if (panel == 0 || panel->IsKindOf(RUNTIME_CLASS(TOffersPanelView)) == 0) {
      return 0;
    }
    return static_cast<TOffersPanelView*>(panel);
  }

  bool QueueOfferResponse(TOffersPanelView* offers, int responseTag) const {
    (void)offers;
    return RuntimeUiDriver::PostActivate(RuntimeControlSelector(
        kControlTagOffr, kControlTagShee, responseTag, RUNTIME_CLASS(TControl), 0xa));
  }

  bool OfferResponseUsesExpectedEvent(TOffersPanelView* offers, int responseTag) const {
    TControl* response = static_cast<TControl*>(offers->ResolveControlByTag(responseTag));
    return response != 0 && response->GetEventNumber() == 0xa;
  }

  void PoseAcceptedOffer() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    TOffersPanelView* offers = OffersPanel();
    if (diplomacy == 0 || offers == 0) {
      FailScenario("\"diplomacy orders disappeared before posing an accepted offer\"");
      return;
    }
    if (!Require("diplomacy_offer_accept_event",
                 OfferResponseUsesExpectedEvent(offers, kControlTagAcce),
                 "\"diplomacy accept control did not publish event 0x0a\"")) {
      return;
    }
    if (!QueueOfferResponse(offers, kControlTagAcce)) {
      FailScenario("\"could not queue the diplomacy accept input\"");
      return;
    }
    EnterScenarioStep("accepting_diplomacy_offer", "click_offer_accept_control");
    diplomacy->PoseOffer(g_pSimMgr->GetActiveNationId(), allianceTargetNation,
                         kDiplomacyProposalNonAggressionPact);
    if (offers->lastNegotiationResponseTag64 != kControlTagAcce) {
      FailScenario("\"accept did not close the blocking diplomatic offer loop\"");
      return;
    }
    phase = kPoseRejectedOffer;
    EnterScenarioStep("posing_rejected_diplomacy_offer", "pose_offer_for_rejection");
    ContinueAfterAction();
  }

  void PoseRejectedOffer() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    TOffersPanelView* offers = OffersPanel();
    if (diplomacy == 0 || offers == 0) {
      FailScenario("\"diplomacy orders disappeared before posing a rejected offer\"");
      return;
    }
    if (!Require("diplomacy_offer_reject_event",
                 OfferResponseUsesExpectedEvent(offers, kControlTagReje),
                 "\"diplomacy reject control did not publish event 0x0a\"")) {
      return;
    }
    if (!QueueOfferResponse(offers, kControlTagReje)) {
      FailScenario("\"could not queue the diplomacy reject input\"");
      return;
    }
    EnterScenarioStep("rejecting_diplomacy_offer", "click_offer_reject_control");
    diplomacy->PoseOffer(g_pSimMgr->GetActiveNationId(), allianceTargetNation,
                         kDiplomacyProposalNonAggressionPact);
    if (offers->lastNegotiationResponseTag64 != kControlTagReje) {
      FailScenario("\"reject did not close the blocking diplomatic offer loop\"");
      return;
    }
    phase = kReturnToMap;
    EnterScenarioStep("returning_from_diplomacy_screen", "click_diplomacy_end_control");
    ContinueAfterAction();
  }

  void ReturnToMap() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before back navigation\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_map_after_diplomacy", "activate_diplomacy_end_control");
    if (!RuntimeUiDriver::Activate(
            diplomacy, RuntimeControlSelector(kControlTagEnd, RUNTIME_CLASS(TControl)))) {
      FailScenario("\"diplomacy back control is missing or cannot receive native input\"");
      return;
    }
    ContinueAfterAction();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      AwaitUiChange("\"diplomacy back control did not restore the strategic map\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(g_ModalViewStack.GetHead());
      FailScenario("\"diplomacy back navigation left an unexpected modal\"");
      return;
    }
    Pass();
  }

  Phase phase;
  short targetNation;
  short policyBeforeAction;
  short allianceTargetNation;
  short alliancePolicyBeforeAction;
};

DiplomacyScreenTestCase g_test;

} // namespace

RuntimeTestCase* DiplomacyScreenTest() {
  return &g_test;
}
