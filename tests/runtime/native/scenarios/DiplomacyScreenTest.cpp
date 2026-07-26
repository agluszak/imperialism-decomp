#include "RuntimeScenario.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_manifest_tags.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"

namespace {

class DiplomacyScreenTestCase : public RuntimeScenario {
public:
  DiplomacyScreenTestCase()
      : phase(kActivateDiplomacyScreen), targetNation(-1), policyBeforeAction(-1) {}

  const char* Name() const override {
    return "diplomacy_screen_operates";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
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
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
    if (phase == kActivateDiplomacyScreen) {
      ActivateDiplomacyScreen();
    } else if (phase == kWaitForDiplomacyScreen) {
      WaitForDiplomacyScreen();
    } else if (phase == kSelectForeignNation) {
      SelectForeignNation();
    } else if (phase == kVerifyForeignNation) {
      VerifyForeignNation();
    } else if (phase == kActivateTreatiesTopic) {
      ActivateTreatiesTopic();
    } else if (phase == kVerifyTreatiesTopic) {
      VerifyTreatiesTopic();
    } else if (phase == kInitiatePrimaryAction) {
      InitiatePrimaryAction();
    } else if (phase == kVerifyPrimaryAction) {
      VerifyPrimaryAction();
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
    kActivateTreatiesTopic,
    kVerifyTreatiesTopic,
    kInitiatePrimaryAction,
    kVerifyPrimaryAction,
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
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before opening diplomacy\"");
      return;
    }
    phase = kWaitForDiplomacyScreen;
    EnterScenarioStep("waiting_for_diplomacy_screen", "activate_diplomacy_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.ActivateDiplomacy()) {
      FailScenario("\"diplomacy toolbar control is missing or disabled\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForDiplomacyScreen() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventDiplomacyMap || diplomacy == 0) {
      WaitForScenarioTick("\"diplomacy toolbar action did not activate diplomacy orders\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
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
    if (ScenarioPhaseElapsedMs() < 1000) {
      RequestScenarioTick();
      return;
    }
    if (HoldAtScenarioScreen("diplomacy")) {
      RedrawWindow(diplomacy->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
      Pass();
      return;
    }
    phase = kSelectForeignNation;
    EnterScenarioStep("selecting_diplomacy_nation", "click_first_foreign_nation_on_map");
    RequestScenarioTick();
  }

  void SelectForeignNation() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before nation selection\"");
      return;
    }
    const short activeNation = g_pSimMgr->GetActiveNationId();
    CPoint point;
    // A fresh major-to-major relationship cannot build a consulate: the original
    // validation requires relationSideEffectMatrix1402 == 0, which is the initial
    // major-to-minor state. Pick a real minor nation so the primary treaty action is
    // expected to commit rather than deliberately opening the rejection notice.
    for (short nation = 7; nation < 0x17; ++nation) {
      if (nation != activeNation && g_apTerrainTypeDescriptorTable[nation] != 0 &&
          diplomacy->RuntimeGetNationSelectionPoint(nation, &point)) {
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
    if (!RuntimeUiDriver::ClickViewPoint(diplomacy, point.x, point.y)) {
      FailScenario("\"diplomacy nation map has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyForeignNation() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->RuntimeActiveNation() != targetNation) {
      FailScenario("\"diplomacy map click did not select and inspect the foreign nation\"");
      return;
    }
    phase = kActivateTreatiesTopic;
    EnterScenarioStep("activating_diplomacy_treaties", "click_treaties_action_topic");
    RequestScenarioTick();
  }

  void ActivateTreatiesTopic() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before treaty selection\"");
      return;
    }
    phase = kVerifyTreatiesTopic;
    EnterScenarioStep("verifying_diplomacy_treaties", "activate_treaties_action_topic");
    if (!RuntimeUiDriver::ClickControl(diplomacy, kControlTagTrtt)) {
      FailScenario("\"diplomacy treaties action control is missing or cannot receive input\"");
      return;
    }
    RequestScenarioTick();
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
    RequestScenarioTick();
  }

  void InitiatePrimaryAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    CPoint point;
    if (diplomacy == 0 || !diplomacy->RuntimeGetNationSelectionPoint(targetNation, &point)) {
      FailScenario("\"diplomacy target disappeared before the consulate action\"");
      return;
    }
    phase = kVerifyPrimaryAction;
    EnterScenarioStep("verifying_diplomacy_action", "apply_consulate_diplomacy_policy");
    if (!RuntimeUiDriver::ClickViewPoint(diplomacy, point.x, point.y)) {
      FailScenario("\"diplomacy consulate action could not reach the native host\"");
      return;
    }
    RequestScenarioTick();
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
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"diplomacy consulate action opened an unexpected modal\"");
      return;
    }
    phase = kReturnToMap;
    EnterScenarioStep("returning_from_diplomacy_screen", "click_diplomacy_end_control");
    RequestScenarioTick();
  }

  void ReturnToMap() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy orders disappeared before back navigation\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_map_after_diplomacy", "activate_diplomacy_end_control");
    if (!RuntimeUiDriver::ClickControl(diplomacy, kControlTagEnd)) {
      FailScenario("\"diplomacy back control is missing or cannot receive native input\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      WaitForScenarioTick("\"diplomacy back control did not restore the strategic map\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"diplomacy back navigation left an unexpected modal\"");
      return;
    }
    if (ScenarioPhaseTicks() < 20) {
      RequestScenarioTick();
      return;
    }
    Pass();
  }

  Phase phase;
  short targetNation;
  short policyBeforeAction;
};

DiplomacyScreenTestCase g_test;

} // namespace

RuntimeTestCase* DiplomacyScreenTest() {
  return &g_test;
}
