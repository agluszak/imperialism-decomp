#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/globals/view_registries.h"

namespace {

// End the turn several times in a row on Easy and require the game to come back to a
// playable combined map each time, with the economic turn advancing by exactly one and no
// unexpected modal left behind. One end turn (easy_turns_advance) only proves the first
// hop. Later turns exercise the alert-modals-then-DONE-again path before the state machine
// advances, so the loop and faithful handling of those modals are the point.
const short kTurnsToAdvance = 3;

class MultiTurnAdvanceTestCase : public RandomGameScenario {
public:
  MultiTurnAdvanceTestCase()
      : phase(kActivateEndTurn), baselineEconomicTurn(0), startEconomicTurn(0), turnsDone(0),
        leftDealBook(false), sawTurnAlert(false), resubmittedEndTurn(false) {}

  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateEndTurn;
    turnsDone = 0;
    startEconomicTurn = 0;
    EnterScenarioStep("activating_end_turn", "reach_combined_map");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (phase == kActivateEndTurn) {
      ActivateEndTurn();
    } else {
      WaitForTurnProcessed();
    }
  }

private:
  enum Phase { kActivateEndTurn, kWaitForTurnProcessed };

  void ActivateEndTurn() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before ending the turn\"");
      return;
    }
    baselineEconomicTurn = g_pSimMgr->economicTurn;
    if (turnsDone == 0) {
      startEconomicTurn = baselineEconomicTurn;
    }
    leftDealBook = false;
    sawTurnAlert = false;
    resubmittedEndTurn = false;
    // Each ended turn may pop its own newspaper, and AdvanceNewspaperIfNeeded only acts
    // once per armed flag (the random-game setup already consumed the first one). Without
    // this the second newspaper is never dismissed and the run stalls on it.
    ResetNewspaperAdvance();
    phase = kWaitForTurnProcessed;
    StrategicMapDriver map(mainView);
    if (!map.EndTurnThroughNativeMessages()) {
      FailScenario("\"end-turn control is missing\"");
      return;
    }
    EnterScenarioStep("waiting_for_turn_processed", "activate_map_done");
    RequestScenarioTick();
  }

  void WaitForTurnProcessed() {
    if (g_pUiRuntimeContext->currentTurnEventCode == 0x11f8) {
      FailScenario("\"end turn entered the game-over/opening-cinematic path\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      TWindow* modal = g_ModalViewStack.GetHead();
      TDialogBehavior* behavior = modal->GetDialogBehavior();
      unsigned long defaultCommand = behavior != 0 ? behavior->defaultCommandCode : 0;
      TControl* defaultControl = static_cast<TControl*>(modal->ResolveControlByTag(defaultCommand));
      if (behavior == 0 ||
          (defaultCommand != kControlTagOkay && defaultCommand != kControlTagPic5) ||
          defaultControl == 0) {
        RecordUnexpectedModalView(modal);
        FailScenario("\"ended turn opened an unrecognized modal\"");
        return;
      }
      const char* modalLabel;
      const char* action;
      if (defaultCommand == kControlTagOkay) {
        sawTurnAlert = true;
        modalLabel = "turn_alert";
        action = "activate_turn_alert_okay";
      } else {
        modalLabel = "end_turn_warning";
        action = "activate_end_turn_warning";
      }
      RecordHandledModal(modalLabel);
      if (!RuntimeUiDriver::ActivateControlSemantically(modal, defaultCommand)) {
        FailScenario("\"turn-flow modal default control could not be activated\"");
        return;
      }
      EnterScenarioStep("waiting_for_turn_processed", action);
      RequestScenarioTick();
      return;
    }
    if (g_pUiRuntimeContext->currentTurnEventCode == kTurnEventDealBook && !leftDealBook) {
      leftDealBook = true;
      g_pSimMgr->StartNextPhase();
      RequestScenarioTick();
      return;
    }
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (sawTurnAlert && !resubmittedEndTurn &&
        g_pUiRuntimeContext->currentTurnEventCode == kTurnEventStrategicMap && mainView != 0 &&
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) != 0 &&
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      resubmittedEndTurn = true;
      EnterScenarioStep("waiting_for_turn_processed", "reactivate_map_done_after_turn_alerts");
      StrategicMapDriver map(mainView);
      if (!map.EndTurnThroughNativeMessages()) {
        FailScenario("\"end-turn control disappeared after turn alerts\"");
        return;
      }
      RequestScenarioTick();
      return;
    }
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty() ||
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      WaitForScenarioTick("\"ended turn did not advance back to the combined map\"");
      return;
    }
    if (g_pSimMgr->economicTurn != baselineEconomicTurn + 1) {
      FailScenario("\"economic turn advanced by more than one\"");
      return;
    }

    ++turnsDone;
    if (turnsDone < kTurnsToAdvance) {
      phase = kActivateEndTurn;
      EnterScenarioStep("activating_end_turn", "reach_combined_map");
      RequestScenarioTick();
      return;
    }
    if (g_pSimMgr->economicTurn != startEconomicTurn + kTurnsToAdvance) {
      FailScenario("\"economic turn total does not match the number of ended turns\"");
      return;
    }
    Pass();
  }

  Phase phase;
  short baselineEconomicTurn;
  short startEconomicTurn;
  short turnsDone;
  bool leftDealBook;
  bool sawTurnAlert;
  bool resubmittedEndTurn;
};

MultiTurnAdvanceTestCase g_test;

} // namespace

RuntimeTestCase* MultiTurnAdvanceTest() {
  return &g_test;
}
