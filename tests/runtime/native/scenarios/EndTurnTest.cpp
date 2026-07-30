#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "screens/StrategicMapDriver.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/view_registries.h"

namespace {

class EndTurnTestCase : public RandomGameScenario {
public:
  EndTurnTestCase() : phase(kActivateEndTurn), baselineEconomicTurn(0), leftDealBook(false) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateEndTurn;
    EnterScenarioStep("activating_end_turn", "reach_combined_map");
    ContinueAfterAction();
  }

  void AdvanceScenario() override {
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
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 ||
        !g_ModalViewStack.IsEmpty()) {
      AwaitUiChange("combined map was not idle before ending the turn");
      return;
    }
    baselineEconomicTurn = g_pSimMgr->economicTurn;
    leftDealBook = false;
    ResetNewspaperAdvance();
    StrategicMapDriver map(mainView);
    if (!map.EndTurn()) {
      FailScenario("\"end-turn control is missing\"");
      return;
    }
    phase = kWaitForTurnProcessed;
    EnterScenarioStep("waiting_for_turn_processed", "activate_map_done");
    ContinueAfterAction();
  }

  void WaitForTurnProcessed() {
    if (g_pViewMgr->currentTurnEventCode == 0x11f8) {
      FailScenario("\"end turn entered the game-over/opening-cinematic path\"");
      return;
    }
    if (g_pViewMgr->currentTurnEventCode == kTurnEventDealBook && !leftDealBook) {
      leftDealBook = true;
      g_pSimMgr->StartNextPhase();
      ContinueAfterAction();
      return;
    }
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != 0x7dd || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty() ||
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      AwaitUiChange("ended turn did not advance back to the combined map");
      return;
    }
    if (g_pSimMgr->economicTurn != baselineEconomicTurn + 1) {
      FailScenario("\"economic turn advanced by more than one\"");
      return;
    }
    Pass();
  }

  Phase phase;
  short baselineEconomicTurn;
  bool leftDealBook;
};

EndTurnTestCase g_test;

} // namespace

RuntimeTestCase* EndTurnTest() {
  return &g_test;
}
