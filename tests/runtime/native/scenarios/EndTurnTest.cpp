#include "RuntimeScenario.h"
#include "screens/StrategicMapDriver.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

const int kEndTurnCycles = 3;

class EndTurnTestCase : public RuntimeScenario {
public:
  EndTurnTestCase() : phase(kActivateEndTurn), baselineEconomicTurn(0), turnsCompleted(0) {}

  const char* Name() const override {
    return "easy_turns_advance";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  bool UsesEasyDifficulty() const override {
    return true;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnEasyMapReady() override {
    phase = kActivateEndTurn;
    EnterScenarioStep("activating_end_turn", "reach_combined_map");
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
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
      WaitForScenarioTick("\"combined map was not idle before ending the turn\"");
      return;
    }
    baselineEconomicTurn = g_pSimMgr->economicTurn;
    ResetNewspaperAdvance();
    StrategicMapDriver map(mainView);
    if (!map.EndTurn()) {
      FailScenario("\"end-turn (send) control is missing\"");
      return;
    }
    phase = kWaitForTurnProcessed;
    EnterScenarioStep("waiting_for_turn_processed", "activate_map_done");
    RequestScenarioTick();
  }

  void WaitForTurnProcessed() {
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x7dd || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty() ||
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      WaitForScenarioTick("\"ended turn did not advance back to the combined map\"");
      return;
    }
    if (g_pSimMgr->economicTurn != baselineEconomicTurn + 1) {
      FailScenario("\"economic turn advanced by more than one\"");
      return;
    }
    ++turnsCompleted;
    if (turnsCompleted < kEndTurnCycles) {
      phase = kActivateEndTurn;
      EnterScenarioStep("activating_end_turn", "turn_processed");
      RequestScenarioTick();
      return;
    }
    Pass();
  }

  Phase phase;
  short baselineEconomicTurn;
  int turnsCompleted;
};

EndTurnTestCase g_test;

} // namespace

RuntimeTestCase* EndTurnTest() {
  return &g_test;
}
