#include "RandomSetupFlow.h"

#include "RuntimeObservations.h"
#include "RuntimeRun.h"
#include "scenarios/RuntimeScenario.h"
#include "screens/RandomSetupDriver.h"

#include "game/core/global_data_tables.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_tags_screens.h"

RandomSetupFlow::RandomSetupFlow() : phase(kComplete), checkpoint(kRuntimeNoCheckpoint) {}

void RandomSetupFlow::Start(RuntimeScenario& scenario) {
  checkpoint = kRuntimeNoCheckpoint;
  phase = kWaitingForRandomSetup;
  scenario.EnterFlowPhase("waiting_for_random_setup", "activate_main_menu_random_game");
  scenario.ContinueAfterAction();
}

RuntimeFlowStatus RandomSetupFlow::Advance(RuntimeScenario& scenario) {
  TView* mainView = scenario.CurrentMainView();
  if (phase == kWaitingForRandomSetup) {
    if (g_pViewMgr->currentTurnEventCode != 0x5dd ||
        !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
      scenario.AwaitUiChange("\"random-map setup did not become active\"");
      return kRuntimeFlowRunning;
    }
    RandomSetupDriver setup(mainView);
    scenario.RunState().SetSelectedNationSlot(setup.SelectedNationSlot());
    phase = kSettingCountryName;
    scenario.EnterFlowPhase("setting_country_name", "wait_for_event_0x05dd");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kSettingCountryName) {
    if (!RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
      scenario.FailScenario("\"random-map setup disappeared before country-name entry\"");
      return kRuntimeFlowRunning;
    }
    RandomSetupDriver setup(mainView);
    if (!setup.SetCountryName("Testland")) {
      scenario.FailScenario("\"country-name control is missing\"");
      return kRuntimeFlowRunning;
    }
    phase = kSelectingDifficulty;
    scenario.EnterFlowPhase("selecting_difficulty", "set_text_coun");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kSelectingDifficulty) {
    RandomSetupDriver setup(mainView);
    if (!setup.SelectDifficulty(kControlTagDif0 + scenario.DifficultyLevel())) {
      scenario.FailScenario("\"requested difficulty control is missing\"");
      return kRuntimeFlowRunning;
    }
    phase = kActivatingOkay;
    scenario.EnterFlowPhase("activating_okay", "select_requested_difficulty");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kActivatingOkay) {
    RandomSetupDriver setup(mainView);
    if (!setup.Accept()) {
      scenario.FailScenario("\"random setup okay control is missing\"");
      return kRuntimeFlowRunning;
    }
    checkpoint = kRuntimeRandomSetupAccepted;
    phase = kAtCheckpoint;
    return kRuntimeFlowCheckpoint;
  }
  if (phase == kAtCheckpoint) {
    return kRuntimeFlowCheckpoint;
  }
  return kRuntimeFlowComplete;
}

RuntimeFlowCheckpoint RandomSetupFlow::Checkpoint() const {
  return checkpoint;
}

void RandomSetupFlow::ContinueFromCheckpoint() {
  checkpoint = kRuntimeNoCheckpoint;
  phase = kComplete;
}
