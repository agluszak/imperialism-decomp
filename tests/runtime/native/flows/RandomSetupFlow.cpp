#include "RandomSetupFlow.h"

#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeRun.h"
#include "scenarios/RuntimeScenario.h"
#include "screens/RandomSetupScreen.h"

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
  if (phase == kWaitingForRandomSetup) {
    if (!RandomSetupScreen::IsCurrent()) {
      scenario.AwaitUiChange("random-map setup did not become active");
      return kRuntimeFlowRunning;
    }
    scenario.RunState().SetSelectedNationSlot(RandomSetup().SelectedNationSlot());
    phase = kSettingCountryName;
    scenario.EnterFlowPhase("setting_country_name", "wait_for_event_0x05dd");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kSettingCountryName) {
    RuntimeActionResult named = RandomSetup().SetCountryName("Testland");
    if (!named.Succeeded()) {
      CString failureJson;
      RuntimeJson::AppendString(failureJson, named.FailureMessage());
      scenario.FailScenario(failureJson);
      return kRuntimeFlowRunning;
    }
    phase = kSelectingDifficulty;
    scenario.EnterFlowPhase("selecting_difficulty", "set_text_coun");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kSelectingDifficulty) {
    RuntimeActionResult selected = RandomSetup().SelectDifficulty(scenario.DifficultyLevel());
    if (!selected.Succeeded()) {
      CString failureJson;
      RuntimeJson::AppendString(failureJson, selected.FailureMessage());
      scenario.FailScenario(failureJson);
      return kRuntimeFlowRunning;
    }
    phase = kActivatingOkay;
    scenario.EnterFlowPhase("activating_okay", "select_requested_difficulty");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kActivatingOkay) {
    RuntimeActionResult accepted = RandomSetup().Accept();
    if (!accepted.Succeeded()) {
      CString failureJson;
      RuntimeJson::AppendString(failureJson, accepted.FailureMessage());
      scenario.FailScenario(failureJson);
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
