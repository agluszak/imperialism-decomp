#include "RandomSetupFlow.h"

#include "RuntimeObservations.h"
#include "RuntimeMapGenerationCapture.h"
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
    const char* planetSeed = scenario.RandomSetupPlanetSeed();
    if (planetSeed != 0) {
      RuntimeActionResult regenerated = RandomSetup().RegeneratePlanet(planetSeed);
      if (!regenerated.Succeeded()) {
        scenario.FailScenario(regenerated.FailureMessage());
        return kRuntimeFlowRunning;
      }
      phase = kCapturingRegeneratedPlanet;
      scenario.EnterFlowPhase("capturing_regenerated_planet", "regenerate_planet_seed");
      scenario.ContinueAfterAction();
      return kRuntimeFlowRunning;
    }
    CaptureRuntimeMapGeneration(scenario.RunState());
    phase = kSettingCountryName;
    scenario.EnterFlowPhase("setting_country_name", "wait_for_event_0x05dd");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kCapturingRegeneratedPlanet) {
    CaptureRuntimeMapGeneration(scenario.RunState());
    phase = kSettingCountryName;
    scenario.EnterFlowPhase("setting_country_name", "wait_for_event_0x05dd");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kSettingCountryName) {
    RuntimeActionResult named = RandomSetup().SetCountryName("Testland");
    if (!named.Succeeded()) {
      scenario.FailScenario(named.FailureMessage());
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
      scenario.FailScenario(selected.FailureMessage());
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
      scenario.FailScenario(accepted.FailureMessage());
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
