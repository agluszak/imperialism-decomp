#include "RandomSetupFlow.h"

#include "RuntimeObservations.h"
#include "RuntimeMapGenerationCapture.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"
#include "scenarios/RuntimeScenario.h"
#include "screens/RandomSetupScreen.h"

#include "game/core/global_data_tables.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "parson.h"

namespace {

const char* DifficultyName(int value) {
  static const char* const kNames[5] = {"introductory", "easy", "normal", "hard",
                                        "nigh_on_impossible"};
  ASSERT(value >= 0 && value < 5);
  return kNames[value];
}

void CaptureRandomGameSetup(RuntimeRun& run, TSetupRandomMapPicture* setup) {
  if (!run.RequestsCapture(kRuntimeCaptureRandomGameSetup) || run.HasCapture("random_game_setup")) {
    return;
  }
  if (setup == 0) {
    run.RecordAssertion("capture.random_game_setup", "the random-game setup view is unavailable",
                        true);
    return;
  }

  TEditText* country = static_cast<TEditText*>(setup->ResolveControlByTag(kControlTagCoun));
  TRadioTextCluster* difficulty =
      static_cast<TRadioTextCluster*>(setup->ResolveControlByTag(kControlTagDiff));
  TRadioTextCluster* names =
      static_cast<TRadioTextCluster*>(setup->ResolveControlByTag(kControlTagName));
  if (country == 0 || difficulty == 0 || names == 0) {
    run.RecordAssertion("capture.random_game_setup", "a random-game setup control is unavailable",
                        true);
    return;
  }
  TControl* selectedDifficulty =
      static_cast<TControl*>(setup->ResolveControlByTag(difficulty->selectedTag88));
  if (selectedDifficulty == 0) {
    run.RecordAssertion("capture.random_game_setup",
                        "the selected random-game difficulty is unavailable", true);
    return;
  }

  CString countryName;
  country->GetCurrentText(&countryName);
  JSON_Value* value = json_value_init_object();
  JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
  if (object == 0) {
    json_value_free(value);
    run.RecordAssertion("capture.random_game_setup",
                        "could not allocate the random-game setup capture", true);
    return;
  }
  json_object_set_string(object, "planet_seed", static_cast<LPCSTR>(setup->planetSeed94));
  json_object_set_number(object, "topology", static_cast<unsigned int>(setup->wrapHorizontally98));
  json_object_set_number(object, "nation", static_cast<int>(setup->selectedNationSlot9A));
  json_object_set_string(object, "country_name", static_cast<LPCSTR>(countryName));
  json_object_set_string(object, "difficulty", DifficultyName(selectedDifficulty->controlValue3c));
  json_object_set_boolean(object, "localized_names", names->selectedTag88 != kControlTagRand);
  run.SetCapture("random_game_setup", value);
}

} // namespace

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
    if (!scenario.RunState().RequestsCapture(kRuntimeCaptureGameState)) {
      CaptureRandomGameSetup(scenario.RunState(), RandomSetup().View());
    }
    phase = kSettingCountryName;
    scenario.EnterFlowPhase("setting_country_name", "wait_for_event_0x05dd");
    scenario.ContinueAfterAction();
    return kRuntimeFlowRunning;
  }
  if (phase == kCapturingRegeneratedPlanet) {
    CaptureRuntimeMapGeneration(scenario.RunState());
    if (!scenario.RunState().RequestsCapture(kRuntimeCaptureGameState)) {
      CaptureRandomGameSetup(scenario.RunState(), RandomSetup().View());
    }
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
    // A game-state boundary needs the setup values that StartGame is about to commit,
    // after the scripted country and difficulty edits. Map-generation-only scenarios
    // retain the earlier setup-screen capture paired with their generated preview.
    CaptureRandomGameSetup(scenario.RunState(), RandomSetup().View());
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
