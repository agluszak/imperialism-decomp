#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "probes/StrategicMapProbe.h"
#include "RuntimeUiDriver.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

namespace {

class RandomGameJourneyTestCase : public RandomGameScenario {
public:
  RandomGameJourneyTestCase() : phase(kReturnToRandomSetup), exercisedReentry(false) {}

  const char* Name() const override {
    return "random_game_enters_map";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void TickScenario() override {
    if (phase == kReturnToRandomSetup) {
      WaitForReturnedRandomSetup();
    } else if (phase == kReturnToMainMenu) {
      WaitForReturnedMainMenu();
    } else if (phase == kReenterRandomSetup) {
      WaitForReenteredRandomSetup();
    } else {
      VerifyReenteredRandomSetup();
    }
  }

  void OnCombinedMapReady() override {
    CString failure;
    TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
    if (!StrategicMapProbe::VerifyRendering(mapView, failure) ||
        !StrategicMapProbe::VerifyHoverCache(mapView, failure) ||
        !StrategicMapProbe::VerifyScrolling(mapView, failure)) {
      FailScenario(failure);
      return;
    }
    Pass();
  }

protected:
  void OnFlowCheckpoint(RuntimeFlowCheckpoint checkpoint) override {
    if (checkpoint != kRuntimeCapitalSelectionReady || exercisedReentry) {
      RuntimeScenario::OnFlowCheckpoint(checkpoint);
      return;
    }
    exercisedReentry = true;
    phase = kReturnToRandomSetup;
    EnterScenarioStep("returning_to_random_setup", "native_click_strategic_map_cancel");
    TView* mapView = CurrentMainView();
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(mapView, kControlTagCanc)) {
      FailScenario("\"strategic-map return control has no native-message path\"");
      return;
    }
    RequestScenarioTick();
  }

private:
  enum Phase {
    kReturnToRandomSetup,
    kReturnToMainMenu,
    kReenterRandomSetup,
    kVerifyReenteredRandomSetup
  };

  void WaitForReturnedRandomSetup() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TSetupRandomMapPicture)) == 0) {
      WaitForScenarioTick("\"random setup did not return from capital selection\"");
      return;
    }
    phase = kReturnToMainMenu;
    EnterScenarioStep("returning_to_main_menu", "native_click_random_setup_cancel");
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(mainView, kControlTagCncl)) {
      FailScenario("\"returned random setup has no native-message cancel path\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForReturnedMainMenu() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc) {
      WaitForScenarioTick("\"main menu did not return after random setup cancellation\"");
      return;
    }
    phase = kReenterRandomSetup;
    EnterScenarioStep("reentering_random_setup", "native_click_main_menu_random_game");
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(mainView, kControlTagRand)) {
      FailScenario("\"returned main menu has no native-message random-game path\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForReenteredRandomSetup() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TSetupRandomMapPicture)) == 0) {
      WaitForScenarioTick("\"random setup did not reopen from the returned main menu\"");
      return;
    }
    TSetupRandomMapPicture* setup = static_cast<TSetupRandomMapPicture*>(mainView);
    SetSelectedNation(setup->selectedNationSlot9A);
    phase = kVerifyReenteredRandomSetup;
    EnterScenarioStep("verifying_returned_random_setup", "native_click_hard_difficulty");
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(mainView, kControlTagDif3)) {
      FailScenario("\"reopened random setup has no native-message difficulty path\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyReenteredRandomSetup() {
    TView* mainView = CurrentMainView();
    TRadioTextCluster* difficulty =
        mainView != 0
            ? static_cast<TRadioTextCluster*>(mainView->ResolveControlByTag(kControlTagDiff))
            : 0;
    if (difficulty == 0 || difficulty->selectedTag88 != static_cast<int>(kControlTagDif3)) {
      FailScenario("\"reentered random setup did not accept the native difficulty click\"");
      return;
    }
    if (!RuntimeUiDriver::ActivateControlSemantically(mainView, kControlTagOkay)) {
      FailScenario("\"reentered random setup okay control is missing\"");
      return;
    }
    RestartRandomGameAtStrategicMapEntry();
  }

  Phase phase;
  bool exercisedReentry;
};

RandomGameJourneyTestCase g_test;

} // namespace

RuntimeTestCase* RandomGameJourneyTest() {
  return &g_test;
}
