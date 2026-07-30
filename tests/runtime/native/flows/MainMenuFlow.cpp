#include "MainMenuFlow.h"

#include "RuntimeObservations.h"
#include "RuntimeJson.h"
#include "RuntimeRun.h"
#include "scenarios/RuntimeScenario.h"
#include "screens/MainMenuDriver.h"

#include "game/core/global_data_tables.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TGameSetupPicture.h"

#include <stdlib.h>

MainMenuFlow::MainMenuFlow() : phase(kComplete), checkpoint(kRuntimeNoCheckpoint) {}

void MainMenuFlow::Start(RuntimeScenario& scenario) {
  checkpoint = kRuntimeNoCheckpoint;
  phase = kWaitingForMainMenu;
  g_pAmbitApplication->PostTurnEventCodeMessage2420(0x5dc);
  scenario.EnterFlowPhase("waiting_for_main_menu", "post_turn_event_0x05dc");
  scenario.ContinueAfterAction();
}

RuntimeFlowStatus MainMenuFlow::Advance(RuntimeScenario& scenario) {
  if (phase == kWaitingForMainMenu) {
    TView* mainView = scenario.CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != 0x5dc ||
        !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
      scenario.AwaitUiChange("main menu did not become active");
      return kRuntimeFlowRunning;
    }
    srand(scenario.RunState().Seed());
    g_zoneStatusCodePrngSeed_006a5aec = scenario.RunState().Seed();
    MainMenuDriver menu(mainView);
    CString failure;
    if (!menu.StartRandomGame(&failure)) {
      CString failureJson;
      RuntimeJson::AppendString(failureJson, failure);
      scenario.FailScenario(failureJson);
      return kRuntimeFlowRunning;
    }
    checkpoint = kRuntimeMainMenuRandomGameRequested;
    phase = kAtCheckpoint;
    return kRuntimeFlowCheckpoint;
  }
  if (phase == kAtCheckpoint) {
    return kRuntimeFlowCheckpoint;
  }
  return kRuntimeFlowComplete;
}

RuntimeFlowCheckpoint MainMenuFlow::Checkpoint() const {
  return checkpoint;
}

void MainMenuFlow::ContinueFromCheckpoint() {
  checkpoint = kRuntimeNoCheckpoint;
  phase = kComplete;
}
