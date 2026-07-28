#include "LoadGameFlow.h"

#include "game/assets/TAssetMgr.h"
#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/view_registries.h"

LoadGameFlow::LoadGameFlow() : phase(kComplete), checkpoint(kRuntimeNoCheckpoint) {}

void LoadGameFlow::Start(RuntimeScenario& scenario) {
  phase = kOpenFixture;
  checkpoint = kRuntimeNoCheckpoint;
  scenario.EnterFlowPhase("loading_saved_game", "open_saved_game_fixture");
  scenario.RequestScenarioTick();
}

RuntimeFlowStatus LoadGameFlow::Tick(RuntimeScenario& scenario) {
  if (phase == kOpenFixture) {
    CString fixturePath(scenario.FixturePath());
    if (g_pAssetMgr->OpenMainDocumentFromPathAndMarkLoaded(fixturePath) == 0) {
      scenario.FailScenario("\"saved-game fixture failed to open through the document path\"");
      return kRuntimeFlowRunning;
    }
    phase = kWaitForMap;
    scenario.EnterFlowPhase("waiting_for_loaded_map", "opened_saved_game_fixture");
    scenario.RequestScenarioTick();
    return kRuntimeFlowRunning;
  }
  if (phase == kWaitForMap) {
    if (scenario.AdvanceNewspaperIfNeeded()) {
      return kRuntimeFlowRunning;
    }
    TView* mainView = scenario.CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != 0x7dd || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      scenario.WaitForScenarioTick("\"loaded game did not reach the combined strategic map\"");
      return kRuntimeFlowRunning;
    }
    if (g_pGlobalMapState == 0 || g_pSimMgr->activeNationSlot < 0 ||
        g_pSimMgr->activeNationSlot >= 7) {
      scenario.FailScenario("\"loaded game has no map state or valid active nation\"");
      return kRuntimeFlowRunning;
    }
    scenario.SetSelectedNation(g_pSimMgr->activeNationSlot);
    checkpoint = kRuntimeLoadedMapReady;
    phase = kAtCheckpoint;
    return kRuntimeFlowCheckpoint;
  }
  if (phase == kAtCheckpoint) {
    return kRuntimeFlowCheckpoint;
  }
  return kRuntimeFlowComplete;
}

RuntimeFlowCheckpoint LoadGameFlow::Checkpoint() const {
  return checkpoint;
}

void LoadGameFlow::ContinueFromCheckpoint() {
  checkpoint = kRuntimeNoCheckpoint;
  phase = kComplete;
}

RuntimeFlow* LoadGameScenario::NavigationFlow() {
  return &loadGameFlow;
}
