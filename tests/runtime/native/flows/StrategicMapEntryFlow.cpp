#include "StrategicMapEntryFlow.h"

#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeRun.h"
#include "RuntimeUiDriver.h"
#include "scenarios/RuntimeScenario.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TCitySiteView.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/globals/view_registries.h"

namespace {

bool NationModesMatchSelectedNation(const RuntimeRun& run) {
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    short expected = nationSlot == run.SelectedNationSlot() ? 1 : 2;
    if (g_pSimMgr->nationControlModes[nationSlot] != expected) {
      return false;
    }
  }
  return true;
}

void RecordHandledModal(RuntimeRun& run, const char* label) {
  CString entry;
  entry.Format("\"%s\"", label);
  RuntimeJson::AppendArrayItem(run.HandledModals(), entry);
}

short FindCapitalSite(short nationSlot) {
  for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    StrategicTerrainKind terrainKind = tile.GetTerrainKind();
    bool supportsCity =
        terrainKind == kStrategicTerrainPlains || terrainKind == kStrategicTerrainFarmland ||
        terrainKind == kStrategicTerrainForest || terrainKind == kStrategicTerrainDesert;
    if (supportsCity && tile.ownerNationTag04 == nationSlot && tile.recruitSearchVisited0e == 0) {
      return tileIndex;
    }
  }
  return -1;
}

} // namespace

StrategicMapEntryFlow::StrategicMapEntryFlow()
    : phase(kComplete), phaseAfterCheckpoint(kComplete), checkpoint(kRuntimeNoCheckpoint) {}

void StrategicMapEntryFlow::Enter(RuntimeScenario& scenario, Phase next, const char* phaseName,
                                  const char* action) {
  phase = next;
  checkpoint = kRuntimeNoCheckpoint;
  scenario.EnterFlowPhase(phaseName, action);
}

void StrategicMapEntryFlow::Start(RuntimeScenario& scenario) {
  if (scenario.DifficultyLevel() <= 1) {
    Enter(scenario, kWaitingForDirectMap, "waiting_for_direct_strategic_map",
          "activate_random_setup_okay");
  } else {
    Enter(scenario, kWaitingForCapitalMap, "waiting_for_strategic_map",
          "activate_random_setup_okay");
  }
  scenario.RequestScenarioTick();
}

RuntimeFlowStatus StrategicMapEntryFlow::ReachCheckpoint(RuntimeFlowCheckpoint value) {
  checkpoint = value;
  phase = kAtCheckpoint;
  return kRuntimeFlowCheckpoint;
}

RuntimeFlowStatus StrategicMapEntryFlow::Tick(RuntimeScenario& scenario) {
  RuntimeRun& run = scenario.RunState();
  TView* mainView = scenario.CurrentMainView();

  if (phase == kWaitingForDirectMap) {
    if (scenario.AdvanceNewspaperIfNeeded()) {
      return kRuntimeFlowRunning;
    }
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x7dd ||
        !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
      scenario.WaitForScenarioTick("\"random game did not reach the combined strategic map\"");
      return kRuntimeFlowRunning;
    }
    if (!g_ModalViewStack.IsEmpty() || g_pGlobalMapState == 0 ||
        g_pSimMgr->difficultyLevel != scenario.DifficultyLevel() ||
        g_pSimMgr->multiplayerSessionRole != 0 || !NationModesMatchSelectedNation(run)) {
      scenario.FailScenario("\"direct strategic-map navigation prerequisites are invalid\"");
      return kRuntimeFlowRunning;
    }
    phaseAfterCheckpoint = kComplete;
    return ReachCheckpoint(kRuntimeMapReadyWithoutCapitalSelection);
  }

  if (phase == kWaitingForCapitalMap) {
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
        !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture)) ||
        g_ModalViewStack.IsEmpty()) {
      scenario.WaitForScenarioTick("\"capital-selection map and prompt did not become active\"");
      return kRuntimeFlowRunning;
    }
    TWindow* modal = g_ModalViewStack.GetHead();
    TDialogBehavior* behavior = modal->GetDialogBehavior();
    TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
    if (behavior == 0 || behavior->defaultCommandCode != kControlTagOkay || okay == 0) {
      scenario.RecordUnexpectedModalView(modal);
      scenario.FailScenario("\"unexpected modal while entering capital selection\"");
      return kRuntimeFlowRunning;
    }
    RecordHandledModal(run, "city_site_prompt");
    if (!RuntimeUiDriver::ActivateControlSemantically(modal, kControlTagOkay)) {
      scenario.FailScenario("\"capital-selection prompt okay control is missing\"");
      return kRuntimeFlowRunning;
    }
    Enter(scenario, kWaitingForCapitalPromptDismissal, "waiting_for_modal_dismissal",
          "activate_city_site_prompt_okay");
    scenario.RequestScenarioTick();
    return kRuntimeFlowRunning;
  }

  if (phase == kWaitingForCapitalPromptDismissal) {
    if (!g_ModalViewStack.IsEmpty()) {
      scenario.WaitForScenarioTick("\"capital-selection prompt did not dismiss\"");
      return kRuntimeFlowRunning;
    }
    TMapUberPicture* mapView = RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))
                                   ? static_cast<TMapUberPicture*>(mainView)
                                   : 0;
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 || mapView == 0 ||
        g_pGlobalMapState == 0 || mapView->subview2A8 == 0 || mapView->miniMapViewC0 == 0 ||
        mapView->ResolveControlByTag(kControlTagCanc) == 0 ||
        mapView->ResolveControlByTag(kControlTagQuer) == 0) {
      scenario.FailScenario("\"capital-selection map is missing navigation prerequisites\"");
      return kRuntimeFlowRunning;
    }
    if (scenario.RecordsGameFlow()) {
      CaptureRuntimeMapState(run);
    }
    phaseAfterCheckpoint = kSelectingCapitalSite;
    return ReachCheckpoint(kRuntimeCapitalSelectionReady);
  }

  if (phase == kSelectingCapitalSite) {
    TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    if (mapDialog == 0 || !RuntimeIsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
      scenario.FailScenario("\"capital-selection map has no TCitySiteView\"");
      return kRuntimeFlowRunning;
    }
    short citySite = FindCapitalSite(run.SelectedNationSlot());
    if (citySite == -1) {
      scenario.FailScenario("\"random map has no valid capital-site candidate\"");
      return kRuntimeFlowRunning;
    }
    Enter(scenario, kWaitingForCapitalConfirmation, "waiting_for_city_site_confirmation",
          "submit_semantic_city_site");
    static_cast<TCitySiteView*>(mapDialog)->HandleMapClickByInteractionMode(citySite, 0);
    scenario.RequestScenarioTick();
    return kRuntimeFlowRunning;
  }

  if (phase == kWaitingForCapitalConfirmation) {
    if (g_ModalViewStack.IsEmpty()) {
      scenario.WaitForScenarioTick("\"capital-site confirmation did not become active\"");
      return kRuntimeFlowRunning;
    }
    TWindow* modal = g_ModalViewStack.GetHead();
    TView* dialog = modal->ResolveControlByTag(kControlTagDialog);
    TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
    if (dialog == 0 || okay == 0 || modal->IsActionable() == 0 || okay->IsActionable() == 0 ||
        modal->nativeWindow50 == 0 || okay->nativeWindow50 != modal->nativeWindow50) {
      scenario.FailScenario("\"capital-site confirmation tree is incomplete or detached\"");
      return kRuntimeFlowRunning;
    }
    run.CapitalConfirmationUiSnapshot() = CaptureRuntimeUiSnapshot(0x3b9, modal);
    RecordHandledModal(run, "city_site_confirmation");
    if (!RuntimeUiDriver::ActivateControlSemantically(modal, kControlTagOkay)) {
      scenario.FailScenario("\"capital-site confirmation okay control is missing\"");
      return kRuntimeFlowRunning;
    }
    Enter(scenario, kWaitingForCombinedMap, "waiting_for_combined_map",
          "accept_city_site_confirmation");
    scenario.RequestScenarioTick();
    return kRuntimeFlowRunning;
  }

  if (phase == kWaitingForCombinedMap) {
    if (scenario.AdvanceNewspaperIfNeeded()) {
      return kRuntimeFlowRunning;
    }
    TMapUberPicture* mapView = RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))
                                   ? static_cast<TMapUberPicture*>(mainView)
                                   : 0;
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x7dd || mapView == 0 ||
        !g_ModalViewStack.IsEmpty()) {
      scenario.WaitForScenarioTick("\"accepted capital site did not reach the combined map\"");
      return kRuntimeFlowRunning;
    }
    if (mapView->subview2A8 == 0 ||
        RuntimeIsViewKindOf(mapView->subview2A8, RUNTIME_CLASS(TCitySiteView))) {
      scenario.FailScenario("\"combined map retained the capital-selection map view\"");
      return kRuntimeFlowRunning;
    }
    phaseAfterCheckpoint = kComplete;
    return ReachCheckpoint(kRuntimeCombinedMapReady);
  }

  if (phase == kAtCheckpoint) {
    return kRuntimeFlowCheckpoint;
  }
  return kRuntimeFlowComplete;
}

void StrategicMapEntryFlow::ObserveTurnEvent(RuntimeScenario& scenario, int eventCode) {
  if (phase == kWaitingForCombinedMap && eventCode == 0x7dd) {
    scenario.RequestScenarioTick();
  }
}

RuntimeFlowCheckpoint StrategicMapEntryFlow::Checkpoint() const {
  return checkpoint;
}

void StrategicMapEntryFlow::ContinueFromCheckpoint() {
  phase = phaseAfterCheckpoint;
  checkpoint = kRuntimeNoCheckpoint;
}
