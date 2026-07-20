#include "game/TScenarioChooser.h"

#include "game/TAmbitApplication.h"
#include "game/TAssetMgr.h"
#include "game/TMapPreviewView.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x0045ae90
// TScenarioChooser::`scalar deleting destructor'
TScenarioChooser::~TScenarioChooser() {}
// SYNTHETIC: IMPERIALISM 0x00579ae0
// TScenarioChooser::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579b60
// TScenarioChooser::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScenarioChooser, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0045ae60
TScenarioChooser::TScenarioChooser() {}

// FUNCTION: IMPERIALISM 0x00579b80
void TScenarioChooser::NoOpUiLifecycleHook(int arg) {
  TNoHilitePicture::NoOpUiLifecycleHook(arg);
  // The original then sets up the scenario-list/preview controls (973 bytes) -- not yet
  // ported.
}

// FUNCTION: IMPERIALISM 0x0057a050
void TScenarioChooser::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  // The original dispatches on commandId (4, 'pick', 0xa, 0x14, ...) against
  // sourceHandler's own +0x1060/+0x1064/+0x1068 fields (an unresolved receiver class) and
  // scenarioChooserState94's opaque layout before reaching this common tail in every path
  // -- not yet ported.
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0057a2d0
undefined TScenarioChooser::PostTurnEvent5DCOrResetScenarioSelectionState() {
  if (g_pSimMgr->field44 != 0) {
    g_pGameFlowState->ResetLocalUiStateAndPostTurnEvent5E5();
  } else {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0057a310
void TScenarioChooser::ForwardParam(int param) {}

// Per-scenario-index language/campaign tag consumed by TAssetMgr::EnsurePictWvDataGobLoadedBySlot.
static const int kScenarioLanguageTagByIndex[15] = {1, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};

// FUNCTION: IMPERIALISM 0x0057a350
undefined TScenarioChooser::ApplyScenarioSelectionAndPostTurnEvent5E4() {
  if (selectedScenarioIndex142 == -1) {
    return 0;
  }

  int languageTag = 1;
  if (selectedScenarioIndex142 < 16 &&
      static_cast<unsigned int>(selectedScenarioIndex142) <
          sizeof(kScenarioLanguageTagByIndex) / sizeof(kScenarioLanguageTagByIndex[0])) {
    languageTag = kScenarioLanguageTagByIndex[selectedScenarioIndex142];
  }
  g_pUiViewManager->EnsurePictWvDataGobLoadedBySlot(languageTag);

  TMapPreviewView* mapControl = static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagMapP));
  mapControl->AssertValid();
  g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);
  g_pSimMgr->RecreateActiveMapContextAndInitializeGlobalMapState(selectedScenarioIndex142);
  g_pSimMgr->SetStateCodeAndUpdateZeroOrOutOfRangeFlag(
      nationStateCodesByMapSelection144[mapControl->selectedNation68]);

  if (g_pSimMgr->field44 != 0) {
    // The original then builds a multiplayer save-slot file path (finding the next unused
    // numbered slot in a loop), publishes it, and posts turn event 0x5e4 -- not yet
    // decoded.
  } else {
    g_pSimMgr->SetActiveNationSlotAndRefreshCityCapabilityUiHandles(mapControl->selectedNation68);
    for (int i = 0; i < 7; ++i) {
      g_pSimMgr->scenarioSetupRows0[i] = 2;
    }
    g_pSimMgr->scenarioSetupRows0[mapControl->selectedNation68] = 1;
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0057ab30
void TScenarioChooser::Free() {}
