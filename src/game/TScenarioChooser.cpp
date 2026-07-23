#include "game/TScenarioChooser.h"

#include "game/TAmbitApplication.h"
#include "game/TAssetMgr.h"
#include "game/TDeluxeText.h"
#include "game/TMapPreviewView.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TTextList.h"
#include "game/TUiEvent.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

// FUNCTION: IMPERIALISM 0x0045ae60
TScenarioChooser::TScenarioChooser() {}

// SYNTHETIC: IMPERIALISM 0x0045ae90
// TScenarioChooser::`scalar deleting destructor'
TScenarioChooser::~TScenarioChooser() {}
// SYNTHETIC: IMPERIALISM 0x00579ae0
// TScenarioChooser::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579b60
// TScenarioChooser::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScenarioChooser, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00579b80
void TScenarioChooser::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);
  // The original then sets up the scenario-list/preview controls (973 bytes) -- not yet
  // ported.
}

// FUNCTION: IMPERIALISM 0x0057a050
void TScenarioChooser::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 4) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    // g_pUiRuntimeContext->turnEventCursors[26]: (0x7c - 0x14) / sizeof(HCURSOR).
    SetCursor(g_pUiRuntimeContext->turnEventCursors[26]);
    // sourceHandler is the 'list' TTextList itself (confirmed by size: TTextList's
    // selectedIndex lands at exactly +0x1068).
    TTextList* scenarioList = static_cast<TTextList*>(sourceHandler);
    LoadScenarioMetadataByIndexIntoUiControlCore(
        scenarioIndexByListRow94[scenarioList->selectedIndex]);
    SetCursor(LoadCursorA(nullptr, IDC_ARROW));
  } else if (commandId == kControlTagPick) { // 'pick'
    TMapPreviewView* mapPreview =
        static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagPreviewMap)); // 'pmap'
    mapPreview->AssertValid();
    if (nationStateCodesByMapSelection144[mapPreview->pendingNation6C] != -1 &&
        mapPreview->pendingNation6C != mapPreview->selectedNation68) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
      mapPreview->selectedNation68 = mapPreview->pendingNation6C;
      mapPreview->EnhancePhoto();
      mapPreview->RefreshControl();
      TDeluxeText* descControl =
          static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagDesc)); // 'desc'
      descControl->SetTextEntryFromChars(
          nationDescriptionTextByMapSelection118[mapPreview->pendingNation6C],
          nationDescriptionLengthByMapSelection134[mapPreview->pendingNation6C]);
    }
  } else if (commandId == 0xa) {
    if (sourceHandler->controlTag == kControlTagStar) { // 'star'
      StartGame();
    }
  } else if (commandId == 0xd) {
    if (sourceHandler->controlTag == kControlTagMore) {                                // 'more'
      TTextList* list = static_cast<TTextList*>(ResolveControlByTag(kControlTagList)); // 'list'
      list->AssertValid();
      int newOffset = list->frameHeight38 / list->itemHeight + list->scrollOffset;
      list->scrollOffset = (newOffset > list->totalItems) ? 0 : newOffset;
      list->RefreshControl();
    }
  } else if (commandId == 0x14) {
    if (sourceHandler->controlTag == kControlTagExit) { // 'exit'
      ExitScreen();
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0057a2d0
void TScenarioChooser::ExitScreen() {
  if (g_pSimMgr->multiplayerSessionRole != 0) {
    g_pGameFlowState->ResetLocalUiStateAndPostTurnEvent5E5();
  } else {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventMainMenu));
  }
}

// FUNCTION: IMPERIALISM 0x0057a310
void TScenarioChooser::DoKeyEvent(TToolboxEvent* event) {
  int commandCode = event->commandCode;
  if (commandCode == kUiKeyEnter || commandCode == kUiKeyReturn) {
    StartGame();
  } else if (commandCode == kUiKeyEscape) {
    ExitScreen();
  }
}

// Per-scenario-index language/campaign tag consumed by TAssetMgr::EnsurePictWvDataGobLoadedBySlot.
static const int kScenarioLanguageTagByIndex[15] = {1, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};

// FUNCTION: IMPERIALISM 0x0057a350
void TScenarioChooser::StartGame() {
  if (selectedScenarioIndex142 == -1) {
    return;
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
  g_pSimMgr->SetDifficultyLevel(nationStateCodesByMapSelection144[mapControl->selectedNation68]);

  if (g_pSimMgr->multiplayerSessionRole != 0) {
    // The original then builds a multiplayer save-slot file path (finding the next unused
    // numbered slot in a loop), publishes it, and posts turn event 0x5e4 -- not yet
    // decoded.
  } else {
    g_pSimMgr->SetActiveNationSlotAndRefreshCityCapabilityUiHandles(mapControl->selectedNation68);
    for (int i = 0; i < 7; ++i) {
      g_pSimMgr->nationControlModes[i] = 2;
    }
    g_pSimMgr->nationControlModes[mapControl->selectedNation68] = 1;
    g_pSimMgr->StartNextPhase();
  }
}

// FUNCTION: IMPERIALISM 0x0057a6e0
void TScenarioChooser::LoadScenarioMetadataByIndexIntoUiControlCore(short scenarioIndex) {
  selectedScenarioIndex142 = scenarioIndex;
  CString path;
  g_pUiViewManager->BuildScenarioPathForModeAndIndex(scenarioIndex, 0, &path);
  // The original then opens that scenario metadata file (a '#'-delimited text format, not
  // the binary save-slot layout used elsewhere in this codebase) via a 0x1950-byte read
  // buffer and fgetc-driven parser, and rebuilds several dialog controls from the parsed
  // fields -- not yet decoded.
}

// FUNCTION: IMPERIALISM 0x0057ab30
void TScenarioChooser::Free() {
  for (int i = 0; i < 7; ++i) {
    if (nationDescriptionTextByMapSelection118[i] != 0) {
      delete[] nationDescriptionTextByMapSelection118[i];
    }
  }
  TView::Free();
}
