#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include <stdio.h>
#include "game/map/TMapMgr.h"
#include <mbstring.h>
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_screens/TScenarioChooser.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_screens/TTextList.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"

// FUNCTION: IMPERIALISM 0x0045ae60
TScenarioChooser::TScenarioChooser() {}

// SYNTHETIC: IMPERIALISM 0x0045ae90
// TScenarioChooser::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0045aec0
TScenarioChooser::~TScenarioChooser() {}
// SYNTHETIC: IMPERIALISM 0x00579ae0
// TScenarioChooser::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579b60
// TScenarioChooser::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScenarioChooser, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00579b80
void TScenarioChooser::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);
  g_bMultiplayerScenarioSetupActive = 0;
  scenarioListRowCount114 = 0;

  TTextList* scenarioList = static_cast<TTextList*>(ResolveControlByTag(kControlTagList));
  scenarioList->AssertValid();

  // Scenario slots 9..15 are single-player only, so a multiplayer session skips them.
  for (int scenarioIndex = 0; scenarioIndex < 0x40; ++scenarioIndex) {
    CString unusedScratch;
    CString scenarioPath;
    if (scenarioIndex > 8 && scenarioIndex < 0x10 && g_pSimMgr->multiplayerSessionRole != 0) {
      continue;
    }
    g_pUiViewManager->BuildScenarioPathForModeAndIndex(static_cast<short>(scenarioIndex), 0,
                                                       &scenarioPath);
    if (TryGetFileMetadataForPath(&scenarioPath) == 0) {
      continue;
    }
    FILE* metadataStream = fopen(scenarioPath, "r");
    char titleLine[0x40];
    fgets(titleLine, 0x40, metadataStream);
    fclose(metadataStream);

    if (scenarioList->totalItems < 0x40) {
      char* destination = scenarioList->items[scenarioList->totalItems].text;
      const char* source = titleLine;
      if (*source != 0) {
        while (source - titleLine < 0x40) {
          if (*source == '\n') {
            break;
          }
          *destination = *source;
          ++destination;
          ++source;
          if (*source == 0) {
            break;
          }
        }
      }
      *destination = 0;
      ++scenarioList->totalItems;
    }
    scenarioIndexByListRow94[scenarioListRowCount114] = static_cast<short>(scenarioIndex);
    ++scenarioListRowCount114;
  }
  scenarioList->RefreshControl();

  TextStyle headingStyle;
  BuildUiTextStyleDescriptor(&headingStyle, 0, 0xe, 0x2b6a);
  CString headingText;
  COLORREF shadowColor;
  ResolveUiThemeColor(0x2b6c, &shadowColor);

  TDropShadowText* moreLabel =
      static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagMore)); // 'more'
  moreLabel->AssertValid();
  g_pSimMgr->GetString(0x2758, 0x20, &headingText);
  moreLabel->SetTextAndMaybeRefresh(&headingText, 0);
  moreLabel->InstallTextStyle(headingStyle, 1);
  moreLabel->shadowColor94 = shadowColor;
  moreLabel->SetState(1, 0);

  TextStyle bodyStyle;
  BuildUiTextStyleDescriptor(&bodyStyle, 0, 0xc, 0x2b6a);
  TDeluxeText* scenarioDescription =
      static_cast<TDeluxeText*>(ResolveControlByTag(0x73646573)); // 'sdes'
  scenarioDescription->AssertValid();
  scenarioDescription->SetTextStyle(bodyStyle, 0);
  TDeluxeText* nationDescription =
      static_cast<TDeluxeText*>(ResolveControlByTag(0x63646573)); // 'cdes'
  nationDescription->AssertValid();
  nationDescription->SetTextStyle(bodyStyle, 0);

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    nationDescriptionTextByMapSelection118[nationSlot] = new char[0x400];
  }
  selectedScenarioIndex142 = -1;

  TInfoBarText* cursorPanel = static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel = cursorPanel;
  cursorPanel->AssertValid();
  cursorPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  cursorPanel->SetTextAlignmentAndMaybeRefresh(1, 1);

  LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x18, this);
  LoadUiStringByGroupAndIndexToControlObject(0x2737, 0x14, ResolveControlByTag(kControlTagExit));
  LoadUiStringByGroupAndIndexToControlObject(0x2737, 0x16,
                                             ResolveControlByTag(kControlTagPreviewMap));
  LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x19, ResolveControlByTag(kControlTagStar));
  LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x1a, ResolveControlByTag(kControlTagList));
  LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x1c, ResolveControlByTag(kControlTagMore));
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

  TMapPreviewView* mapControl =
      static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagPreviewMap));
  mapControl->AssertValid();
  g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);
  g_pSimMgr->RecreateActiveMapContextAndInitializeGlobalMapState(selectedScenarioIndex142);
  g_pSimMgr->SetDifficultyLevel(nationStateCodesByMapSelection144[mapControl->selectedNation68]);

  if (g_pSimMgr->multiplayerSessionRole != 0) {
    // Ask for the session's save name until it differs from the one already published,
    // then normalise it and hand it to the game-flow state with the chosen nation and
    // the scenario's 'scn0'+index tag before posting event 0x5e4.
    do {
      CString proposedName;
      g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&g_pGameFlowState->playerNameString);
      g_cstrCountryNameSettingValue006A4220 =
          g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&g_pGameFlowState->playerNameString);
      CString promptText;
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&promptText, 0x2742, 3);
      g_pUiRuntimeContext->MakePlanetSeedDialog(promptText, g_cstrCountryNameSettingValue006A4220,
                                                0, 0, 0, 0);
    } while (g_cstrCountryNameSettingValue006A4220.Compare(g_szEmptyString) == 0);

    CString qualifiedName = g_pLanguageMgr->PickGender(g_cstrCountryNameSettingValue006A4220);
    qualifiedName += g_cstrCountryNameSettingValue006A4220;
    g_cstrCountryNameSettingValue006A4220 = qualifiedName;
    g_pGameFlowState->playerNameMirror = g_cstrCountryNameSettingValue006A4220;
    g_pGameFlowState->playerNameString = g_cstrCountryNameSettingValue006A4220;
    g_pGameFlowState->activeNationTagIndex =
        static_cast<unsigned char>(mapControl->selectedNation68);
    g_pGameFlowState->scenarioSelectionTag = kControlTagScn0 + selectedScenarioIndex142;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(kTurnEventNetworkGameOptions);
  } else {
    g_pSimMgr->SetActiveNationSlotAndRefreshCityCapabilityUiHandles(mapControl->selectedNation68);
    for (int i = 0; i < 7; ++i) {
      g_pSimMgr->nationControlModes[i] = 2;
    }
    g_pSimMgr->nationControlModes[mapControl->selectedNation68] = 1;
    g_pSimMgr->StartNextPhase();
  }
}

// Copies one '#'-delimited field out of the metadata stream, translating newlines to
// spaces and '^' to a carriage return, and stopping at the field separator, end of file
// or 0x7fe bytes. Returns one past the NUL it writes.
static char* ReadScenarioMetadataField(FILE* stream, char* destination) {
  char* cursor = destination;
  for (;;) {
    int ch = fgetc(stream);
    if (ch == '#') {
      break;
    }
    if (ch == '\n' || ch == '\r') {
      *cursor = ' ';
    } else if (ch == '^') {
      *cursor = '\r';
    } else {
      *cursor = static_cast<char>(ch);
    }
    ++cursor;
    if (cursor - destination >= 0x7fe) {
      break;
    }
  }
  *cursor = 0;
  return cursor + 1;
}

// FUNCTION: IMPERIALISM 0x0057a6e0
void TScenarioChooser::LoadScenarioMetadataByIndexIntoUiControlCore(short scenarioIndex) {
  CString path;
  selectedScenarioIndex142 = scenarioIndex;
  g_pUiViewManager->BuildScenarioPathForModeAndIndex(scenarioIndex, 0, &path);

  char* fieldBuffer = new char[0x1950];
  FILE* metadataStream = fopen(path, "rb");

  // Skip everything before the first field separator.
  int ch;
  do {
    ch = fgetc(metadataStream);
  } while (feof(metadataStream) == 0 && ch != '#');

  char* scenarioDescriptionEnd = ReadScenarioMetadataField(metadataStream, fieldBuffer);
  TDeluxeText* scenarioDescription =
      static_cast<TDeluxeText*>(ResolveControlByTag(0x73646573)); // 'sdes'
  scenarioDescription->AssertValid();
  scenarioDescription->SetTextEntryFromChars(
      fieldBuffer, static_cast<short>(scenarioDescriptionEnd - fieldBuffer));
  scenarioDescription->SetEnabled(1, 0);
  scenarioDescription->RefreshControl();

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    char* nationText = nationDescriptionTextByMapSelection118[nationSlot];
    char* nationTextEnd = ReadScenarioMetadataField(metadataStream, nationText);
    nationDescriptionLengthByMapSelection134[nationSlot] =
        static_cast<short>(nationTextEnd - nationText);
  }

  int previewNationSlot = 0;
  fscanf(metadataStream, "%d %d %d %d %d %d %d %d", &nationStateCodesByMapSelection144[0],
         &nationStateCodesByMapSelection144[1], &nationStateCodesByMapSelection144[2],
         &nationStateCodesByMapSelection144[3], &nationStateCodesByMapSelection144[4],
         &nationStateCodesByMapSelection144[5], &nationStateCodesByMapSelection144[6],
         &previewNationSlot);
  fclose(metadataStream);

  TDeluxeText* nationDescription =
      static_cast<TDeluxeText*>(ResolveControlByTag(0x63646573)); // 'cdes'
  nationDescription->AssertValid();
  nationDescription->SetTextEntryFromChars(
      nationDescriptionTextByMapSelection118[previewNationSlot],
      nationDescriptionLengthByMapSelection134[previewNationSlot]);
  nationDescription->SetEnabled(1, 0);
  nationDescription->RefreshControl();

  // The map file is the Mac-endian tile record array; byte 4 of each 0x24-byte record is
  // the owner tag the preview draws.
  ScenarioTileDiskRecord* tileRecords = new ScenarioTileDiskRecord[0x1950];
  g_pUiViewManager->BuildScenarioPathForModeAndIndex(scenarioIndex, 1, &path);
  FILE* mapStream = fopen(path, "rb");
  fread(tileRecords, sizeof(ScenarioTileDiskRecord), 0x1950, mapStream);
  ByteSwapScenarioTileRecordWords(tileRecords);
  fclose(mapStream);
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    fieldBuffer[tileIndex] = tileRecords[tileIndex].ownerNationTag04;
  }

  TMapPreviewView* mapPreview =
      static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagPreviewMap));
  mapPreview->AssertValid();
  mapPreview->TakeSatellitePhoto(fieldBuffer);
  mapPreview->selectedNation68 = previewNationSlot;
  mapPreview->EnhancePhoto();
  mapPreview->SetEnabled(1, 0);
  mapPreview->SetState(1, 0);
  mapPreview->RefreshControl();

  TView* startButton = ResolveControlByTag(kControlTagStar); // 'star'
  startButton->AssertValid();
  startButton->SetState(1, 1);
  startButton->SetEnabled(1, 0);

  delete[] fieldBuffer;
  delete[] tileRecords;

  if (glyphBase84 != 0x1198) {
    SetPictureResourceIdAndRefresh(0x1198, 1);
  }
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
