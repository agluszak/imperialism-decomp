#include "game/TAmbitApplication.h"
#include "game/TWindow.h"
#include "game/TSetupRandomMapPicture.h"

#include "game/TApplication.h"
#include "game/TAssetMgr.h"
#include "game/TControl.h"
#include "game/TDropShadowText.h"
#include "game/TEditText.h"
#include "game/TGWorldPartView.h"
#include "game/TInfoBarText.h"
#include "game/TLanguageMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TMapMgr.h"
#include "game/TMapPreviewView.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMultiplayerMgr.h"
#include "game/TPicture.h"
#include "game/TRadioText.h"
#include "game/TRadioTextCluster.h"
#include "game/TSoundPlayer.h"
#include "game/TSpaceCommand.h"
#include "game/TSimMgr.h"
#include "game/TUiEvent.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TAmbitApplication.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

#include <stdlib.h>

static void GenerateDifferentRandomMapSeed(CString* seed) {
  CString previousSeed(*seed);
  do {
    GenerateMappedFlavorTextByCurrentContextNation(seed);
  } while (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(*seed)),
                   reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(previousSeed))) == 0);
}

// SYNTHETIC: IMPERIALISM 0x00576ca0
// TSetupRandomMapPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00576d60
// TSetupRandomMapPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSetupRandomMapPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00576d80
TSetupRandomMapPicture::TSetupRandomMapPicture()
    : TNoHilitePicture(), planetSeed94(), wrapHorizontally98(0), countryControlReadyA4(0) {}

// SYNTHETIC: IMPERIALISM 0x00576e00
// TSetupRandomMapPicture::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x00576e30
// TSetupRandomMapPicture::~TSetupRandomMapPicture
TSetupRandomMapPicture::~TSetupRandomMapPicture() {}

// FUNCTION: IMPERIALISM 0x00576fe0
void TSetupRandomMapPicture::RecheckCountryName() {
  if (countryControlReadyA4 == 0) {
    bool sessionInactive = g_pSimMgr->multiplayerSessionRole == 0;
    if (sessionInactive) {
      TEditText* countryControl = static_cast<TEditText*>(ResolveControlByTag(kControlTagCoun));
      countryControl->AssertValid();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00577030
void TSetupRandomMapPicture::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);
  g_pUiViewManager->EnsurePictWvDataGobLoadedBySlot(0);
  g_pSimMgr->scenarioMapIndexPlusOne = 0;

  if (g_pGlobalMapState == 0) {
    // LIBRARY: rand (0x005e83f0)
    selectedNationSlot9A = static_cast<short>(rand() % 7);
    GenerateMappedFlavorTextByCurrentContextNation(&planetSeed94);
    wrapHorizontally98 = 0;
  } else {
    planetSeed94 = g_pGlobalMapState->scenarioTagText1c;
    wrapHorizontally98 = g_pGlobalMapState->hexNeighborWrapHorizontally20;
    selectedNationSlot9A = static_cast<short>(g_nRandomMapSelectedNationSlot00698AB0);
    if (selectedNationSlot9A == -1) {
      // LIBRARY: rand (0x005e83f0)
      selectedNationSlot9A = static_cast<short>(rand() % 7);
    }
    TMapPreviewView* mapPreview =
        static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagMapP));
    mapPreview->AssertValid();
    mapPreview->pendingNation6C = selectedNationSlot9A;
  }

  RefreshActiveControlThenApplyThemeStyleAndCaption(kControlTagCoun, 0, 0xc, 0x2b6b, 1,
                                                    g_szEmptyString);
  TEditText* countryControl = static_cast<TEditText*>(ResolveControlByTag(kControlTagCoun));
  countryControl->AssertValid();
  countryControl->maxCharacterCount = 0xc;

  g_bMultiplayerScenarioSetupActive = 0;
  g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);

  g_pCursorControlPanel = static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagHot));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->SetTextStyle(0, 0xe, 0x2b6b);
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  g_pCursorControlPanel->SetTextAlignmentAndMaybeRefresh(1, 0);

  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagKeyP);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagStuf);

  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2758, 0x1e, kControlTagName);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x13, kControlTagGlob);
  short cancelStringIndex = g_pSimMgr->multiplayerSessionRole != 0 ? 0x2e : 0x14;
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, cancelStringIndex, kControlTagCanc);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, cancelStringIndex, kControlTagCncl);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x15, kControlTagOkay);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2758, 0x13, kControlTagMapP);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x17, kControlTagDiff);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x1a, kControlTagCoun);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x1b, kControlTagFlag);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x1c, kControlTagCoat);

  TDropShadowText* countryTitle =
      static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagTcou));
  countryTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(countryTitle, 0, 0xe, 0x2b6a, 0x2b6c);
  countryTitle->SetTextFromStringResource(0x2737, 0x1e, 0);

  TMapPreviewView* mapPreview = static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagMapP));
  mapPreview->AssertValid();
  mapPreview->selectedNation68 = selectedNationSlot9A;

  GroundControlToMajorTom(1);
  g_pCursorControlPanel->SetTextAlignmentAndMaybeRefresh(1, 0);

  TGWorldPartView* flagView = static_cast<TGWorldPartView*>(ResolveControlByTag(kControlTagFlag));
  flagView->AssertValid();
  flagView->sourceSurface60 = g_pStrategicMapViewSystem->atlas680;
  flagView->sourceRect64.left = selectedNationSlot9A * flagView->frameWidth34;
  flagView->sourceRect64.top = 0;
  flagView->sourceRect64.right = (selectedNationSlot9A + 1) * flagView->frameWidth34;
  flagView->sourceRect64.bottom = flagView->frameHeight38;

  if (g_pSimMgr->multiplayerSessionRole != 0) {
    g_cstrCountryNameSettingValue006A4220 =
        g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&g_pGameFlowState->playerNameMirror);
  } else {
    g_pSimMgr->useLocalizedNameTables68 = static_cast<char>(g_pSimMgr->preferenceValues[13]);
    GenerateMappedFlavorTextByCurrentContextNation(&g_cstrCountryNameSettingValue006A4220);
    CString profileName;
    LoadProfileStringAndAssignSharedRef(&profileName, g_szCountryNameProfileKey00698AE0,
                                        g_cstrCountryNameSettingValue006A4220);
    g_cstrCountryNameSettingValue006A4220 =
        g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&profileName);
  }

  RefreshActiveControlThenApplyThemeStyleAndCaption(kControlTagCoun, 0, 0xc, 0x2b6b, 1,
                                                    g_cstrCountryNameSettingValue006A4220);

  TRadioTextCluster* difficultyCluster =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagDiff));
  difficultyCluster->AssertValid();
  difficultyCluster->SetSelectedTextOptionByTag(kControlTagDif0 + g_pSimMgr->preferenceValues[11],
                                                false);
  difficultyCluster->frameThemeCode90 = 0x2b6b;

  TDropShadowText* difficultyTitle =
      static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagDift));
  difficultyTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(difficultyTitle, 0, 0xe, 0x2b6a, 0x2b6c);
  CString labelText;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 2);
  difficultyTitle->SetTextAndMaybeRefresh(&labelText, 0);

  TDropShadowText* namesTitle = static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagTnam));
  namesTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(namesTitle, 0, 0xe, 0x2b6a, 0x2b6c);
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 3);
  namesTitle->SetTextAndMaybeRefresh(&labelText, 0);

  TRadioTextCluster* namesCluster =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagName));
  namesCluster->AssertValid();
  namesCluster->SetSelectedTextOptionByTag(
      g_pSimMgr->preferenceValues[13] != 0 ? kControlTagHist : kControlTagRand, false);
  namesCluster->frameThemeCode90 = 0x2b6b;

  TRadioText* historicalNames =
      static_cast<TRadioText*>(namesCluster->ResolveControlByTag(kControlTagHist));
  historicalNames->AssertValid();
  ApplyUiTextStyleAndThemeFlags(historicalNames, 0, 0xc, 0x2b6b, 0x2b6c);
  historicalNames->SetTextAlignmentAndMaybeRefresh(1, 0);
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 4);
  historicalNames->SetTextAndMaybeRefresh(&labelText, 0);
  historicalNames->controlValue3c = kControlTagHist;

  TRadioText* randomNames =
      static_cast<TRadioText*>(namesCluster->ResolveControlByTag(kControlTagRand));
  randomNames->AssertValid();
  ApplyUiTextStyleAndThemeFlags(randomNames, 0, 0xc, 0x2b6b, 0x2b6c);
  randomNames->SetTextAlignmentAndMaybeRefresh(1, 0);
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 5);
  randomNames->SetTextAndMaybeRefresh(&labelText, 0);
  randomNames->controlValue3c = kControlTagRand;

  for (int difficulty = 0; difficulty < 5; ++difficulty) {
    TRadioText* option = static_cast<TRadioText*>(
        difficultyCluster->ResolveControlByTag(kControlTagDif0 + difficulty));
    option->AssertValid();
    ApplyUiTextStyleAndThemeFlags(option, 0, 0xc, 0x2b6b, 0x2b6c);
    option->SetTextAlignmentAndMaybeRefresh(1, 0);
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2737,
                                                                    difficulty + 0xe);
    option->SetTextAndMaybeRefresh(&labelText, 0);
    option->controlValue3c = difficulty;
  }

  RecheckCountryName();
}

// FUNCTION: IMPERIALISM 0x005779c0
void TSetupRandomMapPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x7069636b /* 'pick' */) {
    TMapPreviewView* mapPreview = static_cast<TMapPreviewView*>(sourceHandler);
    mapPreview->AssertValid();
    mapPreview->selectedNation68 = mapPreview->pendingNation6C;
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    selectedNationSlot9A = static_cast<short>(mapPreview->selectedNation68);

    TGWorldPartView* flagView = static_cast<TGWorldPartView*>(ResolveControlByTag(kControlTagFlag));
    flagView->AssertValid();
    flagView->SetSourceRectFromGridCell(selectedNationSlot9A, 0);
    flagView->RefreshControl();

    TPicture* coatView = static_cast<TPicture*>(ResolveControlByTag(kControlTagCoat));
    coatView->AssertValid();
    coatView->SetPictureResourceIdAndRefresh(static_cast<short>(selectedNationSlot9A + 0x11c6),
                                             true);

    RecheckCountryName();
    mapPreview->EnhancePhoto();

    CRect previewBounds;
    mapPreview->QueryContentBounds(&previewBounds);
    ScopedMapQuickDrawContext mapContext(mapPreview);
    mapPreview->Draw(&previewBounds);
  }

  unsigned int controlTag = static_cast<unsigned int>(sourceHandler->controlTag);
  if (controlTag == kControlTagGlob &&
      (static_cast<unsigned short>(GetAsyncKeyState(VK_CONTROL)) & 0x8000) != 0) {
    controlTag = 0x706c616e; // 'plan'
  }

  if (commandId == 0x14 || commandId == 0xa || commandId == 0x22 || commandId == 0xd) {
    if (controlTag == kControlTagCanc || controlTag == kControlTagCncl) {
      ExitScreen();
    } else if (controlTag == kControlTagGlob) {
      GenerateDifferentRandomMapSeed(&planetSeed94);
      MajorTomToGroundControl(1);
    } else if (controlTag == kControlTagKeyP || controlTag == 0x706c616e /* 'plan' */) {
      CString planetSeed(planetSeed94);
      CString instruction;
      CString unusedOptionText;
      CString unusedCancelText;
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&instruction, 0x2758, 6);
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&unusedOptionText, 0x2758,
                                                                      10);
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&unusedCancelText, 0x2758,
                                                                      11);
      int resultTag = g_pUiRuntimeContext->MakePlanetSeedDialog(static_cast<LPCSTR>(instruction),
                                                                planetSeed, 0, 0, 0, 0);
      wrapHorizontally98 = resultTag == 0x6f6e6531 /* 'one1' */;

      if (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(planetSeed)),
                  reinterpret_cast<const unsigned char*>(g_szEmptyString)) != 0 &&
          _mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(planetSeed)),
                  reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(planetSeed94))) != 0) {
        planetSeed94 = planetSeed;
        MajorTomToGroundControl(1);
      } else {
        g_pGlobalMapState->hexNeighborWrapHorizontally20 = wrapHorizontally98;
      }
    } else if (controlTag == kControlTagOkay) {
      StartGame();
    }
  }

  TNoHilitePicture::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00577e40
void TSetupRandomMapPicture::StartGame() {
  TEditText* countryControl = static_cast<TEditText*>(ResolveControlByTag(kControlTagCoun));
  countryControl->AssertValid();

  CString countryText;
  countryControl->GetCurrentText(&countryText);
  if (g_pSimMgr->useLocalizedNameTables68 != 0) {
    CString localizedName;
    unsigned char duplicateName = 0;
    for (int nationSlot = 0; nationSlot < 0x17 && duplicateName == 0; ++nationSlot) {
      if (nationSlot != selectedNationSlot9A) {
        g_pSimMgr->GetString(0x2715, static_cast<short>(nationSlot), &localizedName);
        duplicateName =
            _mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(localizedName)),
                    reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(countryText))) == 0;
      }
    }
    if (duplicateName != 0) {
      g_pSimMgr->GetString(0x2715, selectedNationSlot9A, &countryText);
    }
  }

  {
    CString emptyName(g_szEmptyString);
    g_cstrCountryNameSettingValue006A4220 = emptyName;
  }
  g_cstrCountryNameSettingValue006A4220 +=
      g_pLanguageMgr->PickGender(static_cast<LPCSTR>(countryText));
  g_cstrCountryNameSettingValue006A4220 += countryText;

  TRadioTextCluster* difficultyCluster =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagDiff));
  difficultyCluster->AssertValid();
  TControl* selectedDifficulty =
      static_cast<TControl*>(ResolveControlByTag(difficultyCluster->selectedTag88));
  selectedDifficulty->AssertValid();
  int difficulty = selectedDifficulty->controlValue3c;
  g_pSimMgr->SetDifficultyLevel(difficulty);
  g_pSimMgr->preferenceValues[11] = static_cast<short>(difficulty);

  TRadioTextCluster* nameCluster =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagName));
  nameCluster->AssertValid();
  g_pSimMgr->useLocalizedNameTables68 = nameCluster->selectedTag88 != kControlTagRand;
  g_pSimMgr->preferenceValues[13] = static_cast<short>(g_pSimMgr->useLocalizedNameTables68);
  g_pSimMgr->InitializeOrLoadEntryArray14AndClampLimits(true);

  g_nRandomMapSelectedNationSlot00698AB0 = selectedNationSlot9A;
  if (g_pSimMgr->multiplayerSessionRole != 0) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventNetworkGameOptions));
    g_pGameFlowState->playerNameMirror = g_cstrCountryNameSettingValue006A4220;
    g_pGameFlowState->playerNameString = g_cstrCountryNameSettingValue006A4220;
    g_pGameFlowState->activeNationTagIndex = static_cast<unsigned char>(selectedNationSlot9A);
    return;
  }

  g_pSimMgr->SetActiveNationSlotAndRefreshCityCapabilityUiHandles(selectedNationSlot9A);
  {
    CString countryName(g_cstrCountryNameSettingValue006A4220);
    g_pUiViewManager->SaveSettingValueFromPointerByKey(&countryName,
                                                       g_szCountryNameProfileKey00698AE0);
  }
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    g_pSimMgr->nationControlModes[nationSlot] = 2;
  }
  g_pSimMgr->nationControlModes[selectedNationSlot9A] = 1;
  g_pSimMgr->StartNextPhase();
}

// FUNCTION: IMPERIALISM 0x005781f0
void TSetupRandomMapPicture::ExitScreen() {
  unsigned char multiplayerSessionActive = g_pSimMgr->multiplayerSessionRole != 0;
  if (multiplayerSessionActive != 0) {
    g_pGameFlowState->ResetLocalUiStateAndPostTurnEvent5E5();
    return;
  }
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(EncodeTurnEventCode(kTurnEventMainMenu));
}

// FUNCTION: IMPERIALISM 0x00578230
void TSetupRandomMapPicture::GroundControlToMajorTom(unsigned char mode) {
  TSpaceCommand* command = new TSpaceCommand();
  command->InitializeRangePair(0x4e415341 /* 'NASA' */, g_pGlobalUiRootController, 0, 0, 0);
  command->setupPicture18 = this;
  command->mode1c = mode;
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x005782f0
void TSetupRandomMapPicture::DoKeyEvent(TToolboxEvent* event) {
  TToolboxEvent* commandEvent = event;
  int commandCode = commandEvent->commandCode;
  if (commandCode == 3 || commandCode == 0xd) {
    StartGame();
  } else if (commandCode == 0x1b) {
    ExitScreen();
  }
}

// FUNCTION: IMPERIALISM 0x00578330
void TSetupRandomMapPicture::MajorTomToGroundControl(unsigned char mode) {
  TInfoBarText* infoBar = static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagHot));
  infoBar->AssertValid();
  CString generatingText;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&generatingText, 0x2758, 7);
  infoBar->UpdateTextEntrySharedStringAndMaybeNotify(&generatingText, 1);
  infoBar->CenterVertically(1);

  TEditText* countryControl = static_cast<TEditText*>(ResolveControlByTag(kControlTagCoun));
  countryControl->AssertValid();
  countryControl->SetEnabled(0, 0);

  TView* settingsPanel = ResolveControlByTag(kControlTagStuf);
  settingsPanel->AssertValid();
  int hiddenSettingsPanelPosition[2] = {0x7d0, 0x898};
  int visibleSettingsPanelPosition[2] = {0x120, 4};
  settingsPanel->CaptureLayoutF0(hiddenSettingsPanelPosition, 0);

  SetPictureResourceIdAndRefresh(0x1195, true);
  TPicture* coatView = static_cast<TPicture*>(ResolveControlByTag(kControlTagCoat));
  coatView->AssertValid();
  coatView->SetPictureResourceIdAndRefresh(0x11cd, true);

  if (mode != 0) {
    GetWindow()->ForceRedraw();
  }

  g_pActiveRandomMapSetupPicture006A4268 = this;
  lastGlobeTick9C = GetTickCountDiv16();
  globeFrameA0 = 0;
  SpinYourGlobe();
  g_pSimMgr->RebuildMapContextAndGlobalMapState(1, static_cast<LPCSTR>(planetSeed94),
                                                static_cast<int>(wrapHorizontally98));
  g_pActiveRandomMapSetupPicture006A4268 = 0;
  SpinYourGlobe();

  TMapPreviewView* mapPreview = static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagMapP));
  mapPreview->AssertValid();
  mapPreview->TakeSatellitePhoto(0);
  mapPreview->EnhancePhoto();

  countryControl->SetEnabled(1, 0);
  settingsPanel->CaptureLayoutF0(visibleSettingsPanelPosition, 0);
  SetPictureResourceIdAndRefresh(0x11bc, true);
  coatView->SetPictureResourceIdAndRefresh(static_cast<short>(selectedNationSlot9A + 0x11c6), true);

  CString emptyText(g_szEmptyString);
  infoBar->UpdateTextEntrySharedStringAndMaybeNotify(&emptyText, 1);
  RecheckCountryName();
}

// FUNCTION: IMPERIALISM 0x00578680
void TSetupRandomMapPicture::SpinYourGlobe() {
  unsigned int now = GetTickCountDiv16();
  if (now > lastGlobeTick9C) {
    lastGlobeTick9C = GetTickCountDiv16();
    ++globeFrameA0;
    if (globeFrameA0 >= 24) {
      globeFrameA0 = 0;
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 == 0) {
    globeFrameA0 = 0;
  }

  TNoHilitePicture* globe = static_cast<TNoHilitePicture*>(ResolveControlByTag(kControlTagGlob));
  globe->AssertValid();
  globe->SetPictureResourceIdAndRefresh(static_cast<short>(globeFrameA0 + 0x11d0), false);

  ScopedMapQuickDrawContext globeContext(globe);
  globe->PrepareForDrawing();
  CRect bounds;
  globe->QueryBounds(&bounds);
  globe->Draw(&bounds);
}
