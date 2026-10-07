#include "game/nation_domain_types.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"

#include <mbstring.h>

#include "game/ui_core/TApplication.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TEditText.h"
#include "game/app/TGWorldPartView.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/gfx/TResourceMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/TRadioText.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_screens/TSpaceCommand.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_text_label_helpers_decls.h"

#include <stdlib.h>

IMPLEMENT_DYNCREATE(TSetupRandomMapPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00576d80
TSetupRandomMapPicture::TSetupRandomMapPicture() : wrapHorizontally(0), countryControlReady(0) {}

TSetupRandomMapPicture::~TSetupRandomMapPicture() {}

// FUNCTION: IMPERIALISM 0x00576ef0
void TSetupRandomMapPicture::PickCountry(short nationSlot) {
  selectedNationSlot = nationSlot;

  TGWorldPartView* flagView = static_cast<TGWorldPartView*>(FindSubView(kControlTagFlag));
  flagView->AssertValid();
  int flagStripRight = (selectedNationSlot + 1) * flagView->frameWidth;
  flagView->sourceRect.left = selectedNationSlot * flagView->frameWidth;
  flagView->sourceRect.top = 0;
  flagView->sourceRect.right = flagStripRight;
  flagView->sourceRect.bottom = flagView->frameHeight;
  flagView->RefreshControl();

  TPicture* coatView = static_cast<TPicture*>(FindSubView(kControlTagCoat));
  coatView->AssertValid();
  coatView->SetPictureRsrcID(static_cast<short>(selectedNationSlot + 0x11c6), true);

  if (!countryControlReady) {
    bool sessionInactive = g_pSimMgr->multiplayerSessionRole == kSessionRoleStandalone;
    if (sessionInactive) {
      TEditText* countryControl = static_cast<TEditText*>(FindSubView(kControlTagCoun));
      countryControl->AssertValid();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00576fe0
void TSetupRandomMapPicture::RecheckCountryName() {
  if (!countryControlReady) {
    bool sessionInactive = g_pSimMgr->multiplayerSessionRole == kSessionRoleStandalone;
    if (sessionInactive) {
      TEditText* countryControl = static_cast<TEditText*>(FindSubView(kControlTagCoun));
      countryControl->AssertValid();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00577030
void TSetupRandomMapPicture::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);
  g_pAssetMgr->EnsurePictWvDataGobLoadedBySlot(0);
  g_pSimMgr->scenarioMapIndexPlusOne = 0;

  if (g_pGlobalMapState == 0) {
    // LIBRARY: rand (0x005e83f0)
    selectedNationSlot = static_cast<short>(rand() % 7);
    GenerateFlavorTextForNation(&planetSeed);
    wrapHorizontally = 0;
  } else {
    planetSeed = g_pGlobalMapState->scenarioTagText;
    wrapHorizontally = g_pGlobalMapState->hexNeighborWrapHorizontally;
    selectedNationSlot = static_cast<short>(g_nRandomMapSelectedNationSlot);
    if (selectedNationSlot == -1) {
      // LIBRARY: rand (0x005e83f0)
      selectedNationSlot = static_cast<short>(rand() % 7);
    }
    TMapPreviewView* mapPreview = static_cast<TMapPreviewView*>(FindSubView(kControlTagMapP));
    mapPreview->AssertValid();
    mapPreview->pendingNation = selectedNationSlot;
  }

  RefreshAndTheme(kControlTagCoun, 0, 0xc, 0x2b6b, 1, g_szEmptyString);
  TEditText* countryControl = static_cast<TEditText*>(FindSubView(kControlTagCoun));
  countryControl->AssertValid();
  countryControl->maxCharacterCount = 0xc;

  g_bMultiplayerScenarioSetupActive = false;
  g_pSimMgr->CreateSimObjects(true);

  g_pCursorControlPanel = static_cast<TInfoBarText*>(FindSubView(kControlTagHot));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->SetTextStyle(0, 0xe, 0x2b6b);
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  g_pCursorControlPanel->SetJustification(1, false);

  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagKeyP);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagStuf);

  SetTaggedStringAndApply(0x2758, 0x1e, kControlTagName);
  SetTaggedStringAndApply(0x2737, 0x13, kControlTagGlob);
  short cancelStringIndex =
      g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone ? 0x2e : 0x14;
  SetTaggedStringAndApply(0x2737, cancelStringIndex, kControlTagCanc);
  SetTaggedStringAndApply(0x2737, cancelStringIndex, kControlTagCncl);
  SetTaggedStringAndApply(0x2737, 0x15, kControlTagOkay);
  SetTaggedStringAndApply(0x2758, 0x13, kControlTagMapP);
  SetTaggedStringAndApply(0x2737, 0x17, kControlTagDiff);
  SetTaggedStringAndApply(0x2737, 0x1a, kControlTagCoun);
  SetTaggedStringAndApply(0x2737, 0x1b, kControlTagFlag);
  SetTaggedStringAndApply(0x2737, 0x1c, kControlTagCoat);

  TDropShadowText* countryTitle = static_cast<TDropShadowText*>(FindSubView(kControlTagTcou));
  countryTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(countryTitle, 0, 0xe, 0x2b6a, 0x2b6c);
  countryTitle->SetTextWithStrListID(0x2737, 0x1e, false);

  TMapPreviewView* mapPreview = static_cast<TMapPreviewView*>(FindSubView(kControlTagMapP));
  mapPreview->AssertValid();
  mapPreview->selectedNation = selectedNationSlot;

  GroundControlToMajorTom(1);
  g_pCursorControlPanel->SetJustification(1, false);

  TGWorldPartView* flagView = static_cast<TGWorldPartView*>(FindSubView(kControlTagFlag));
  flagView->AssertValid();
  flagView->sourceSurface = g_pMacViewMgr->flagWorld;
  flagView->sourceRect.left = selectedNationSlot * flagView->frameWidth;
  flagView->sourceRect.top = 0;
  flagView->sourceRect.right = (selectedNationSlot + 1) * flagView->frameWidth;
  flagView->sourceRect.bottom = flagView->frameHeight;

  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_cstrCountryNameSettingValue =
        g_pLanguageMgr->StripCodeStr(g_pGameFlowState->playerNameMirror);
  } else {
    g_pSimMgr->useLocalizedNameTables = static_cast<char>(g_pSimMgr->preferenceValues[13]);
    GenerateFlavorTextForNation(&g_cstrCountryNameSettingValue);
    CString profileName;
    LoadProfileStringAndAssignSharedRef(&profileName, g_szCountryNameProfileKey,
                                        g_cstrCountryNameSettingValue);
    g_cstrCountryNameSettingValue = g_pLanguageMgr->StripCodeStr(profileName);
  }

  RefreshAndTheme(kControlTagCoun, 0, 0xc, 0x2b6b, 1, g_cstrCountryNameSettingValue);

  TRadioTextCluster* difficultyCluster =
      static_cast<TRadioTextCluster*>(FindSubView(kControlTagDiff));
  difficultyCluster->AssertValid();
  difficultyCluster->SetSelectedTextOptionByTag(kControlTagDif0 + g_pSimMgr->preferenceValues[11],
                                                false);
  difficultyCluster->frameThemeCode = 0x2b6b;

  TDropShadowText* difficultyTitle = static_cast<TDropShadowText*>(FindSubView(kControlTagDift));
  difficultyTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(difficultyTitle, 0, 0xe, 0x2b6a, 0x2b6c);
  CString labelText;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 2);
  difficultyTitle->SetTextAndMaybeRefresh(&labelText, false);

  TDropShadowText* namesTitle = static_cast<TDropShadowText*>(FindSubView(kControlTagTnam));
  namesTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(namesTitle, 0, 0xe, 0x2b6a, 0x2b6c);
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 3);
  namesTitle->SetTextAndMaybeRefresh(&labelText, false);

  TRadioTextCluster* namesCluster = static_cast<TRadioTextCluster*>(FindSubView(kControlTagName));
  namesCluster->AssertValid();
  namesCluster->SetSelectedTextOptionByTag(
      g_pSimMgr->preferenceValues[13] != 0 ? kControlTagHist : kControlTagRand, false);
  namesCluster->frameThemeCode = 0x2b6b;

  TRadioText* historicalNames =
      static_cast<TRadioText*>(namesCluster->FindSubView(kControlTagHist));
  historicalNames->AssertValid();
  ApplyUiTextStyleAndThemeFlags(historicalNames, 0, 0xc, 0x2b6b, 0x2b6c);
  historicalNames->SetJustification(1, false);
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 4);
  historicalNames->SetTextAndMaybeRefresh(&labelText, false);
  historicalNames->controlValue = kControlTagHist;

  TRadioText* randomNames = static_cast<TRadioText*>(namesCluster->FindSubView(kControlTagRand));
  randomNames->AssertValid();
  ApplyUiTextStyleAndThemeFlags(randomNames, 0, 0xc, 0x2b6b, 0x2b6c);
  randomNames->SetJustification(1, false);
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2758, 5);
  randomNames->SetTextAndMaybeRefresh(&labelText, false);
  randomNames->controlValue = kControlTagRand;

  for (int difficulty = 0; difficulty < 5; ++difficulty) {
    TRadioText* option =
        static_cast<TRadioText*>(difficultyCluster->FindSubView(kControlTagDif0 + difficulty));
    option->AssertValid();
    ApplyUiTextStyleAndThemeFlags(option, 0, 0xc, 0x2b6b, 0x2b6c);
    option->SetJustification(1, false);
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&labelText, 0x2737, difficulty + 0xe);
    option->SetTextAndMaybeRefresh(&labelText, false);
    option->controlValue = difficulty;
  }

  RecheckCountryName();
}

// FUNCTION: IMPERIALISM 0x005779c0
void TSetupRandomMapPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == kControlTagPick) {
    TMapPreviewView* mapPreview = static_cast<TMapPreviewView*>(sourceHandler);
    mapPreview->AssertValid();
    mapPreview->selectedNation = mapPreview->pendingNation;
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    selectedNationSlot = static_cast<short>(mapPreview->selectedNation);

    TGWorldPartView* flagView = static_cast<TGWorldPartView*>(FindSubView(kControlTagFlag));
    flagView->AssertValid();
    flagView->SetSourceRectFromGridCell(selectedNationSlot, 0);
    flagView->RefreshControl();

    TPicture* coatView = static_cast<TPicture*>(FindSubView(kControlTagCoat));
    coatView->AssertValid();
    coatView->SetPictureRsrcID(static_cast<short>(selectedNationSlot + 0x11c6), true);

    RecheckCountryName();
    mapPreview->EnhancePhoto();

    CRect previewBounds;
    mapPreview->GetExtent(&previewBounds);
    ScopedMapQuickDrawContext mapContext(mapPreview);
    mapPreview->Draw(&previewBounds);
  }

  unsigned int controlTag = sourceHandler->controlTag;
  if (controlTag == kControlTagGlob &&
      (static_cast<unsigned short>(GetAsyncKeyState(VK_CONTROL)) & 0x8000) != 0) {
    controlTag = kControlTagPlan; // 'plan'
  }

  if (commandId == 0x14 || commandId == 0xa || commandId == 0x22 || commandId == 0xd) {
    if (controlTag == kControlTagCanc || controlTag == kControlTagCncl) {
      ExitScreen();
    } else if (controlTag == kControlTagGlob) {
      GenerateFlavorTextForNation(&this->planetSeed);
      MajorTomToGroundControl(1);
    } else if (controlTag == kControlTagKeyP || controlTag == kControlTagPlan) {
      CString planetSeed(this->planetSeed);
      CString instruction;
      CString unusedOptionText;
      CString unusedCancelText;
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&instruction, 0x2758, 6);
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&unusedOptionText, 0x2758, 10);
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&unusedCancelText, 0x2758, 11);
      int resultTag = g_pViewMgr->MakePlanetSeedDialog(static_cast<LPCSTR>(instruction), planetSeed,
                                                       0, 0, 0, false);
      wrapHorizontally = resultTag == kControlTagOne1;

      if (planetSeed.Compare(g_szEmptyString) != 0 && planetSeed.Compare(this->planetSeed) != 0) {
        this->planetSeed = planetSeed;
        MajorTomToGroundControl(1);
      } else {
        g_pGlobalMapState->hexNeighborWrapHorizontally = wrapHorizontally;
      }
    } else if (controlTag == kControlTagOkay) {
      StartGame();
    }
  }

  TNoHilitePicture::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00577e40
void TSetupRandomMapPicture::StartGame() {
  TEditText* countryControl = static_cast<TEditText*>(FindSubView(kControlTagCoun));
  countryControl->AssertValid();

  CString countryText;
  countryControl->GetCurrentText(&countryText);
  if (g_pSimMgr->useLocalizedNameTables != 0) {
    CString localizedName;
    bool duplicateName = false;
    for (int nationSlot = 0; nationSlot < kNationSlotCount && !duplicateName; ++nationSlot) {
      if (nationSlot != selectedNationSlot) {
        g_pSimMgr->GetString(0x2715, static_cast<short>(nationSlot), &localizedName);
        duplicateName = localizedName.Compare(countryText) == 0;
      }
    }
    if (duplicateName) {
      g_pSimMgr->GetString(0x2715, selectedNationSlot, &countryText);
    }
  }

  {
    CString emptyName(g_szEmptyString);
    g_cstrCountryNameSettingValue = emptyName;
  }
  g_cstrCountryNameSettingValue += g_pLanguageMgr->PickGender(static_cast<LPCSTR>(countryText));
  g_cstrCountryNameSettingValue += countryText;

  TRadioTextCluster* difficultyCluster =
      static_cast<TRadioTextCluster*>(FindSubView(kControlTagDiff));
  difficultyCluster->AssertValid();
  TControl* selectedDifficulty =
      static_cast<TControl*>(FindSubView(difficultyCluster->selectedTag));
  selectedDifficulty->AssertValid();
  eDifficulty difficulty = static_cast<eDifficulty>(selectedDifficulty->controlValue);
  g_pSimMgr->SetDifficultyLevel(difficulty);
  g_pSimMgr->preferenceValues[11] = static_cast<short>(difficulty);

  TRadioTextCluster* nameCluster = static_cast<TRadioTextCluster*>(FindSubView(kControlTagName));
  nameCluster->AssertValid();
  g_pSimMgr->useLocalizedNameTables = nameCluster->selectedTag != kControlTagRand;
  g_pSimMgr->preferenceValues[13] = static_cast<short>(g_pSimMgr->useLocalizedNameTables);
  g_pSimMgr->UpdatePreferences(true);

  g_nRandomMapSelectedNationSlot = selectedNationSlot;
  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pAmbitApplication->PostTurnEventCodeMessage(
        EncodeTurnEventCode(kTurnEventNetworkGameOptions));
    g_pGameFlowState->playerNameMirror = g_cstrCountryNameSettingValue;
    g_pGameFlowState->playerNameString = g_cstrCountryNameSettingValue;
    g_pGameFlowState->activeNationTagIndex = static_cast<unsigned char>(selectedNationSlot);
    return;
  }

  g_pSimMgr->SetPlayerCountry(selectedNationSlot);
  {
    CString countryName(g_cstrCountryNameSettingValue);
    g_pAssetMgr->SetPreferenceString(&countryName, g_szCountryNameProfileKey);
  }
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    g_pSimMgr->nationControlModes[nationSlot] = 2;
  }
  g_pSimMgr->nationControlModes[selectedNationSlot] = 1;
  g_pSimMgr->StartNextPhase();
}

// FUNCTION: IMPERIALISM 0x005781f0
void TSetupRandomMapPicture::ExitScreen() {
  bool multiplayerSessionActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
  if (multiplayerSessionActive) {
    g_pGameFlowState->ResetAndShowMultiplayerSetup();
    return;
  }
  g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventMainMenu));
}

// FUNCTION: IMPERIALISM 0x00578230
void TSetupRandomMapPicture::GroundControlToMajorTom(unsigned char mode) {
  TSpaceCommand* command = new TSpaceCommand();
  command->ICommand(kControlTagNASA, g_pAmbitApplication, 0, 0, 0);
  command->setupPicture = this;
  command->mode = mode;
  g_pAmbitApplication->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x005782f0
void TSetupRandomMapPicture::DoKeyEvent(TToolboxEvent* event) {
  TToolboxEvent* commandEvent = event;
  int commandCode = commandEvent->commandCode;
  if (commandCode == kUiKeyEnter || commandCode == kUiKeyReturn) {
    StartGame();
  } else if (commandCode == kUiKeyEscape) {
    ExitScreen();
  }
}

// FUNCTION: IMPERIALISM 0x00578330
void TSetupRandomMapPicture::MajorTomToGroundControl(unsigned char mode) {
  TInfoBarText* infoBar = static_cast<TInfoBarText*>(FindSubView(kControlTagHot));
  infoBar->AssertValid();
  CString generatingText;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&generatingText, 0x2758, 7);
  infoBar->SetEntryText(&generatingText, true);
  infoBar->CenterVertically(true);

  TEditText* countryControl = static_cast<TEditText*>(FindSubView(kControlTagCoun));
  countryControl->AssertValid();
  countryControl->Show(0, 0);

  TView* settingsPanel = FindSubView(kControlTagStuf);
  settingsPanel->AssertValid();
  CPoint hiddenSettingsPanelPosition(0x7d0, 0x898);
  CPoint visibleSettingsPanelPosition(0x120, 4);
  settingsPanel->Locate(hiddenSettingsPanelPosition, false);

  SetPictureRsrcID(0x1195, true);
  TPicture* coatView = static_cast<TPicture*>(FindSubView(kControlTagCoat));
  coatView->AssertValid();
  coatView->SetPictureRsrcID(0x11cd, true);

  if (mode != 0) {
    GetWindow()->ForceRedraw();
  }

  g_pActiveRandomMapSetupPicture = this;
  lastGlobeTick = GetTickCountDiv16();
  globeFrame = 0;
  SpinYourGlobe();
  g_pSimMgr->CreatePlanet(1, static_cast<LPCSTR>(planetSeed), static_cast<int>(wrapHorizontally));
  g_pActiveRandomMapSetupPicture = 0;
  SpinYourGlobe();

  TMapPreviewView* mapPreview = static_cast<TMapPreviewView*>(FindSubView(kControlTagMapP));
  mapPreview->AssertValid();
  mapPreview->TakeSatellitePhoto(0);
  mapPreview->EnhancePhoto();

  countryControl->Show(1, 0);
  settingsPanel->Locate(visibleSettingsPanelPosition, false);
  SetPictureRsrcID(0x11bc, true);
  coatView->SetPictureRsrcID(static_cast<short>(selectedNationSlot + 0x11c6), true);

  CString emptyText(g_szEmptyString);
  infoBar->SetEntryText(&emptyText, true);
  RecheckCountryName();
}

// FUNCTION: IMPERIALISM 0x00578680
void TSetupRandomMapPicture::SpinYourGlobe() {
  unsigned int now = GetTickCountDiv16();
  if (now > lastGlobeTick) {
    lastGlobeTick = GetTickCountDiv16();
    ++globeFrame;
    if (globeFrame >= 24) {
      globeFrame = 0;
    }
  }
  if (g_pActiveRandomMapSetupPicture == 0) {
    globeFrame = 0;
  }

  TNoHilitePicture* globe = static_cast<TNoHilitePicture*>(FindSubView(kControlTagGlob));
  globe->AssertValid();
  globe->SetPictureRsrcID(static_cast<short>(globeFrame + 0x11d0), false);

  ScopedMapQuickDrawContext globeContext(globe);
  globe->PrepareForDrawing();
  CRect bounds;
  globe->GetFrame(&bounds);
  globe->Draw(&bounds);
}
