#include "game/map_domain_types.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/gfx/TAmbitApplication.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/gfx/TResourceMgr.h"
#include <mbstring.h>
#include <stdio.h>
#include <string.h>

#include "game/ui_core/TApplication.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/ui_screens/TPictureButton.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TUiEvent.h"
#include "game/military/mapped_flavor_text.h"
#include "game/net/TMultiplayerMgr.h"

// FUNCTION: IMPERIALISM 0x0043d8f0
TLoadSavePicture::TLoadSavePicture() {
  styleAt94.textColor = 0;
  styleAt9e.textColor = 0;
}

// FUNCTION: IMPERIALISM 0x0043db20
TLoadSavePicture::~TLoadSavePicture() {}

IMPLEMENT_DYNCREATE(TLoadSavePicture, TPicture)

// FUNCTION: IMPERIALISM 0x0056bcc0
void TLoadSavePicture::DoPostCreate(int arg) {
  loadModeFlag = static_cast<unsigned char>(g_nSaveFormatVersion == -2);
  selectedSlot = -1;
  TPicture::DoPostCreate(arg);
  BuildUiTextStyleDescriptor(&styleAt94, 1, 0xc, 0x2b68);
  BuildUiTextStyleDescriptor(&styleAt9e, 0, 0xc, 0x2b6c);

  TInfoBarText* cursorPanel = static_cast<TInfoBarText*>(FindSubView(kControlTagCurs));
  g_pCursorControlPanel = cursorPanel;
  cursorPanel->AssertValid();
  cursorPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b6b);
  cursorPanel->SetJustification(1, true);

  CString slotPath;
  CString slotCaption;
  for (int slot = 0; slot < 8; ++slot) {
    TStaticText* slotControl =
        static_cast<TStaticText*>(FindSubView(kControlTagSlt0 + slot)); // 'slt0'
    slotControl->AssertValid();
    const char* savePrefix = (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone)
                                 ? g_pszMultiplayerSavePrefix
                                 : g_pszSingleSlotSavePrefix;
    CString slotNumberText;
    slotNumberText.Format(g_szDecimalFormat, slot);
    slotPath =
        CString(g_szSaveDirectoryPrefix) + savePrefix + slotNumberText + g_pszImpSaveExtension;

    if (TryGetFileMetadataForPath(&slotPath) == 0) {
      // Empty slot: the save picture offers it, the load picture greys it out.
      if (loadModeFlag) {
        slotControl->Show(0, 1);
        slotControl->ViewEnable(0, 0);
      } else {
        slotControl->SetTextWithStrListID(0x2737, 0xd, true);
      }
    } else {
      char saveHeader[0x2c];
      FILE* slotFile = fopen(slotPath, g_szLiteralRb);
      fread(saveHeader, 1, sizeof(saveHeader), slotFile);
      fclose(slotFile);
      slotCaption = saveHeader + 0xc;
      slotControl->SetTextAndMaybeRefresh(&slotCaption, true);
    }
    slotControl->InstallTextStyle(styleAt9e, 0);
  }

  if (loadModeFlag) {
    TPicture* okayControl = static_cast<TPicture*>(FindSubView(kControlTagOkay));
    okayControl->AssertValid();
    okayControl->SetPictureRsrcID(static_cast<short>(okayControl->glyphBase + 2), 0);
  } else {
    TView* plateControl = FindSubView(0x706c6174); // 'plat'
    plateControl->AssertValid();
    plateControl->Show(1, 1);
    TMapPreviewView* preview =
        static_cast<TMapPreviewView*>(plateControl->FindSubView(kControlTagMapP));
    preview->AssertValid();
    preview->TakeSatellitePhoto(0);
    preview->selectedNation = g_pSimMgr->GetPlayerCountry();
    preview->EnhancePhoto();
  }

  RefreshActiveControlThenApplyThemeStyleAndCaption(kControlTagInfo, 0, 0xc, 0x2b6a, 0, 0);

  // Hover-help strings differ between the load and the save picture.
  if (loadModeFlag) {
    LoadUiStringByGroupAndIndexToControlObject(0x2737, 0xc, this);
    LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x11, FindSubView(kControlTagOtto));
    LoadUiStringByGroupAndIndexToControlObject(0x2737, 0x14, FindSubView(kControlTagCncl));
    LoadUiStringByGroupAndIndexToControlObject(0x2737, 0x16, FindSubView(kControlTagMapP));
    LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x14, FindSubView(kControlTagOkay));
    for (int slot = 0; slot < 8; ++slot) {
      TView* slotControl = FindSubView(kControlTagSlt0 + slot);
      slotControl->AssertValid();
      LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x12, slotControl);
    }
  } else {
    LoadUiStringByGroupAndIndexToControlObject(0x2737, 0xb, this);
    LoadUiStringByGroupAndIndexToControlObject(0x2737, 0xb, FindSubView(kControlTagOtto));
    LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x15, FindSubView(kControlTagCncl));
    LoadUiStringByGroupAndIndexToControlObject(0x2737, 0x16, FindSubView(kControlTagMapP));
    LoadUiStringByGroupAndIndexToControlObject(0x2743, 2, FindSubView(kControlTagOkay));
    for (int slot = 0; slot < 8; ++slot) {
      TView* slotControl = FindSubView(kControlTagSlt0 + slot);
      slotControl->AssertValid();
      LoadUiStringByGroupAndIndexToControlObject(0x2758, 0x16, slotControl);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056c740
void TLoadSavePicture::LoadHeader(short slotMode) {
  CString path;
  BuildSavePathStringForMode(&path, slotMode, 0);
  if (!TryGetFileMetadataForPath(&path)) {
    return;
  }

  char* tileOwnerTagTable = new char[kStrategicTileCount];
  FILE* file = fopen(path, g_szLiteralRb);
  char headerSkip[0xc];
  fread(headerSkip, 1, 0xc, file);
  unsigned char slotMetadata[0x20];
  fread(slotMetadata, 1, 0x20, file);
  fread(tileOwnerTagTable, 1, kStrategicTileCount, file);
  short turnNumber;
  fread(&turnNumber, 1, 2, file);
  unsigned char oneByteFieldA;
  fread(&oneByteFieldA, 1, 1, file);
  unsigned char pendingNationByte;
  fread(&pendingNationByte, 1, 1, file);
  unsigned char trailingRecord[0x20];
  fread(trailingRecord, 1, 0x20, file);
  fclose(file);

  TMapPreviewView* mapControl = static_cast<TMapPreviewView*>(FindSubView(kControlTagMapP));
  mapControl->AssertValid();
  mapControl->Show(1, 1);
  mapControl->TakeSatellitePhoto(tileOwnerTagTable);
  mapControl->selectedNation = pendingNationByte;
  mapControl->EnhancePhoto();
  mapControl->RefreshControl();

  TStaticText* infoControl = static_cast<TStaticText*>(FindSubView(kControlTagInfo)); // 'info'
  infoControl->AssertValid();

  CString yearText;
  yearText.Format(g_szDecimalFormat, turnNumber + 0x717);
  CString slotNationName;
  g_pSimMgr->GetString(0x2737, oneByteFieldA + 0xd, &slotNationName);
  CString infoText = yearText + ", " + slotNationName;
  infoControl->SetTextAndMaybeRefresh(&infoText, false);

  CRect infoBounds;
  infoControl->GetFrame(&infoBounds);
  InvalidateCityDialogRectRegion(&infoBounds, 1);
}

namespace {

struct SaveFileHeader {
  unsigned char pad0[8];
  int scenarioIndex;
  unsigned char pad0C[0x40 - 0xc];
};

} // namespace

// FUNCTION: IMPERIALISM 0x0056cd10
void TLoadSavePicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xd) {
    short newSlot = sourceHandler->controlTag - kControlTagSlt0;
    if (newSlot != selectedSlot) {
      if (loadModeFlag) {
        if (selectedSlot != -1 && selectedSlot != 0xa1) {
          TControl* oldSlotControl =
              static_cast<TControl*>(FindSubView(kControlTagSlt0 + selectedSlot));
          oldSlotControl->AssertValid();
          oldSlotControl->InstallTextStyle(styleAt9e, 0);
          CRect oldBounds;
          oldSlotControl->GetFrame(&oldBounds);
          InvalidateCityDialogRectRegion(&oldBounds, 1);
        }
        // sourceHandler is the newly-clicked slot control itself.
        TControl* newSlotControl = static_cast<TControl*>(sourceHandler);
        newSlotControl->InstallTextStyle(styleAt94, 0);
        CRect newBounds;
        newSlotControl->GetFrame(&newBounds);
        InvalidateCityDialogRectRegion(&newBounds, 1);
        selectedSlot = newSlot;
        LoadHeader(newSlot);
      } else if (selectedSlot == -1) {
        CString slotText;
        TStaticText* slotControl = static_cast<TStaticText*>(sourceHandler);
        slotControl->AssertValid();
        TEditText* editControl = new TEditText();
        editControl->IEditText(this, &slotControl->ownerLocalX, &slotControl->frameWidth, 0x1f);
        selectedSlot = newSlot;
        slotControl->Show(0, 1);
        slotControl->CopyTextTo(&slotText);

        editControl->InstallTextStyle(styleAt9e, 0);
        editControl->InitDialogWindowAndSyncTitleIfChanged(&slotText, 0);
        editControl->PrepareForDrawing();
        editControl->BecomeTarget();
        editControl->SetSelection(0, static_cast<short>(slotText.GetLength()), 0);
        editControl->controlTag = kControlTagSlot; // 'slot'
        g_pViewMgr->SetBackColor(0x10);
      }
    }
    if (g_pApplication->screenMode > 1) {
      TView* okayControl = FindSubView(kControlTagOkay);
      if (okayControl != NULL) {
        QueueDeferredUiEventPacket(this, 0xa, okayControl);
      }
    }
    return;
  }

  if (commandId == 0x14) {
    if (sourceHandler->controlTag == kControlTagCncl) { // 'clnc'
      HandleTurnFlowStateTickOrShowMainMenu();
    }
    if (loadModeFlag && sourceHandler->controlTag == kControlTagOtto) {
      if (selectedSlot != -1 && selectedSlot != 0xa1) {
        TControl* oldSlotControl =
            static_cast<TControl*>(FindSubView(kControlTagSlt0 + selectedSlot));
        oldSlotControl->AssertValid();
        oldSlotControl->InstallTextStyle(styleAt9e, 0);
        CRect oldBounds;
        oldSlotControl->GetFrame(&oldBounds);
        InvalidateCityDialogRectRegion(&oldBounds, 1);
      }
      selectedSlot = 0xa1;
      LoadHeader(0xa1);
    }
  } else if (commandId == 0xa && sourceHandler->controlTag == kControlTagOkay) {
    HandleSaveGameSlotSelectionAndPromptFlow();
  }
}

// FUNCTION: IMPERIALISM 0x0056d190
void TLoadSavePicture::HandleTurnFlowStateTickOrShowMainMenu() {
  if (g_pSimMgr->previousTurnStateCode != kGamePhaseStartup) {
    g_pSimMgr->StartNextPhase();
    return;
  }
  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pGameFlowState->ResetLocalUiStateAndShowMultiplayerSetup();
    return;
  }
  g_pAmbitApplication->PostTurnEventCodeMessage(kTurnEventMainMenu);
}

// FUNCTION: IMPERIALISM 0x0056d1e0
void TLoadSavePicture::DoKeyEvent(TToolboxEvent* event) {
  int commandCode = event->commandCode;
  if (commandCode == kUiKeyEnter || commandCode == kUiKeyReturn) {
    TPictureButton* okayButton = static_cast<TPictureButton*>(FindSubView(kControlTagOkay));
    if (okayButton != 0) {
      g_pSfxPlaybackSystem->PlaySoundEffect(okayButton->clickSoundId, 0, 1);
      QueueDeferredUiEventPacket(this, 0xa, okayButton);
    }
  } else if (commandCode == kUiKeyEscape && FindSubView(kControlTagCncl) != 0) {
    QueueDeferredUiEventPacket(this, 0x14, FindSubView(kControlTagCncl));
  }
}

namespace {

static bool IsMultiplayerFlowHosting() {
  return g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
}

static bool IsMultiplayerFlowActive() {
  return g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
}

} // namespace

// FUNCTION: IMPERIALISM 0x0056d2a0
void TLoadSavePicture::HandleSaveGameSlotSelectionAndPromptFlow() {
  if (selectedSlot == -1) {
    if (!loadModeFlag) {
      g_pViewMgr->ShowLocalizedUiPromptByGroupAndIndex(0x2758, 0x17, 1, 0);
      return;
    }
    return;
  }
  if (loadModeFlag) {
    if (g_pSimMgr->mode == kGamePhaseStartup ||
        g_pViewMgr->DispatchGameStateEventIfLocalizedPromptAccepted(kControlTagLoad) != 0) {
      GetWindow()->ForceRedraw();
      char* prefix = (char*)g_pszMultiplayerSavePrefix;
      if (!IsMultiplayerFlowActive()) {
        prefix = (char*)g_pszSingleSlotSavePrefix;
      }
      short slot = selectedSlot;
      CString path;
      BuildSavePathStringForMode(&path, slot, prefix);
      if (TryGetFileMetadataForPath(&path) != 0) {
        g_pAssetMgr->LoadTheGame(path);
      }
    }
  } else {
    CString enteredName;
    TEditText* slotNameControl = static_cast<TEditText*>(FindSubView(kControlTagSlot));
    slotNameControl->AssertValid();
    slotNameControl->GetCurrentText(&enteredName);
    if (enteredName.Compare(g_szEmptyString) == 0) {
      enteredName = BuildSharedStringFromMappedFlavorTextIndex(0xd);
      slotNameControl->InitDialogWindowAndSyncTitleIfChanged(&enteredName, 1);
      slotNameControl->ForceRedraw();
    }
    strcpy(g_ScenarioSaveNameBuffer, enteredName);
    if (IsMultiplayerFlowActive()) {
      g_pGameFlowState->AttemptSave(selectedSlot, (char*)g_pszMultiplayerSavePrefix, true);
    } else {
      SaveGameWithModeAndOptionalLabel(selectedSlot, (char*)g_pszSingleSlotSavePrefix);
    }
    g_pSimMgr->StartNextPhase();
  }
  g_pSfxPlaybackSystem->ResetPlayList();
  g_pSfxPlaybackSystem->AddToPlayList(2);
  g_pSfxPlaybackSystem->AddToPlayList(3);
  g_pSfxPlaybackSystem->PlayRandomTrack();
}

// FUNCTION: IMPERIALISM 0x0056d660
void __cdecl BuildSavePathStringForMode(CString* out, int saveMode, char* label) {
  const char* prefix = label;
  if (label == 0) {
    prefix = g_pszMultiplayerSavePrefix;
    if (!IsMultiplayerFlowActive()) {
      prefix = g_pszSingleSlotSavePrefix;
    }
  }
  CString slotText;
  if (saveMode == 0xa1) {
    CString autosaveLabel(g_szLiteralA);
    slotText = autosaveLabel;
  } else {
    slotText.Format(g_szDecimalFormat, saveMode);
  }
  {
    CString directoryPrefix(g_szSaveDirectoryPrefix);
    *out = directoryPrefix;
  }
  *out += prefix;
  *out += slotText;
  *out += g_pszImpSaveExtension;
}

// FUNCTION: IMPERIALISM 0x0056d7d0
int __cdecl ReadScenarioIndexFromSaveHeader(const char* path) {
  SaveFileHeader header;
  int result = -3;
  FILE* file = fopen(path, g_szLiteralRb);
  if (fread(&header, 1, 0xc, file) == 0xc) {
    result = header.scenarioIndex;
  }
  fclose(file);
  return result;
}

// FUNCTION: IMPERIALISM 0x0056d840
void LoadAndFormatMappedFlavorTextRecordsFromStream(int* outSlot, int targetGameId) {
  CString scratch;
  for (int slot = 0; slot < 8; ++slot) {
    const char* prefix = (g_pSimMgr->multiplayerSessionRole == kSessionRoleStandalone)
                             ? g_szSingleSlotSavePrefix
                             : g_szMultiplayerSavePrefix;
    CString slotStr;
    slotStr.Format(g_szDecimalFormat, slot);
    CString path(g_szSaveDirectoryPrefix);
    path += prefix;
    path += slotStr;
    path += g_szImpSaveExtension;
    if (TryGetFileMetadataForPath(&path)) {
      FILE* file = fopen(static_cast<const char*>(path), g_szLiteralRb);
      int header[3];
      int gameId = -3;
      if (fread(header, 1, 0xc, file) == 0xc) {
        gameId = header[2];
      }
      fclose(file);
      if (gameId == targetGameId) {
        *outSlot = slot;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056da50
void __cdecl SaveGameWithModeAndOptionalLabel(int mode, char* label) {
  bool markSaved = true;
  if (mode == 0xa2) {
    markSaved = false;
    mode = 0xa1;
  }

  if (IsMultiplayerFlowHosting() && mode == 0xa1) {
    int currentScenario = g_pGameFlowState->queueSyncDword;
    CString probePath;
    for (int i = 0; i < 8; ++i) {
      BuildSavePathStringForMode(&probePath, i, 0);
      if (TryGetFileMetadataForPath(&probePath) &&
          ReadScenarioIndexFromSaveHeader(probePath) == currentScenario) {
        mode = i;
      }
    }
  }

  if (mode == 0xa1) {
    CString scenarioName;
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&scenarioName, 0x2758, 9);
    strcpy(g_ScenarioSaveNameBuffer, scenarioName);
  }

  CString savePath;
  if (label == 0) {
    label = (char*)g_pszMultiplayerSavePrefix;
    if (!IsMultiplayerFlowActive()) {
      label = (char*)g_pszSingleSlotSavePrefix;
    }
  }
  {
    CString slotText;
    if (mode == 0xa1) {
      CString autosaveLabel(g_szLiteralA);
      slotText = autosaveLabel;
    } else {
      slotText.Format(g_szDecimalFormat, mode);
    }
    {
      CString directoryPrefix(g_szSaveDirectoryPrefix);
      savePath = directoryPrefix;
    }
    savePath += label;
    savePath += slotText;
    savePath += g_pszImpSaveExtension;
  }

  if (g_pAssetMgr->SaveTheGame(savePath)) {
    if (IsMultiplayerFlowHosting()) {
      g_pGameFlowState->networkSavePending = markSaved;
      g_pGameFlowState->SendGameControl(kControlTagSave, markSaved, -2);
    }
    if (IsMultiplayerFlowHosting() && mode != 0xa1) {
      const char* autosavePrefix = g_pszMultiplayerSavePrefix;
      if (!IsMultiplayerFlowActive()) {
        autosavePrefix = g_pszSingleSlotSavePrefix;
      }
      {
        CString autosaveSlotText;
        {
          CString autosaveLabel(g_szLiteralA);
          autosaveSlotText = autosaveLabel;
        }
        {
          CString directoryPrefix(g_szSaveDirectoryPrefix);
          savePath = directoryPrefix;
        }
        savePath += autosavePrefix;
        savePath += autosaveSlotText;
        savePath += g_pszImpSaveExtension;
      }
      if (TryGetFileMetadataForPath(&savePath)) {
        SaveFileHeader header;
        int scenarioIndex = -3;
        FILE* file = fopen(savePath, g_szLiteralRb);
        if (fread(&header, 1, 0xc, file) == 0xc) {
          scenarioIndex = header.scenarioIndex;
        }
        fclose(file);
        if (scenarioIndex == g_pGameFlowState->queueSyncDword) {
          DeleteFileWithErrorReporting(&savePath);
        }
      }
    }
  } else {
    if (IsMultiplayerFlowHosting()) {
      g_pGameFlowState->networkSavePending = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056df40
unsigned char __cdecl BuildSaveSlotPathAndProbeMetadata(int slot, const char* label) {
  CString path;
  const char* prefix = label;
  if (label == 0) {
    prefix = g_pszMultiplayerSavePrefix;
    if (!IsMultiplayerFlowActive()) {
      prefix = g_pszSingleSlotSavePrefix;
    }
  }
  {
    CString slotText;
    if (slot == 0xa1) {
      CString autosaveLabel(g_szLiteralA);
      slotText = autosaveLabel;
    } else {
      slotText.Format(g_szDecimalFormat, slot);
    }
    {
      CString directoryPrefix(g_szSaveDirectoryPrefix);
      path = directoryPrefix;
    }
    path += prefix;
    path += slotText;
    path += g_pszImpSaveExtension;
  }
  if (TryGetFileMetadataForPath(&path) == 0) {
    return 0;
  }
  return g_pAssetMgr->LoadTheGame(path);
}
