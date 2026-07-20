#include "game/TLoadSavePicture.h"

#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include <stdio.h>
#include <string.h>

#include "game/TAssetMgr.h"
#include "game/TEditText.h"
#include "game/TSoundPlayer.h"
#include "game/TViewMgr.h"
#include "game/mapped_flavor_text.h"
#include "game/TMultiplayerMgr.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x0043da40
// TLoadSavePicture::`scalar deleting destructor'
TLoadSavePicture::~TLoadSavePicture() {}
// SYNTHETIC: IMPERIALISM 0x0056bbd0
// TLoadSavePicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056bca0
// TLoadSavePicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLoadSavePicture, TPicture)

TLoadSavePicture::TLoadSavePicture() {}

// FUNCTION: IMPERIALISM 0x0056bcc0
void TLoadSavePicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x0056cd10
void TLoadSavePicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  // The original also handles commandId==0xd (a slot-tab-index switch spanning
  // selectedSlot92/loadModeFlag90, InvalidateCityDialogRectRegion, and further per-slot
  // control refreshes) here -- not yet ported. The original never calls a base-class
  // HandleEvent in any path, so none is modeled here either.
  if (commandId == 0xa && sourceHandler->controlTag == kControlTagOkay) {
    HandleSaveGameSlotSelectionAndPromptFlow();
  }
}

// FUNCTION: IMPERIALISM 0x0056d190
undefined TLoadSavePicture::HandleTurnFlowStateTickOrPostTurnEvent5DC() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0056d1e0
void TLoadSavePicture::ForwardParam(int param) {}

namespace {

// The whole save flow tests g_pSimMgr->field44 through Boolean-returning inline
// helpers: every original site materializes the comparison into a byte register
// (sete/setne + test al,al) before branching, the Mac-style unsigned-char Boolean shape
// under /Ob1.
static __inline unsigned char IsMultiplayerFlowHosting() {
  return g_pSimMgr->field44 == 1;
}

static __inline unsigned char IsMultiplayerFlowActive() {
  return g_pSimMgr->field44 != 0;
}

} // namespace

// Save/load-slot confirm flow. No slot selected: pose the "pick a slot" prompt when
// saving, else do nothing. Load picture: after the confirm prompt (skipped when the
// setup mode is already 1), refresh the owner panel, rebuild the slot's save path with
// the mult/slot prefix, and open the document when the file exists. Save picture:
// fetch the name typed into the 'slot' edit control (defaulting empty text to the
// mapped flavor string 0xd), publish it to the scenario-name buffer, then run the
// multiplayer-aware or plain save driver and re-post turn-flow command 100. Both
// completed paths reset the audio cue pools and schedule a random cue.
// FUNCTION: IMPERIALISM 0x0056d2a0
undefined TLoadSavePicture::HandleSaveGameSlotSelectionAndPromptFlow() {
  if (selectedSlot92 == -1) {
    if (loadModeFlag90 == 0) {
      return g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x2758, 0x17, 1, 0);
    }
    return 0;
  }
  if (loadModeFlag90 != 0) {
    if (g_pSimMgr->mode == 1 ||
        g_pUiRuntimeContext->DispatchGameStateEventIfLocalizedPromptAccepted(0x6c6f6164) != 0) {
      OwnerPanel()->InvokeSlot13C();
      char* prefix = (char*)g_pszMultiplayerSavePrefix_0065DDD4;
      if (!IsMultiplayerFlowActive()) {
        prefix = (char*)g_pszSingleSlotSavePrefix_0065DDD0;
      }
      short slot = selectedSlot92;
      CString path;
      BuildSavePathStringForMode(&path, slot, prefix);
      if (TryGetFileMetadataForPath(&path) != 0) {
        g_pUiViewManager->OpenMainDocumentFromPathAndMarkLoaded(path);
      }
    }
  } else {
    CString enteredName;
    TEditText* slotNameControl = static_cast<TEditText*>(ResolveControlByTag(0x736c6f74));
    slotNameControl->AssertValid();
    slotNameControl->GetCurrentText(&enteredName);
    if (strcmp(enteredName, g_szEmptyString) == 0) {
      enteredName = BuildSharedStringFromMappedFlavorTextIndex(0xd);
      slotNameControl->InitDialogWindowAndSyncTitleIfChanged(&enteredName, 1);
      slotNameControl->InvokeSlot13C();
    }
    strcpy(g_ScenarioSaveNameBuffer_006A2178, enteredName);
    if (IsMultiplayerFlowActive()) {
      g_pGameFlowState->TrySaveGameAndMaybeShowFailureDialog(
          selectedSlot92, (char*)g_pszMultiplayerSavePrefix_0065DDD4, 1);
    } else {
      SaveGameWithModeAndOptionalLabel(selectedSlot92, (char*)g_pszSingleSlotSavePrefix_0065DDD0);
    }
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
  }
  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(2);
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(3);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0056d660
void __cdecl BuildSavePathStringForMode(CString* out, int saveMode, char* label) {
  const char* prefix = label;
  if (label == 0) {
    prefix = g_pszMultiplayerSavePrefix_0065DDD4;
    if (!IsMultiplayerFlowActive()) {
      prefix = g_pszSingleSlotSavePrefix_0065DDD0;
    }
  }
  CString slotText;
  if (saveMode == 0xa1) {
    CString autosaveLabel(g_szAutosaveSlotLabel_0069872C);
    slotText = autosaveLabel;
  } else {
    slotText.Format(g_szDecimalFormat, saveMode);
  }
  {
    CString directoryPrefix(g_szSaveDirectoryPrefix_00698724);
    *out = directoryPrefix;
  }
  *out += prefix;
  *out += slotText;
  *out += g_pszImpSaveExtension_0065DDD8;
}

namespace {

// Save-file header record: both header readers reserve the full 0x40 bytes on the stack
// (sub esp,0x40 at 0x56d7d4 / the 0x48 local area at 0x56da65) but only fread the first
// 0xc bytes to reach scenarioIndex.
struct SaveFileHeader {
  unsigned char pad0[8];
  int scenarioIndex; // +0x08
  unsigned char pad0C[0x40 - 0xc];
};

} // namespace

// FUNCTION: IMPERIALISM 0x0056d7d0
int __cdecl ReadScenarioIndexFromSaveHeader(const char* path) {
  SaveFileHeader header;
  int result = -3;
  FILE* file = fopen(path, g_szSaveFileReadBinaryMode_00698720);
  if (fread(&header, 1, 0xc, file) == 0xc) {
    result = header.scenarioIndex;
  }
  fclose(file);
  return result;
}

// Top-level save-game driver. mode 0xa1 = autosave slot "A"; 0xa2 = autosave without
// marking the document saved; 0..7 = numbered slot. In multiplayer (field44 == 1) an
// autosave first rebinds to the numbered slot whose save file carries the current
// scenario id, and the scenario display name (resource 0x2758/9) is published to
// g_ScenarioSaveNameBuffer_006A2178 for the slot picker. After a successful manual save
// in multiplayer the flow dispatches the 'save' game-state event and deletes a stale
// autosave of the same scenario.
// FUNCTION: IMPERIALISM 0x0056da50
void __cdecl SaveGameWithModeAndOptionalLabel(int mode, char* label) {
  char markSaved = 1;
  if (mode == 0xa2) {
    markSaved = 0;
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
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&scenarioName, 0x2758, 9);
    strcpy(g_ScenarioSaveNameBuffer_006A2178, scenarioName);
  }

  CString savePath;
  if (label == 0) {
    label = (char*)g_pszMultiplayerSavePrefix_0065DDD4;
    if (!IsMultiplayerFlowActive()) {
      label = (char*)g_pszSingleSlotSavePrefix_0065DDD0;
    }
  }
  {
    CString slotText;
    if (mode == 0xa1) {
      CString autosaveLabel(g_szAutosaveSlotLabel_0069872C);
      slotText = autosaveLabel;
    } else {
      slotText.Format(g_szDecimalFormat, mode);
    }
    {
      CString directoryPrefix(g_szSaveDirectoryPrefix_00698724);
      savePath = directoryPrefix;
    }
    savePath += label;
    savePath += slotText;
    savePath += g_pszImpSaveExtension_0065DDD8;
  }

  if (g_pUiViewManager->SaveMainDocumentToPathAndMarkSaved(savePath)) {
    if (IsMultiplayerFlowHosting()) {
      g_pGameFlowState->fieldF4 = markSaved;
      g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x73617665, markSaved, -2);
    }
    if (IsMultiplayerFlowHosting() && mode != 0xa1) {
      const char* autosavePrefix = g_pszMultiplayerSavePrefix_0065DDD4;
      if (!IsMultiplayerFlowActive()) {
        autosavePrefix = g_pszSingleSlotSavePrefix_0065DDD0;
      }
      {
        CString autosaveSlotText;
        {
          CString autosaveLabel(g_szAutosaveSlotLabel_0069872C);
          autosaveSlotText = autosaveLabel;
        }
        {
          CString directoryPrefix(g_szSaveDirectoryPrefix_00698724);
          savePath = directoryPrefix;
        }
        savePath += autosavePrefix;
        savePath += autosaveSlotText;
        savePath += g_pszImpSaveExtension_0065DDD8;
      }
      if (TryGetFileMetadataForPath(&savePath)) {
        SaveFileHeader header;
        int scenarioIndex = -3;
        FILE* file = fopen(savePath, g_szSaveFileReadBinaryMode_00698720);
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
      g_pGameFlowState->fieldF4 = 0;
    }
  }
}

// Build the slot's save path (same recipe as BuildSavePathStringForMode) and, when the
// file exists, open it as the main document; returns whether the load was kicked off.
// FUNCTION: IMPERIALISM 0x0056df40
unsigned char __cdecl BuildSaveSlotPathAndProbeMetadata(int slot, const char* label) {
  CString path;
  const char* prefix = label;
  if (label == 0) {
    prefix = g_pszMultiplayerSavePrefix_0065DDD4;
    if (!IsMultiplayerFlowActive()) {
      prefix = g_pszSingleSlotSavePrefix_0065DDD0;
    }
  }
  {
    CString slotText;
    if (slot == 0xa1) {
      CString autosaveLabel(g_szAutosaveSlotLabel_0069872C);
      slotText = autosaveLabel;
    } else {
      slotText.Format(g_szDecimalFormat, slot);
    }
    {
      CString directoryPrefix(g_szSaveDirectoryPrefix_00698724);
      path = directoryPrefix;
    }
    path += prefix;
    path += slotText;
    path += g_pszImpSaveExtension_0065DDD8;
  }
  if (TryGetFileMetadataForPath(&path) != 0) {
    return g_pUiViewManager->OpenMainDocumentFromPathAndMarkLoaded(path);
  }
  return 0;
}
