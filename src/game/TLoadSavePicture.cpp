#include "game/TLoadSavePicture.h"

#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include <stdio.h>

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
void TLoadSavePicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x0056d190
undefined TLoadSavePicture::HandleTurnFlowStateTickOrPostTurnEvent5DC() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0056d1e0
void TLoadSavePicture::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x0056d2a0
undefined TLoadSavePicture::HandleSaveGameSlotSelectionAndPromptFlow() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0056d660
void __cdecl BuildSavePathStringForMode(CString* out, int saveMode, char* label) {
  const char* prefix = label;
  if (label == 0) {
    prefix = g_szMultiplayerSavePrefix_00698710;
    if (g_pSimMgr->field44 == 0) {
      prefix = g_szSingleSlotSavePrefix_00698718;
    }
  }
  CString slotText;
  if (saveMode == 0xa1) {
    slotText = g_szAutosaveSlotLabel_0069872C;
  } else {
    slotText.Format(g_szDecimalFormat, saveMode);
  }
  *out = g_szSaveDirectoryPrefix_00698724;
  *out += prefix;
  *out += slotText;
  *out += g_szImpSaveExtension_00698708;
}

// FUNCTION: IMPERIALISM 0x0056d7d0
int __cdecl ReadScenarioIndexFromSaveHeader(const char* path) {
  struct SaveFileHeader {
    unsigned char pad0[8];
    int scenarioIndex;
  } header;
  FILE* file = fopen(path, g_szSaveFileReadBinaryMode_00698720);
  int result = -3;
  if (fread(&header, 1, 0xc, file) == 0xc) {
    result = header.scenarioIndex;
  }
  fclose(file);
  return result;
}
