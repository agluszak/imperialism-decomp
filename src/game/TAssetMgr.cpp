#include "game/TAssetMgr.h"

#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TTurnEventDialogFactoryRegistry.h"

// FUNCTION: IMPERIALISM 0x005df260
CRuntimeClass* TAssetMgr::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df280
TAssetMgr::TAssetMgr() : TObject(), sharedTextSlots() {}

// SYNTHETIC: IMPERIALISM 0x005df300
// TAssetMgr::`scalar deleting destructor'
TAssetMgr::~TAssetMgr() {}

// FUNCTION: IMPERIALISM 0x005df3a0
void ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag) {
  EnsurePictWvDataGobLoadedBySlot(languageTag);
}

void TAssetMgr::EnsurePictWvDataGobLoadedForLanguageSlot(int languageTag) {
  EnsurePictWvDataGobLoadedBySlot(languageTag);
}

// FUNCTION: IMPERIALISM 0x005df3c0
TView* TAssetMgr::ResolveTurnEventDialogNodeByMessageContext(int messageContext) {
  if (g_pTurnEventDialogFactoryRegistry == nullptr) {
    EnsureTurnEventDialogFactoryRegistryInitialized();
  }
  if (g_pTurnEventDialogFactoryRegistry == nullptr) {
    return nullptr;
  }
  return g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(messageContext);
}

// FUNCTION: IMPERIALISM 0x005df3f0
undefined TAssetMgr::NoOpRuntimeUiCallback_005df3f0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df410
undefined TAssetMgr::NoOpRuntimeUiCallback_005df410() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df780
undefined TAssetMgr::NoOpRuntimeUiCallback_005df780() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005dfc10
undefined TAssetMgr::PlayMovieClipAndDispatchTurnStateFollowup() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005dff20
void EnsurePictWvDataGobLoadedBySlot(int languageTag) {
  CString path;
  path.Format("Data/PictWv%d.gob", languageTag);

  if (g_pModuleLibraryCacheState == 0 ||
      g_pModuleLibraryCacheState->LoadModuleLibrarySlotWithErrorDialog(path, 2)) {
    return;
  }

  CString prefix("A file required by the program, '");
  CString message = prefix + path;
  message += "' is missing.";
  AfxMessageBox(message, MB_OK, 0);
}
