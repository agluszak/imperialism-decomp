#include "game/TAssetMgr.h"

#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
IMPLEMENT_DYNCREATE(TAssetMgr, TObject)

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

extern "C" const char s_PictWvGobPathFormat_00698BF4[];
extern "C" const char s_MissingFilePrefix_0069B820[];
extern "C" const char s_MissingFileSuffix_0069B810[];

// FUNCTION: IMPERIALISM 0x005dff20
void __stdcall EnsurePictWvDataGobLoadedBySlot(int languageTag) {
  CString path;
  path.Format(s_PictWvGobPathFormat_00698BF4, languageTag);

  if (g_pModuleLibraryCacheState->LoadModuleLibrarySlotWithErrorDialog(path, 2)) {
    return;
  }

  CString message(s_MissingFilePrefix_0069B820);
  message += path;
  message += s_MissingFileSuffix_0069B810;
  AfxMessageBox(static_cast<LPCTSTR>(message), MB_OK, 0);
}
