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
  (void)languageTag;
  EnsurePictWvDataGobLoadedBySlot(0);
}

void TAssetMgr::EnsurePictWvDataGobLoadedForLanguageSlot(int languageTag) {
  EnsurePictWvDataGobLoadedBySlot(languageTag);
}

// FUNCTION: IMPERIALISM 0x005df3c0
TView* TAssetMgr::ResolveTurnEventDialogNodeByMessageContext(int messageContext) {
  return g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(messageContext, 0);
}

// FUNCTION: IMPERIALISM 0x005df3f0
void TAssetMgr::NoOpRuntimeUiCallback_005df3f0(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x005df410
void TAssetMgr::NoOpRuntimeUiCallback_005df410(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x005df780
void TAssetMgr::NoOpRuntimeUiCallback_005df780(int arg) {
  (void)arg;
}

// Builds "Movies\<movieName>" (+ install-drive prefix), stashes followupEventCode in the
// UI-runtime context, then tries to play the clip via the message-499 detach helper and
// posts the turn-state followup. Left as a signature-correct stub: a faithful body needs
// ImperialismApp::DetectImperialismInstallDriveAndSetPathPrefix (0x414870) promoted to a
// real method first — it depends on the __thiscall helper 0x5feba9, which is still a free
// stub, so porting it now would require a forbidden calling-convention cast.
// FUNCTION: IMPERIALISM 0x005dfc10
void TAssetMgr::PlayMovieClipAndDispatchTurnStateFollowup(CString movieName,
                                                          int followupEventCode) {
  (void)movieName;
  (void)followupEventCode;
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
