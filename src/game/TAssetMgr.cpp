#include "game/TAssetMgr.h"

#include "game/ImperialismApp.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMovieView.h"
#include "game/TSoundPlayer.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
IMPLEMENT_DYNCREATE(TAssetMgr, TObject)

// FUNCTION: IMPERIALISM 0x005df280
TAssetMgr::TAssetMgr() : TObject(), sharedTextSlots() {}

// SYNTHETIC: IMPERIALISM 0x005df300
// TAssetMgr::`scalar deleting destructor'
TAssetMgr::~TAssetMgr() {}

// FUNCTION: IMPERIALISM 0x005df3a0
void __stdcall ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag) {
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

// FUNCTION: IMPERIALISM 0x005dfc10
void TAssetMgr::PlayMovieClipAndDispatchTurnStateFollowup(CString movieName,
                                                          TMovieView* movieView) {
  CString moviePath = CString("Movies/") + movieName;
  moviePath = moviePath + ".avi";

  CString prefixedPath =
      CString(g_pImperialismApp->DetectImperialismInstallDriveAndSetPathPrefix()) + moviePath;

  g_pUiRuntimeContext->activeMovieViewF4 = movieView;
  if (!movieView->OpenMoviePathAndDetachOnSuccess(static_cast<LPCTSTR>(prefixedPath))) {
    if (!movieView->OpenMoviePathAndDetachOnSuccess(static_cast<LPCTSTR>(moviePath))) {
      g_pUiRuntimeContext->HandleTurnStateExitAndPostFollowupEventCode(0);
      return;
    }
  }

  g_pSfxPlaybackSystem->ClearDirectSoundInitPendingAndResetState();
  g_pUiRuntimeContext->HandleTurnStateExitAndPostFollowupEventCode(2);
  movieView->PlayMovieIfActive();
}

// FUNCTION: IMPERIALISM 0x005dfea0
void __stdcall AssignScoresDatPathToSharedString(CString* out) {
  *out = CString(s_Data_scores_dat_0069b7fc);
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
