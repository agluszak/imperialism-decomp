#include "game/TAssetMgr.h"

#include "game/CFile_Virtuals.h"

#include "game/CAmbitDocument.h"
#include "game/ImperialismApp.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMovieView.h"
#include "game/TSoundPlayer.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
// SYNTHETIC: IMPERIALISM 0x005df1d0
// TAssetMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x005df260
// TAssetMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAssetMgr, TObject)

// FUNCTION: IMPERIALISM 0x005df280
TAssetMgr::TAssetMgr() : TObject(), sharedTextSlots() {}

// SYNTHETIC: IMPERIALISM 0x005df300
// TAssetMgr::`scalar deleting destructor'
TAssetMgr::~TAssetMgr() {}

// FUNCTION: IMPERIALISM 0x005df3a0
void TAssetMgr::ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag) {
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

// FUNCTION: IMPERIALISM 0x005df430
CFile_Virtuals* TAssetMgr::LoadTableResourceStreamByName(CString name) {
  // TODO: port body @ 0x5df430.
  (void)name;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df6d0
void TAssetMgr::ReleaseResourceStreamIfNotNull(CFile_Virtuals* stream) {
  if (stream != 0) {
    stream->CloseAndMaybeDeleteSlot04(1);
  }
}

// FUNCTION: IMPERIALISM 0x005df700
int TAssetMgr::ReadResourceStreamIntoBufferAndAdvance(CFile_Virtuals* stream, void* buffer,
                                                      int* countInOut) {
  *countInOut = stream->ReadBytesSlot3C(buffer, *countInOut);
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df760
int TAssetMgr::GetResourceStreamSize(CFile_Virtuals* stream) {
  return stream->GetLengthSlot38();
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
void TAssetMgr::EnsurePictWvDataGobLoadedBySlot(int languageTag) {
  CString path;
  path.Format(s_PictWvGobPathFormat_00698BF4, languageTag);

  if (g_pModuleLibraryCacheState->LoadModuleLibrarySlotWithErrorDialog(path, 2)) {
    return;
  }

  // Original builds the message with operator+ temporaries (prefix + path + suffix),
  // not in-place +=; the leading const-char*+CString picks the global operator+.
  AfxMessageBox(
      static_cast<LPCTSTR>(s_MissingFilePrefix_0069B820 + path + s_MissingFileSuffix_0069B810),
      MB_OK, 0);
}

namespace {

// RAII wait-cursor guard reconstructed from 0x5e0030's EH layout: EH state 1 opens with
// a fully inlined AfxGetApp()->BeginWaitCursor() and unwinds with the matching inlined
// EndWaitCursor() — an inline-ctor/dtor guard object, unlike MFC's out-of-line
// CWaitCursor.
struct TScopedWaitCursor {
  TScopedWaitCursor() {
    AfxGetApp()->BeginWaitCursor();
  }
  ~TScopedWaitCursor() {
    AfxGetApp()->EndWaitCursor();
  }
};

} // namespace

// Saves the active MFC document to `savePath`, then restamps the document path with the
// "__saved" marker so the next save re-prompts. Original doc-vtable slots: SetPathName
// +0x5c, DoSave +0xa0 (both match retail nafxcw).
// FUNCTION: IMPERIALISM 0x005e0030
unsigned char TAssetMgr::SaveMainDocumentToPathAndMarkSaved(const CString& savePath) {
  CString path(savePath);
  CFrameWnd* frame = static_cast<CFrameWnd*>(AfxGetMainWnd());
  frame->AssertValid();
  CAmbitDocument* document = static_cast<CAmbitDocument*>(frame->GetActiveView()->GetDocument());
  TScopedWaitCursor waitCursor;
  document->SetPathName(path, FALSE);
  unsigned char saved = (unsigned char)document->DoSave(document->GetPathName(), TRUE);
  document->SetPathName(g_szSavedDocumentMarker_0069B848, FALSE);
  return saved;
}

// FUNCTION: IMPERIALISM 0x005e0150
unsigned char TAssetMgr::OpenMainDocumentFromPathAndMarkLoaded(const CString& loadPath) {
  CDocument* document = g_pImperialismApp->OpenDocumentFile(loadPath);
  if (document == 0) {
    return 0;
  }
  document->SetPathName(g_szLoadedDocumentMarker_0069B854, FALSE);
  return 1;
}
