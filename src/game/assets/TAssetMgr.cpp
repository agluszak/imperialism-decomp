#include "game/TScopedWaitCursor.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TWindow.h"

#include "game/app/CAmbitDocument.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/assets/TMovieView.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/assets_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

#include <io.h>
// SYNTHETIC: IMPERIALISM 0x005df1d0
// TAssetMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x005df260
// TAssetMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAssetMgr, TObject)

// FUNCTION: IMPERIALISM 0x005df280
TAssetMgr::TAssetMgr() : TObject(), sharedTextSlots() {}

// SYNTHETIC: IMPERIALISM 0x005df300
// TAssetMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005df330
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
TView* TAssetMgr::ResolveTurnEventDialogNodeByMessageContext(TurnEventId messageContext) {
  return g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(messageContext, 0);
}

// FUNCTION: IMPERIALISM 0x005df3f0
void TAssetMgr::OpenFilesFor(short fileSet) {
  (void)fileSet;
}

// FUNCTION: IMPERIALISM 0x005df410
void TAssetMgr::CloseFilesFor(short fileSet) {
  (void)fileSet;
}

// Per-callsite assert-suppress flag, adjacent to timer_slots.cpp's
// g_timerDispatchSuppressAssert (0x6a5d24) in the original WAssetMgr.cpp.
int g_resourceStreamOpenSuppressAssert; // 0x6a5d20

// FUNCTION: IMPERIALISM 0x005df430
CFile* TAssetMgr::LoadTableResourceStreamByName(CString name) {
  HMODULE hModule = LoadLibraryA(g_pImperialismApp->field_D4);
  HRSRC hResInfo = FindResourceA(hModule, name, "TABLE");
  if (hResInfo != 0) {
    HGLOBAL hResData = LoadResource(hModule, hResInfo);
    CMemFile* memFile = new CMemFile(0x400);
    LPVOID buffer = LockResource(hResData);
    DWORD size = SizeofResource(hModule, hResInfo);
    memFile->Attach(static_cast<BYTE*>(buffer), size, 0);
    return memFile;
  }

  CFile* file = new CFile();
  CFileException exception;
  if (file->Open(name, CFile::modeReadWrite, &exception) == 0 &&
      g_resourceStreamOpenSuppressAssert == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\WAssetMgr.cpp", 0xce);
  }
  return file;
}

// FUNCTION: IMPERIALISM 0x005df6d0
void TAssetMgr::ReleaseResourceStreamIfNotNull(CFile* stream) {
  if (stream != 0) {
    delete stream;
  }
}

// FUNCTION: IMPERIALISM 0x005df700
int TAssetMgr::ReadResourceStreamIntoBufferAndAdvance(CFile* stream, void* buffer,
                                                      int* countInOut) {
  *countInOut = stream->Read(buffer, *countInOut);
  return 0;
}
// `this` (g_pUiViewManager at every callsite) is unused; the method just reseeks the
// stream.
// FUNCTION: IMPERIALISM 0x005df730
void TAssetMgr::SeekResourceStreamFromBeginning(CFile* stream, int offset) {
  stream->Seek(offset, CFile::begin);
}

// FUNCTION: IMPERIALISM 0x005df760
int TAssetMgr::GetResourceStreamSize(CFile* stream) {
  return stream->GetLength();
}

// FUNCTION: IMPERIALISM 0x005df780
void TAssetMgr::OpenFilesForView(short fileSet) {
  (void)fileSet;
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

// FUNCTION: IMPERIALISM 0x005dfd70
void TAssetMgr::BuildScenarioPathForModeAndIndex(int scenarioIndex, int mode, CString* outPath) {
  CString numberText;
  numberText.Format(g_szDecimalFormat, scenarioIndex);
  CString fullPath = "Scenario/s" + numberText;
  *outPath = fullPath;
  switch (mode) {
  case 0:
    *outPath += ".inf";
    break;
  case 1:
    *outPath += ".map";
    break;
  case 2:
    *outPath += ".scn";
    break;
  }
}

// FUNCTION: IMPERIALISM 0x005dfea0
void __stdcall AssignScoresDatPathToSharedString(CString* out) {
  *out = CString(s_Data_scores_dat_0069b7fc);
}

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

// FUNCTION: IMPERIALISM 0x005e0260
void TAssetMgr::SaveSettingValueFromPointerByKey(CString* value, const char* key) {
  g_pImperialismApp->SetSettingValueInSettingsSection(key, *value);
}

// FUNCTION: IMPERIALISM 0x005e0290
void TAssetMgr::LoadSettingValueByKeyIntoOut(int* out, LPCSTR key, int defaultValue) {
  *out = g_pImperialismApp->GetSettingValueFromSettingsSection(key, defaultValue);
}

// FUNCTION: IMPERIALISM 0x005e02c0
void TAssetMgr::WriteIntegerSettingByValueAndKey(int value, LPCSTR key) {
  g_pImperialismApp->WriteSettingValueToSettingsSection(key, value);
}

// FUNCTION: IMPERIALISM 0x005e02f0
unsigned char TAssetMgr::HasPendingClientSaveFile() {
  _finddata_t fileInfo;
  long findHandle = _findfirst("save/cli_*.imp", &fileInfo);
  _findclose(findHandle);
  return findHandle != -1;
}

// FUNCTION: IMPERIALISM 0x005e0340
int TAssetMgr::DeleteLegacyCliSaveImpFiles() {
  int deletedCount = 0;
  _finddata_t fileInfo;
  long findHandle = _findfirst("save/cli_*.imp", &fileInfo);
  _findclose(findHandle);
  while (findHandle != -1) {
    CFile::Remove(CString("save/") + fileInfo.name);
    deletedCount++;
    findHandle = _findfirst("save/cli_*.imp", &fileInfo);
    _findclose(findHandle);
  }
  return deletedCount;
}

// FUNCTION: IMPERIALISM 0x005e0520
void TAssetMgr::ScheduleTimerSlotCallbackWithInterval(TimerSlotCallback callback, UINT interval,
                                                      int slot) {
  g_timerSlotCallbacks[slot] = callback;

  CWnd* mainWnd;
  if (AfxGetThread() == NULL) {
    mainWnd = NULL;
  } else {
    mainWnd = AfxGetThread()->GetMainWnd();
  }
  g_timerSlotIds[slot] = ::SetTimer(mainWnd->m_hWnd, slot + 0xa000, interval,
                                    &DispatchWAssetMgrPeriodicCallbackAndStopInactiveTimerSlot);
}

// FUNCTION: IMPERIALISM 0x005e0590
void TAssetMgr::FormatVersionStringFromVersionResource(CString* out) {
  HRSRC resourceHandle = FindResourceA(nullptr, MAKEINTRESOURCEA(1), MAKEINTRESOURCEA(16));
  if (resourceHandle == nullptr) {
    return;
  }
  HGLOBAL loadedResource = LoadResource(nullptr, resourceHandle);
  if (loadedResource == nullptr) {
    return;
  }
  // Raw offsets into the loaded VS_VERSIONINFO block, matching the original's direct parse
  // (dwFileVersionMS/dwFileVersionLS of the trailing VS_FIXEDFILEINFO) rather than the
  // VerQueryValue API.
  const char* versionInfo = static_cast<const char*>(loadedResource);
  unsigned int fileVersionMS = *reinterpret_cast<const unsigned int*>(versionInfo + 0x38);
  unsigned int fileVersionLS = *reinterpret_cast<const unsigned int*>(versionInfo + 0x3c);
  short major = static_cast<short>(fileVersionMS >> 16);
  short minor = static_cast<short>(fileVersionMS);
  short build = static_cast<short>(fileVersionLS >> 16);
  short revision = static_cast<short>(fileVersionLS);
  if (revision != 0) {
    out->Format("(v. %d.%d.%d.%d)", major, minor, build, revision);
  } else if (fileVersionLS != 0) {
    out->Format("(v. %d.%d.%d)", major, minor, build);
  } else {
    out->Format("(v. %d.%d)", major, minor);
  }
}
