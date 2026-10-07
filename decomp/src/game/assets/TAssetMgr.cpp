#include "game/TScopedWaitCursor.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TWindow.h"

#include "game/app/CAmbitDocument.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TResourceMgr.h"
#include "game/assets/TMovieView.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/assets_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

#include <io.h>

IMPLEMENT_DYNCREATE(TAssetMgr, TObject)

// FUNCTION: IMPERIALISM 0x005df280
TAssetMgr::TAssetMgr() : TObject(), sharedTextSlots() {}

// FUNCTION: IMPERIALISM 0x005df330
TAssetMgr::~TAssetMgr() {}

// FUNCTION: IMPERIALISM 0x005df3a0
void TAssetMgr::ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag) {
  (void)languageTag;
  EnsurePictWvDataGobLoadedBySlot(0);
}

// FUNCTION: IMPERIALISM 0x005df3c0
TWindow* TAssetMgr::ResolveTurnEventDialogNodeByMessageContext(TurnEventId messageContext) {
  return static_cast<TWindow*>(
      g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(messageContext, 0));
}

// FUNCTION: IMPERIALISM 0x005df3f0
void TAssetMgr::OpenFilesFor(short fileSet) {
  (void)fileSet;
}

// FUNCTION: IMPERIALISM 0x005df410
void TAssetMgr::CloseFilesFor(short fileSet) {
  (void)fileSet;
}

int g_resourceStreamOpenSuppressAssert; // 0x6a5d20

// FUNCTION: IMPERIALISM 0x005df430
CFile* TAssetMgr::LoadTableResourceStreamByName(CString name) {
  HMODULE hModule = LoadLibraryA(g_pImperialismApp->assetLibraryName);
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
void TAssetMgr::PlayMovieClipAndDispatchTurnStateFollowup(const CString& movieName,
                                                          TMovieView* movieView, int unused) {
  (void)unused;
  CString moviePath = CString("Movies/") + movieName;
  moviePath = moviePath + ".avi";

  CString prefixedPath =
      CString(g_pImperialismApp->DetectImperialismInstallDriveAndSetPathPrefix()) + moviePath;

  g_pViewMgr->activeMovieView = movieView;
  if (!movieView->OpenMoviePathAndDetachOnSuccess(static_cast<LPCTSTR>(prefixedPath))) {
    if (!movieView->OpenMoviePathAndDetachOnSuccess(static_cast<LPCTSTR>(moviePath))) {
      g_pViewMgr->HandleTurnStateExitAndPostFollowupEventCode(0);
      return;
    }
  }

  g_pSfxPlaybackSystem->ClearDirectSoundInitPendingAndResetState();
  g_pViewMgr->HandleTurnStateExitAndPostFollowupEventCode(2);
  movieView->PlayMovieIfActive();
}

// FUNCTION: IMPERIALISM 0x005dfd70
void TAssetMgr::GetScenarioFileName(int scenarioIndex, int mode, CString* outPath) {
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
  *out = CString(s_Data_scores_dat);
}

extern "C" const char s_MissingFilePrefix[];
extern "C" const char s_MissingFileSuffix[];

// FUNCTION: IMPERIALISM 0x005dff20
void TAssetMgr::EnsurePictWvDataGobLoadedBySlot(int languageTag) {
  CString path;
  path.Format(s_PictWvGobPathFormat, languageTag);

  if (g_pResourceMgr->LoadModuleLibrarySlotWithErrorDialog(path, 2)) {
    return;
  }

  AfxMessageBox(static_cast<LPCTSTR>(s_MissingFilePrefix + path + s_MissingFileSuffix), MB_OK, 0);
}

namespace {} // namespace

// FUNCTION: IMPERIALISM 0x005e0030
unsigned char TAssetMgr::SaveMainDocumentToPathAndMarkSaved(const CString& savePath) {
  CString path(savePath);
  CFrameWnd* frame = static_cast<CFrameWnd*>(AfxGetMainWnd());
  frame->AssertValid();
  CAmbitDocument* document = static_cast<CAmbitDocument*>(frame->GetActiveView()->GetDocument());
  TScopedWaitCursor waitCursor;
  document->SetPathName(path, FALSE);
  unsigned char saved = (unsigned char)document->DoSave(document->GetPathName(), TRUE);
  document->SetPathName(g_szSavedDocumentMarker, FALSE);
  return saved;
}

// FUNCTION: IMPERIALISM 0x005e0150
bool TAssetMgr::OpenMainDocumentFromPathAndMarkLoaded(const CString& loadPath) {
  CDocument* document = g_pImperialismApp->OpenDocumentFile(loadPath);
  if (document == 0) {
    return false;
  }
  document->SetPathName(g_szLoadedDocumentMarker, FALSE);
  return true;
}

// FUNCTION: IMPERIALISM 0x005e0260
void TAssetMgr::SetPreferenceString(CString* value, const char* key) {
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
bool TAssetMgr::HasPendingClientSaveFile() {
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

namespace {
struct LoadedVersionResourceBlock {
  unsigned char prefix00[0x30];
  VS_FIXEDFILEINFO fixedInfo;
};
} // namespace

// FUNCTION: IMPERIALISM 0x005e0590
CString TAssetMgr::FormatVersionStringFromVersionResource() {
  CString versionText;
  HRSRC resourceHandle = FindResourceA(nullptr, MAKEINTRESOURCEA(1), MAKEINTRESOURCEA(16));
  if (resourceHandle != nullptr) {
    HGLOBAL loadedResource = LoadResource(nullptr, resourceHandle);
    if (loadedResource != nullptr) {
      const LoadedVersionResourceBlock* versionInfo =
          static_cast<const LoadedVersionResourceBlock*>(static_cast<const void*>(loadedResource));
      unsigned int fileVersionMS = versionInfo->fixedInfo.dwFileVersionMS;
      unsigned int fileVersionLS = versionInfo->fixedInfo.dwFileVersionLS;
      short major = static_cast<short>(fileVersionMS >> 16);
      short minor = static_cast<short>(fileVersionMS);
      short build = static_cast<short>(fileVersionLS >> 16);
      short revision = static_cast<short>(fileVersionLS);
      if (revision != 0) {
        versionText.Format("(v. %d.%d.%d.%d)", major, minor, build, revision);
      } else if (fileVersionLS != 0) {
        versionText.Format("(v. %d.%d.%d)", major, minor, build);
      } else {
        versionText.Format("(v. %d.%d)", major, minor);
      }
    }
  }
  return versionText;
}
