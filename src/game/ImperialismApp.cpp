#include "game/ImperialismApp.h"
#include "game/ImperialismCommandLineInfo.h"
#include "game/startup_helpers.h"
#include "game/app_init_globals.h"
#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TAmbitApplication.h"
#include "game/TSoundPlayer.h"
#include "game/TDisplayMgr.h"
#include "game/CAmbitDocument.h"
#include "game/CIncludeView.h"
#include "game/CMainFrame.h"
#include "game/TMacViewMgr.h"
#include "game/TAssetMgr.h"
#include "game/TView.h"
#include "game/CString.h"
#include "game/mfc.h"
#include "game/TAutoResolutionDialog.h"

#include <io.h>  // CRT _findfirst/_findnext/_findclose (LIBRARY 0x5e7ae0/0x5e7c10/0x5e7d30)
#include <new.h> // CRT _set_new_handler (LIBRARY 0x5e7a80)
#include <string.h>

namespace {

LPCSTR SettingsSection() {
  return g_pRegistrySettingsSection_0063E040;
}

LPCSTR AutoResValueName() {
  return g_pRegistryAutoResKey_0063E048;
}

LPCSTR LanguageValueName() {
  return g_pRegistryLanguageKey_0063E04C;
}

const int kAutoResPromptSentinel = 0x29a;

// Inlined at every _findfirst/_findnext site in LoadLanguageResourcesFromIrgFiles.
__inline void CloseCrtFindHandleIfOpen(long& findHandle) {
  if (findHandle != -1) {
    _findclose(findHandle);
    findHandle = -1;
  }
}

} // namespace

// FUNCTION: IMPERIALISM 0x005df7a0
BOOL QueryVolumeInformationForDriveIndex(char driveIndex, CString* volumeName, LPDWORD serial) {
  char rootPath[4];
  rootPath[0] = static_cast<char>('A' + driveIndex);
  rootPath[1] = ':';
  rootPath[2] = '\\';
  rootPath[3] = '\0';

  char volumeBuffer[0x1f];
  volumeBuffer[0] = '\0';
  BOOL result = GetVolumeInformationA(rootPath, volumeBuffer, 0x1e, serial, 0, 0, 0, 0);
  *volumeName = CString(volumeBuffer);
  return result;
}

// FUNCTION: IMPERIALISM 0x005df890
bool QueryDriveTypeByDriveIndex(char driveIndex) {
  char rootPath[4];
  rootPath[0] = static_cast<char>('A' + driveIndex);
  rootPath[1] = ':';
  rootPath[2] = '/';
  rootPath[3] = '\0';
  return GetDriveTypeA(rootPath) == DRIVE_CDROM;
}

// The global MFC application object (DAT_006a1210). Its CRT static-init bootstrap is
// 0x00412d40 (ctor) / 0x00412d70 (dtor).
ImperialismApp theApp;

// FUNCTION: IMPERIALISM 0x00412ac0
ImperialismApp::ImperialismApp()
    : CWinApp(), waitCursorAnchorC0(0), field_C4(), appliedAutoResModeC8(0), languageLabelCC(),
      localizedPictGobNameD0(), field_D4(), primaryDataLibNameD8(), field_DC(),
      languageCodeStringE0(), languagePackIdE4(0) {}

// Out-of-memory handler installed by InitInstance through the CRT _set_new_handler;
// __callnewh (0x5e7ac0) invokes it when operator new fails. Returns 0 (no retry).
// FUNCTION: IMPERIALISM 0x00412d90
int __cdecl ShowOutOfMemoryErrorNewHandler(size_t allocationSize) {
  (void)allocationSize;
  MessageBoxA(NULL, s_OutOfMemoryText_006941F0, s_ErrorCaption_00694204, MB_ICONEXCLAMATION);
  return 0;
}

// FUNCTION: IMPERIALISM 0x00412dc0
BOOL ImperialismApp::InitInstance() {
  g_pfnPreviousNewHandler = _set_new_handler(ShowOutOfMemoryErrorNewHandler);

  SetRegistryKey(g_pRegistryCompanyKey_0063E038);

  CString languageOverride;
  ImperialismCommandLineInfo cmdInfo(&languageOverride);
  ParseCommandLine(cmdInfo);

  if (!cmdInfo.m_bClearRegistrySettings34 &&
      cmdInfo.m_nShellCommand != CCommandLineInfo::AppUnregister) {
    g_pModuleLibraryCacheState = new TModuleLibraryCacheTableStateB();

    if (!LoadLanguageResourcesFromIrgFiles()) {
      return FALSE;
    }

    if (!g_pModuleLibraryCacheState->LoadPrimaryDataLibraryWithErrorDialog(
            primaryDataLibNameD8)) {
      return FALSE;
    }

    DAT_006a1350 = ShowAutoResolutionDialogIfNeeded();
    ApplyAutoResolutionModeAndPersist(DAT_006a1350);

    if (!g_pModuleLibraryCacheState->LoadModuleLibrarySlotWithErrorDialog(localizedPictGobNameD0,
                                                                          0)) {
      return FALSE;
    }
    if (!g_pModuleLibraryCacheState->LoadModuleLibrarySlotWithErrorDialog("Data/PictPaid.gob", 1)) {
      return FALSE;
    }
    if (!g_pModuleLibraryCacheState->LoadModuleLibrarySlotWithErrorDialog("Data/PictUniv.gob", 3)) {
      return FALSE;
    }

    LPCSTR* ppFontFiles = g_apFontFiles;
    if (ppFontFiles != nullptr && *ppFontFiles != nullptr) {
      while (*ppFontFiles != nullptr) {
        AddFontResourceA(*ppFontFiles);
        ppFontFiles++;
      }
    }
    PostMessageA(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

    SetCachedShowSplashFlag(cmdInfo.m_bShowSplash);

    CSingleDocTemplate* pDocTemplate =
        new CSingleDocTemplate(0x80, RUNTIME_CLASS(CAmbitDocument), RUNTIME_CLASS(CMainFrame),
                               RUNTIME_CLASS(CIncludeView));
    AddDocTemplate(pDocTemplate);

    if (!WarnLowDiskSpaceAndConfirmContinue()) {
      return FALSE;
    }

    if (!ProcessShellCommand(cmdInfo)) {
      return FALSE;
    }

    g_pImperialismApp = &theApp;

    g_pGlobalUiRootController = new TAmbitApplication();
    static_cast<TAmbitApplication*>(g_pGlobalUiRootController)->InitializeGlobalRuntimeSystems();

    g_pSfxPlaybackSystem = new TSoundPlayer();
    g_pSfxPlaybackSystem->InitializeSoundSubsystemAndAllocateChannelLists(0xf);

    CIncludeView* mainView = GetMainViewHostFromActiveThread();
    mainView->SetUiRuntimeContextAndActivateMain(g_pDisplayMgr->activeDialog);

    if (CompareAnsiStringsWithMbcsAwareness(
            const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(
                static_cast<LPCSTR>(cmdInfo.m_strMainWindowTitle38))),
            reinterpret_cast<unsigned char*>(g_szEmptyString)) != 0) {
      CIncludeView* uiWindow = GetMainViewHostFromActiveThread();
      if (uiWindow != nullptr) {
        uiWindow->SetWindowText(static_cast<LPCSTR>(cmdInfo.m_strMainWindowTitle38));
      }
    }

    PostMessageA(g_pImperialismApp->m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
    return TRUE;
  }

  HKEY hKeySoftware = NULL;
  if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, KEY_ALL_ACCESS, &hKeySoftware) == 0) {
    HKEY hKeyCompany = NULL;
    if (RegOpenKeyExA(hKeySoftware, g_pRegistryCompanyKey_0063E038, 0, KEY_ALL_ACCESS,
                      &hKeyCompany) == 0) {
      HKEY hKeyApp = NULL;
      if (RegOpenKeyExA(hKeyCompany, g_pRegistryAppKey_0063E03C, 0, KEY_ALL_ACCESS, &hKeyApp) ==
          0) {
        RegDeleteKeyA(hKeyApp, g_pRegistrySettingsSection_0063E040);
        RegCloseKey(hKeyApp);
      }
      RegCloseKey(hKeyCompany);
    }
    RegCloseKey(hKeySoftware);
  }

  return FALSE;
}

// FUNCTION: IMPERIALISM 0x00413780
int ImperialismApp::ExitInstance() {
  if (appliedAutoResModeC8) {
    ChangeDisplaySettingsA(nullptr, 0);
  }

  if (g_pDisplayMgr != nullptr) {
    g_pDisplayMgr->Free();
    g_pDisplayMgr = nullptr;
  }
  if (g_pModuleLibraryCacheState != nullptr) {
    delete g_pModuleLibraryCacheState;
    g_pModuleLibraryCacheState = nullptr;
  }
  if (g_pStrategicMapViewSystem != nullptr) {
    g_pStrategicMapViewSystem->Free();
    g_pStrategicMapViewSystem = nullptr;
  }
  if (g_pUiViewManager != nullptr) {
    g_pUiViewManager->Free();
    g_pUiViewManager = nullptr;
  }
  if (g_pSfxPlaybackSystem != nullptr) {
    g_pSfxPlaybackSystem->Free();
    g_pSfxPlaybackSystem = nullptr;
  }
  if (g_pGlobalUiRootController != nullptr) {
    g_pGlobalUiRootController->Free();
    g_pGlobalUiRootController = nullptr;
  }
  ReleaseGlobalClipRegionHandleListAndReset_006a1c98();

  LPCSTR* ppFontFiles = g_apFontFiles;
  if (ppFontFiles != nullptr && *ppFontFiles != nullptr) {
    while (*ppFontFiles != nullptr) {
      RemoveFontResourceA(*ppFontFiles);
      ppFontFiles++;
    }
  }
  PostMessageA(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

  return CWinApp::ExitInstance();
}

// Post the startup WM_COMMAND(100) to the main frame. The original dereferences
// m_pMainWnd unguarded.
// FUNCTION: IMPERIALISM 0x004138b0
void ImperialismApp::PostStartupCommand100() {
  PostMessageA(m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
}

// FUNCTION: IMPERIALISM 0x00414870
LPCTSTR ImperialismApp::DetectImperialismInstallDriveAndSetPathPrefix() {
  if (field_C4.IsEmpty()) {
    char driveIndex = 2;
    while (driveIndex < 0x1a) {
      if (QueryDriveTypeByDriveIndex(driveIndex)) {
        CString volumeName;
        DWORD serial = 0;
        if (QueryVolumeInformationForDriveIndex(driveIndex, &volumeName, &serial) &&
            strcmp(static_cast<LPCTSTR>(volumeName), g_pRegistryProfileAppName_0063E050) == 0) {
          char prefix[4];
          prefix[0] = static_cast<char>('A' + driveIndex);
          prefix[1] = ':';
          prefix[2] = '/';
          prefix[3] = '\0';
          field_C4 = CString(prefix);
          break;
        }
      }
      driveIndex = static_cast<char>(driveIndex + 1);
    }
  }
  return static_cast<LPCTSTR>(field_C4);
}

// FUNCTION: IMPERIALISM 0x00413950
void ImperialismApp::HandleStartupCommand100() {
  int waitCursorAnchor;
  BeginWaitCursor();
  waitCursorAnchorC0 = &waitCursorAnchor;
  if (g_pSimMgr != nullptr) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
  }
  waitCursorAnchorC0 = 0;
  EndWaitCursor();
}

// FUNCTION: IMPERIALISM 0x004139f0
void ImperialismApp::RestoreWaitCursorIfStartupBusy() {
  if (waitCursorAnchorC0 != 0) {
    AfxGetApp()->RestoreWaitCursor();
  }
}

// Post WM_CLOSE to the main thread's window. Faithful to the original: when
// AfxGetThread() returns null the main-window pointer stays null and the m_hWnd
// read dereferences it unguarded (latent original bug, kept as-is).
// FUNCTION: IMPERIALISM 0x004146d0
void PostWmCloseToMainThreadWindow() {
  if (AfxGetThread() != 0) {
    PostMessageA(AfxGetThread()->GetMainWnd()->m_hWnd, WM_CLOSE, 0, 0);
    return;
  }
  CWnd* nullMainWindow = 0;
  PostMessageA(nullMainWindow->m_hWnd, WM_CLOSE, 0, 0);
}

// FUNCTION: IMPERIALISM 0x004149a0
BOOL ImperialismApp::LoadLanguageResourcesFromIrgFiles() {
  CString savedLanguage;
  savedLanguage = GetProfileString(SettingsSection(), LanguageValueName(), 0);

  ImperialismCommandLineInfo cmdInfo(&savedLanguage);
  ParseCommandLine(cmdInfo);

  long findHandle = -1;
  BOOL haveAnyIrgFile = FALSE;
  CString dataDir(s_DataDirectoryPath_006942A8);
  _finddata_t findData;
  {
    CString searchPattern = dataDir + s_IrgGlobPattern_006942FC;
    CloseCrtFindHandleIfOpen(findHandle);
    findHandle = _findfirst(searchPattern, &findData);
  }

  if (findHandle != -1) {
    // The first .irg found seeds the language when none is saved yet; the original
    // loads its label unconditionally (and without a LoadLibraryA null check).
    CString irgPath = dataDir + findData.name;
    HMODULE irgModule = LoadLibraryA(irgPath);
    CString languageLabel;
    LoadStringA(irgModule, 0x1e36, languageLabel.GetBufferSetLength(0x21), 0x20);
    languageLabel.ReleaseBuffer(-1);
    haveAnyIrgFile = TRUE;
    FreeLibrary(irgModule);
    savedLanguage = languageLabel;
  }

  if (!haveAnyIrgFile) {
    AfxMessageBox(s_NoLanguageFilesMessage_006942B4, 0, 0);
    CloseCrtFindHandleIfOpen(findHandle);
    return FALSE;
  }

  // Labels are compared upper-cased (case-insensitive language match).
  savedLanguage.MakeUpper();
  {
    CString searchPattern = dataDir + s_IrgGlobPattern_006942FC;
    CloseCrtFindHandleIfOpen(findHandle);
    findHandle = _findfirst(searchPattern, &findData);
  }

  while (findHandle != -1) {
    CString irgPath = dataDir + findData.name;
    HMODULE irgModule = LoadLibraryA(irgPath);
    CString languageLabel;
    LoadStringA(irgModule, 0x1e36, languageLabel.GetBufferSetLength(0x21), 0x20);
    languageLabel.ReleaseBuffer(-1);
    languageLabel.MakeUpper();

    if (CompareAnsiStringsWithMbcsAwareness(
            const_cast<unsigned char*>(
                reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(savedLanguage))),
            const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(
                static_cast<LPCSTR>(languageLabel)))) == 0) {
      WriteProfileString(SettingsSection(), LanguageValueName(), savedLanguage);

      LoadStringA(irgModule, 0x1e36, languageLabelCC.GetBufferSetLength(0x21), 0x20);
      languageLabelCC.ReleaseBuffer(-1);
      LoadStringA(irgModule, 0x2c6, localizedPictGobNameD0.GetBufferSetLength(0x21), 0x20);
      localizedPictGobNameD0.ReleaseBuffer(-1);
      LoadStringA(irgModule, 0x840, field_D4.GetBufferSetLength(0x21), 0x20);
      field_D4.ReleaseBuffer(-1);
      LoadStringA(irgModule, 0x297, primaryDataLibNameD8.GetBufferSetLength(0x21), 0x20);
      primaryDataLibNameD8.ReleaseBuffer(-1);
      LoadStringA(irgModule, 0x80, field_DC.GetBufferSetLength(0x21), 0x20);
      field_DC.ReleaseBuffer(-1);
      LoadStringA(irgModule, 0x323, languageCodeStringE0.GetBufferSetLength(0x21), 0x20);
      languageCodeStringE0.ReleaseBuffer(-1);

      const unsigned char* langBytes =
          reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(languageCodeStringE0));
      languagePackIdE4 = (static_cast<unsigned int>(langBytes[2]) * 0x100U +
                          static_cast<unsigned int>(langBytes[1])) *
                             0x100U +
                         static_cast<unsigned int>(langBytes[0]);
    }
    FreeLibrary(irgModule);

    if (_findnext(findHandle, &findData) == -1) {
      CloseCrtFindHandleIfOpen(findHandle);
    }
  }

  // "L!" on the command line: scan/report languages, then abort startup.
  BOOL keepStarting = cmdInfo.m_bQuitAfterLanguageScan2c == 0;
  CloseCrtFindHandleIfOpen(findHandle);
  return keepStarting;
}

// FUNCTION: IMPERIALISM 0x00415090
int ImperialismApp::ShowAutoResolutionDialogIfNeeded() {
  int autoResMode = GetProfileInt(SettingsSection(), AutoResValueName(), kAutoResPromptSentinel);

  CString languageOverride;
  ImperialismCommandLineInfo cmdInfo(&languageOverride);
  ParseCommandLine(cmdInfo);

  if (cmdInfo.m_bForceAutoResOff40) {
    autoResMode = 0;
  }
  if (cmdInfo.m_bForceAutoResOn3c) {
    autoResMode = 1;
  }

  if (cmdInfo.m_bShowSetupDialog30 || autoResMode == kAutoResPromptSentinel) {
    TAutoResolutionDialog dialog(nullptr);
    dialog.PrepareAndCreateModalFromTemplate();
    dialog.autoResolutionCheckState = autoResMode;
    dialog.UpdateData(FALSE);
    dialog.FinalizeModalDialogAndRestoreOwnerFocus();
    autoResMode = dialog.autoResolutionCheckState;
  }

  WriteProfileInt(SettingsSection(), AutoResValueName(), autoResMode);
  return autoResMode;
}

// FUNCTION: IMPERIALISM 0x004155b0
void ImperialismApp::ApplyAutoResolutionModeAndPersist(int mode) {
  if (appliedAutoResModeC8 == mode) {
    return;
  }

  appliedAutoResModeC8 = mode;
  if (mode == 0) {
    ChangeDisplaySettingsA(nullptr, 0);
  } else {
    DEVMODEA devMode;
    memset(&devMode, 0, sizeof(devMode));
    LONG changeResult = -1;
    DWORD modeIndex = 0;
    devMode.dmBitsPerPel = 8;
    devMode.dmPelsWidth = 0x280;
    devMode.dmPelsHeight = 0x1e0;
    devMode.dmFields = 0x180000;

    if (EnumDisplaySettingsA(nullptr, modeIndex, &devMode)) {
      do {
        if (devMode.dmPelsWidth == 0x280 && devMode.dmBitsPerPel > 7 &&
            devMode.dmPelsHeight == 0x1e0) {
          devMode.dmFields = 0x180000;
          changeResult = ChangeDisplaySettingsA(&devMode, 0);
          break;
        }
        ++modeIndex;
      } while (EnumDisplaySettingsA(nullptr, modeIndex, &devMode));
    }

    if (changeResult != 0) {
      appliedAutoResModeC8 = 0;
    }
  }

  if (appliedAutoResModeC8 == mode) {
    WriteProfileInt(SettingsSection(), AutoResValueName(), appliedAutoResModeC8);
  }
}
