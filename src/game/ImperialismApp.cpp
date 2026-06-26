#include "game/ImperialismApp.h"
#include "game/startup_helpers.h"
#include "game/diplomacy_globals.h"
#include "game/TSimMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TAmbitApplication.h"
#include "game/TSoundPlayer.h"
#include "game/TDisplayMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TAssetMgr.h"
#include "game/TView.h"
#include "game/CString.h"
#include "game/mfc.h"
#include "game/CMcWindow.h"
#include "game/TModalTemplateDialog.h"

extern "C" char g_szEmptyString[];
extern "C" const char s_DataDirectoryPath_006942A8[];
extern "C" const char s_IrgGlobPattern_006942FC[];
extern "C" const char s_NoLanguageFilesMessage_006942B4[];
extern "C" const char* const g_pRegistryCompanyKey_0063E038;
extern "C" const char* const g_pRegistryAppKey_0063E03C;
extern "C" const char* const g_pRegistrySettingsSection_0063E040;
extern "C" const char* const g_pRegistryAutoResKey_0063E048;
extern "C" const char* const g_pRegistryLanguageKey_0063E04C;

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

bool IsNullOrEmptyFilename(const CString& fileName) {
  LPCSTR text = fileName;
  return text == nullptr || *text == '\0';
}

const int kAutoResPromptSentinel = 0x29a;

void LoadLanguageLabelFromIrgModule(HMODULE irgModule, CString& languageLabel) {
  LPSTR buffer = languageLabel.GetBuffer(0x20);
  LoadStringA(irgModule, 0x1e36, buffer, 0x20);
  languageLabel.ReleaseBuffer();
}

} // namespace

// The global MFC application object (DAT_006a1210). Its CRT static-init bootstrap is
// 0x00412d40 (ctor) / 0x00412d70 (dtor).
ImperialismApp theApp;

// Declarations of MFC document/view runtime classes referenced by InitInstance.
class CAmbitDocument : public CDocument {
public:
  static CRuntimeClass classRuntimeClass;
};
class CIncludeView : public CView {
public:
  static CRuntimeClass classRuntimeClass;
};

// GLOBAL: IMPERIALISM 0x00694150
extern "C" LPCSTR g_apFontFiles[] = {"data\\WeBeBd__.ttf", "data\\Antqua.ttf", "data\\Antqua.ttf",
                                     "data\\AntquaB.ttf", nullptr};

// GLOBAL: IMPERIALISM 0x0063e7f8
CRuntimeClass CAmbitDocument::classRuntimeClass = {
    "CAmbitDocument", sizeof(CAmbitDocument), 0xffff, nullptr, nullptr, nullptr};

// GLOBAL: IMPERIALISM 0x006481c8
CRuntimeClass CIncludeView::classRuntimeClass = {
    "CIncludeView", sizeof(CIncludeView), 0xffff, nullptr, nullptr, nullptr};

// GLOBAL: IMPERIALISM 0x00648628
extern "C" CRuntimeClass TMacViewMgr_RuntimeClass = {
    "TMacViewMgr", sizeof(TMacViewMgr), 0xffff, nullptr, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x00412ac0
ImperialismApp::ImperialismApp()
    : CWinApp(), field_C0(0), field_C4(), field_C8(0), field_CC(), field_D0(), field_D4(),
      field_D8(), field_DC(), field_E0(), field_E4(0) {}

// FUNCTION: IMPERIALISM 0x00412dc0
BOOL ImperialismApp::InitInstance() {
  DAT_006a1354 = SetGlobalCallback6A7FACAndReturnPrevious(reinterpret_cast<void*>(0x004025f9));

  SetRegistryKey(g_pRegistryCompanyKey_0063E038);

  CCommandLineInfo cmdInfo;
  ParseCommandLine(cmdInfo);

  if (IsNullOrEmptyFilename(cmdInfo.m_strFileName) &&
      static_cast<int>(cmdInfo.m_nShellCommand) != 5) {
    g_pModuleLibraryCacheState = new TModuleLibraryCacheTableStateB();

    if (!LoadLanguageResourcesFromIrgFiles()) {
      return FALSE;
    }

    if (!g_pModuleLibraryCacheState->LoadPrimaryDataLibraryWithErrorDialog(field_D8)) {
      return FALSE;
    }

    DAT_006a1350 = ShowAutoResolutionDialogIfNeeded();
    ApplyAutoResolutionModeAndPersist(DAT_006a1350);

    if (!g_pModuleLibraryCacheState->LoadModuleLibrarySlotWithErrorDialog(field_D0, 0)) {
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

    SetGlobalDword6A2018(cmdInfo.m_nShellCommand);

    CSingleDocTemplate* pDocTemplate =
        new CSingleDocTemplate(0x80, &CAmbitDocument::classRuntimeClass, &TMacViewMgr_RuntimeClass,
                               &CIncludeView::classRuntimeClass);
    AddDocTemplate(pDocTemplate);

    if (!WarnLowDiskSpaceAndConfirmContinue()) {
      return FALSE;
    }

    if (!ProcessShellCommand(cmdInfo)) {
      return FALSE;
    }

    DAT_006a1348 = this;

    g_pGlobalUiRootController = new TAmbitApplication();
    InitializeGlobalRuntimeSystemsFromConfig(
        static_cast<TAmbitApplication*>(g_pGlobalUiRootController));

    g_pSfxPlaybackSystem = new TSoundPlayer();
    g_pSfxPlaybackSystem->InitializeSoundSubsystemAndAllocateChannelLists(0xf);

    TView* mainViewHost =
        reinterpret_cast<TView*>(GetMainViewHostFromActiveThread());
    SetUiRuntimeContextAndActivateMain(mainViewHost, g_pDisplayMgr->activeDialog);

    if (CompareAnsiStringsWithMbcsAwareness(
            const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(
                static_cast<LPCSTR>(cmdInfo.m_strFileName))),
            reinterpret_cast<unsigned char*>(g_szEmptyString)) != 0) {
      void* uiWindow = GetMainViewHostFromActiveThread();
      if (uiWindow != nullptr) {
        static_cast<CMcWindow*>(uiWindow)->SetWindowTextOrDelegateToOwner(
            static_cast<LPCSTR>(cmdInfo.m_strFileName));
      }
    }

    PostMessageA(m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
    return TRUE;
  }

  HKEY hKeySoftware = NULL;
  if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, KEY_ALL_ACCESS, &hKeySoftware) == 0) {
    HKEY hKeyCompany = NULL;
    if (RegOpenKeyExA(hKeySoftware, g_pRegistryCompanyKey_0063E038, 0, KEY_ALL_ACCESS,
                      &hKeyCompany) == 0) {
      HKEY hKeyApp = NULL;
      if (RegOpenKeyExA(hKeyCompany, g_pRegistryAppKey_0063E03C, 0, KEY_ALL_ACCESS,
                        &hKeyApp) == 0) {
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
  if (field_C8) {
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

// FUNCTION: IMPERIALISM 0x004138b0
void __fastcall PostCommand100ToMainWindow(CWinApp* app) {
  if (app != nullptr && app->m_pMainWnd != nullptr) {
    PostMessageA(app->m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00413950
void ImperialismApp::HandleStartupCommand100() {
  int waitCursorAnchor;
  BeginWaitCursor();
  field_C0 = reinterpret_cast<int>(reinterpret_cast<void*>(&waitCursorAnchor));
  if (g_pLocalizationTable != nullptr) {
    g_pLocalizationTable->AdvanceGlobalTurnStateMachine();
  }
  field_C0 = 0;
  EndWaitCursor();
}

// FUNCTION: IMPERIALISM 0x004139f0
undefined4 WrapperFor_GetOrCreateMfcModuleThreadState_At004139f0() {
  if (DAT_006a1348 != nullptr && DAT_006a1348->field_C0 != 0) {
    DAT_006a1348->RestoreWaitCursor();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004149a0
BOOL ImperialismApp::LoadLanguageResourcesFromIrgFiles() {
  CString savedLanguage;
  savedLanguage = GetProfileString(SettingsSection(), LanguageValueName(), "");

  CCommandLineInfo cmdInfo;
  ParseCommandLine(cmdInfo);

  CString dataDir(s_DataDirectoryPath_006942A8);
  CString searchPattern = dataDir + s_IrgGlobPattern_006942FC;

  WIN32_FIND_DATAA findData;
  HANDLE findHandle = FindFirstFileA(searchPattern, &findData);
  if (findHandle == INVALID_HANDLE_VALUE) {
    AfxMessageBox(s_NoLanguageFilesMessage_006942B4, MB_OK, 0);
    return FALSE;
  }

  {
    CString irgPath = dataDir + findData.cFileName;
    HMODULE irgModule = LoadLibraryA(irgPath);
    CString firstLanguageLabel;
    if (irgModule != nullptr) {
      LoadLanguageLabelFromIrgModule(irgModule, firstLanguageLabel);
      FreeLibrary(irgModule);
    }
    savedLanguage = firstLanguageLabel;
  }
  FindClose(findHandle);

  findHandle = FindFirstFileA(searchPattern, &findData);
  while (findHandle != INVALID_HANDLE_VALUE) {
    CString irgPath = dataDir + findData.cFileName;
    HMODULE irgModule = LoadLibraryA(irgPath);
    if (irgModule != nullptr) {
      CString languageLabel;
      LoadLanguageLabelFromIrgModule(irgModule, languageLabel);
      if (CompareAnsiStringsWithMbcsAwareness(
              const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(
                  static_cast<LPCSTR>(savedLanguage))),
              const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(
                  static_cast<LPCSTR>(languageLabel)))) == 0) {
        WriteProfileString(SettingsSection(), LanguageValueName(), savedLanguage);

        LoadStringA(irgModule, 0x1e36, field_CC.GetBuffer(0x20), 0x20);
        field_CC.ReleaseBuffer();
        LoadStringA(irgModule, 0x2c6, field_D0.GetBuffer(0x20), 0x20);
        field_D0.ReleaseBuffer();
        LoadStringA(irgModule, 0x840, field_D4.GetBuffer(0x20), 0x20);
        field_D4.ReleaseBuffer();
        LoadStringA(irgModule, 0x297, field_D8.GetBuffer(0x20), 0x20);
        field_D8.ReleaseBuffer();
        LoadStringA(irgModule, 0x80, field_DC.GetBuffer(0x20), 0x20);
        field_DC.ReleaseBuffer();
        LoadStringA(irgModule, 0x323, field_E0.GetBuffer(0x20), 0x20);
        field_E0.ReleaseBuffer();

        const unsigned char* langBytes =
            reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(field_E0));
        field_E4 = (static_cast<unsigned int>(langBytes[2]) * 0x100U +
                    static_cast<unsigned int>(langBytes[1])) *
                       0x100U +
                   static_cast<unsigned int>(langBytes[0]);
      }
      FreeLibrary(irgModule);
    }

    if (FindNextFileA(findHandle, &findData) == 0) {
      FindClose(findHandle);
      break;
    }
  }

  return TRUE;
}

// FUNCTION: IMPERIALISM 0x00415090
int ImperialismApp::ShowAutoResolutionDialogIfNeeded() {
  int autoResMode = GetProfileInt(SettingsSection(), AutoResValueName(), kAutoResPromptSentinel);

  CCommandLineInfo cmdInfo;
  ParseCommandLine(cmdInfo);

  if (cmdInfo.m_bRunAutomated) {
    autoResMode = 0;
  }
  if (cmdInfo.m_bRunEmbedded) {
    autoResMode = 1;
  }

  if (cmdInfo.m_bShowSplash || autoResMode == kAutoResPromptSentinel) {
    HRSRC dialogResource =
        FindResourceA(AfxGetInstanceHandle(), MAKEINTRESOURCEA(0xfb), RT_DIALOG);
    if (dialogResource != nullptr) {
      TAutoResolutionDialog dialog(nullptr);
      if (dialog.PrepareAndCreateModalFromTemplate()) {
        dialog.UpdateData(FALSE);
        autoResMode = dialog.FinalizeModalDialogAndRestoreOwnerFocus();
      }
    } else if (autoResMode == kAutoResPromptSentinel) {
      autoResMode = 0;
    }
  }

  WriteProfileInt(SettingsSection(), AutoResValueName(), autoResMode);
  return autoResMode;
}

// FUNCTION: IMPERIALISM 0x004155b0
void ImperialismApp::ApplyAutoResolutionModeAndPersist(int mode) {
  if (field_C8 == mode) {
    return;
  }

  field_C8 = mode;
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
      field_C8 = 0;
    }
  }

  if (field_C8 == mode) {
    WriteProfileInt(SettingsSection(), AutoResValueName(), field_C8);
  }
}

// FUNCTION: IMPERIALISM 0x00484fb0
undefined4 WrapperFor_thunk_HandleStartupCommand100_At00484fb0() {
  DispatchStartupCommand100ToAppSingleton();
  return 0;
}

// FUNCTION: IMPERIALISM 0x00484fd0
void DispatchStartupCommand100ToAppSingleton() {
  if (DAT_006a1348 != nullptr) {
    DAT_006a1348->HandleStartupCommand100();
  }
}
