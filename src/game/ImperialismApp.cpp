#include "game/ImperialismApp.h"
#include "game/startup_helpers.h"
#include "game/diplomacy_globals.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TAmbitApplication.h"
#include "game/TSoundPlayer.h"
#include "game/TDisplayMgr.h"
#include "game/TStrategicMapViewSystem.h"
#include "game/TAssetMgr.h"

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

  // Set registry key SSI (stored as indirect pointer).
  LPCSTR companyRegistryKey = *reinterpret_cast<LPCSTR*>(0x0063e038);
  SetRegistryKey(companyRegistryKey);

  CCommandLineInfo cmdInfo;
  ParseCommandLine(cmdInfo);

  if (cmdInfo.m_strFileName.IsEmpty() && static_cast<int>(cmdInfo.m_nShellCommand) != 5) {
    g_pModuleLibraryCacheState = new TModuleLibraryCacheTableStateB();

    if (!LoadLanguageResourcesFromIrgFiles(this, 0)) {
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
    InitializeGlobalRuntimeSystemsFromConfig(g_pGlobalUiRootController, 0);

    g_pSfxPlaybackSystem = new TSoundPlayer();
    g_pSfxPlaybackSystem->InitializeSoundSubsystemAndAllocateChannelLists(0xf);

    CWinThread* pThread = AfxGetThread();
    if (pThread != nullptr && pThread->m_pActiveWnd != nullptr) {
      SetUiRuntimeContextAndActivateMain(pThread->m_pActiveWnd, 0, g_pDisplayMgr->activeDialog);
    }

    if (!cmdInfo.m_strFileName.IsEmpty()) {
      if (pThread != nullptr && pThread->m_pActiveWnd != nullptr) {
        pThread->m_pActiveWnd->SetWindowText(cmdInfo.m_strFileName);
      }
    }

    PostMessageA(m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
    return TRUE;
  } else {
    // Registry unregister/register reset branch.
    HKEY hKeySoftware = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, KEY_ALL_ACCESS, &hKeySoftware) == 0) {
      HKEY hKeyCompany = NULL;
      LPCSTR companyName = *reinterpret_cast<LPCSTR*>(0x0063e038); // "SSI"
      if (RegOpenKeyExA(hKeySoftware, companyName, 0, KEY_ALL_ACCESS, &hKeyCompany) == 0) {
        HKEY hKeyApp = NULL;
        LPCSTR appName = *reinterpret_cast<LPCSTR*>(0x0063e03c); // "Imperialism"
        if (RegOpenKeyExA(hKeyCompany, appName, 0, KEY_ALL_ACCESS, &hKeyApp) == 0) {
          LPCSTR settingsName = *reinterpret_cast<LPCSTR*>(0x0063e040); // "Settings"
          RegDeleteKeyA(hKeyApp, settingsName);
          RegCloseKey(hKeyApp);
        }
        RegCloseKey(hKeyCompany);
      }
      RegCloseKey(hKeySoftware);
    }
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

// FUNCTION: IMPERIALISM 0x00415090
int ImperialismApp::ShowAutoResolutionDialogIfNeeded() {
  return DAT_006a1350;
}

// FUNCTION: IMPERIALISM 0x004155b0
void ImperialismApp::ApplyAutoResolutionModeAndPersist(int mode) {
  DAT_006a1350 = mode;
}
