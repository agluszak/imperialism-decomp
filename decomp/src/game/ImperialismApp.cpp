#include "game/menu_commands.h"
#include "game/ImperialismApp.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeTestDriver.h"
#endif
#include "game/ImperialismCommandLineInfo.h"
#include "game/app_init_globals.h"
#include "game/globals/global_types.h"
#include "game/globals/core_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/gfx/TResourceMgr.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/gfx/TBackdropWindow.h" // RefreshBackdropOnInputMessages
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/app/CAmbitDocument.h"
#include "game/ui_core/CIncludeView.h"
#include "game/ui_core/CMainFrame.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TWindow.h"
#include "game/assets/TAssetMgr.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/city/TCity.h"
#include "game/gfx/CDib.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/core/CString.h"
#include "game/mfc.h"
#include "game/gfx/TAutoResolutionDialog.h"
#include "game/app/TModalTemplateDialog.h"
#include "game/military/mapped_flavor_text.h"
#include "game/pointer_representation.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_text_label_helpers_decls.h"

#include <io.h>  // CRT _findfirst/_findnext/_findclose (LIBRARY 0x5e7ae0/0x5e7c10/0x5e7d30)
#include <new.h> // CRT _set_new_handler (LIBRARY 0x5e7a80)
#include <string.h>

namespace {

const int kAutoResPromptSentinel = 0x29a;

// Inlined at every _findfirst/_findnext site in LoadLanguageResourcesFromIrgFiles.
__inline void CloseCrtFindHandleIfOpen(long& findHandle) {
  if (findHandle != -1) {
    _findclose(findHandle);
    findHandle = -1;
  }
}

} // namespace

// FUNCTION: IMPERIALISM 0x00412640
HKEY OpenOrCreateCompanyProductRegistryKey(LPCSTR company, LPCSTR product) {
  HKEY hSoftware = nullptr;
  HKEY hCompany = nullptr;
  HKEY hProduct = nullptr;
  DWORD disposition = 0;

  if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, 0x2001f, &hSoftware) == ERROR_SUCCESS) {
    if (RegCreateKeyExA(hSoftware, company, 0, nullptr, 0, 0x2001f, nullptr, &hCompany,
                        &disposition) == ERROR_SUCCESS) {
      RegCreateKeyExA(hCompany, product, 0, nullptr, 0, 0x2001f, nullptr, &hProduct, &disposition);
    }
  }
  if (hSoftware != nullptr) {
    RegCloseKey(hSoftware);
  }
  if (hCompany != nullptr) {
    RegCloseKey(hCompany);
  }
  return hProduct;
}

// FUNCTION: IMPERIALISM 0x00412720
HKEY OpenOrCreateProfileSectionKey(LPCSTR company, LPCSTR product, LPCSTR section) {
  HKEY hSoftware = nullptr;
  HKEY hCompany = nullptr;
  HKEY hProduct = nullptr;
  HKEY hSection = nullptr;
  DWORD disposition = 0;

  if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, 0x2001f, &hSoftware) == ERROR_SUCCESS) {
    if (RegCreateKeyExA(hSoftware, company, 0, nullptr, 0, 0x2001f, nullptr, &hCompany,
                        &disposition) == ERROR_SUCCESS) {
      RegCreateKeyExA(hCompany, product, 0, nullptr, 0, 0x2001f, nullptr, &hProduct, &disposition);
    }
  }
  if (hSoftware != nullptr) {
    RegCloseKey(hSoftware);
  }
  if (hCompany != nullptr) {
    RegCloseKey(hCompany);
  }
  if (hProduct == nullptr) {
    return nullptr;
  }
  RegCreateKeyExA(hProduct, section, 0, nullptr, 0, 0x2001f, nullptr, &hSection, &disposition);
  RegCloseKey(hProduct);
  return hSection;
}

// FUNCTION: IMPERIALISM 0x00412840
CString ReadOrCreateRegistryStringValueWithFallback(LPCSTR company, LPCSTR product, LPCSTR section,
                                                    LPCSTR valueName, LPCSTR defaultValue) {
  HKEY hSoftware = nullptr;
  HKEY hCompany = nullptr;
  HKEY hProduct = nullptr;
  HKEY hSection = nullptr;
  DWORD disposition = 0;

  if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, 0x2001f, &hSoftware) == ERROR_SUCCESS &&
      RegCreateKeyExA(hSoftware, company, 0, nullptr, 0, 0x2001f, nullptr, &hCompany,
                      &disposition) == ERROR_SUCCESS) {
    RegCreateKeyExA(hCompany, product, 0, nullptr, 0, 0x2001f, nullptr, &hProduct, &disposition);
  }
  if (hSoftware != nullptr) {
    RegCloseKey(hSoftware);
  }
  if (hCompany != nullptr) {
    RegCloseKey(hCompany);
  }

  HKEY hFinal = hProduct;
  if (hProduct == nullptr) {
    hFinal = nullptr;
  } else {
    RegCreateKeyExA(hProduct, section, 0, nullptr, 0, 0x2001f, nullptr, &hSection, &disposition);
    RegCloseKey(hProduct);
    hFinal = hSection;
  }

  if (hFinal == nullptr) {
    return CString(defaultValue);
  }

  CString value;
  DWORD dataType = 0;
  DWORD dataSize = 0;
  LONG status = RegQueryValueExA(hFinal, valueName, nullptr, &dataType, nullptr, &dataSize);
  if (status == ERROR_SUCCESS) {
    LPBYTE buffer = static_cast<LPBYTE>(static_cast<void*>(value.GetBuffer(dataSize)));
    status = RegQueryValueExA(hFinal, valueName, nullptr, &dataType, buffer, &dataSize);
    value.ReleaseBuffer(-1);
  }
  RegCloseKey(hFinal);
  if (status == ERROR_SUCCESS) {
    return value;
  }
  return CString(defaultValue);
}

// FUNCTION: IMPERIALISM 0x00412a70
CIncludeView* GetMainViewHostFromActiveThread() {
  CFrameWnd* mainFrame;
  if (AfxGetThread() != nullptr) {
    mainFrame = static_cast<CFrameWnd*>(AfxGetThread()->GetMainWnd());
  } else {
    mainFrame = nullptr;
  }
  return static_cast<CIncludeView*>(mainFrame->GetActiveView());
}

#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(ImperialismApp, CWinApp)
ON_COMMAND(kCmdTestSomething, OnTestSomething)
ON_COMMAND(kCmdSwitchGreatPower, OnSwitchGreatPower)
ON_COMMAND(kCmdRunOffTurns, OnRunOffTurns)
ON_COMMAND(kCmdBequeathGoodies, OnBequeathGoodies)
ON_COMMAND(kCmdPeekAtDib, OnPeekAtDib)
ON_COMMAND(kCmdHuman, OnHuman)
ON_UPDATE_COMMAND_UI(kCmdHuman, OnUpdateHuman)
ON_COMMAND(kCmdMissionSnooper, OnMissionSnooper)
ON_COMMAND(kCmdSlowMemoryChecking, OnSlowMemoryChecking)
ON_UPDATE_COMMAND_UI(kCmdSlowMemoryChecking, OnUpdateSlowMemoryChecking)
ON_COMMAND(kCmdTraceEnabled, OnTraceEnabled)
ON_UPDATE_COMMAND_UI(kCmdTraceEnabled, OnUpdateTraceEnabled)
ON_COMMAND(kCmdPeekAtGWorld, OnPeekAtGWorld)
ON_COMMAND(ID_FILE_NEW, CWinApp::OnFileNew)
ON_COMMAND(ID_FILE_OPEN, CWinApp::OnFileOpen)
END_MESSAGE_MAP()
#endif

// FUNCTION: IMPERIALISM 0x00412ac0
ImperialismApp::ImperialismApp()
    : CWinApp(), waitCursorAnchorC0(0), field_C4(), appliedAutoResModeC8(0), languageLabelCC(),
      localizedPictGobNameD0(), field_D4(), primaryDataLibNameD8(), field_DC(),
      languageCodeString(), languagePackIdE4(0) {}

// FUNCTION: IMPERIALISM 0x00412c60
ImperialismApp::~ImperialismApp() {}

ImperialismApp theApp;

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

  if (!cmdInfo.m_bClearRegistrySettings &&
      cmdInfo.m_nShellCommand != CCommandLineInfo::AppUnregister) {
    g_pResourceMgr = new TResourceMgr();

    if (!LoadLanguageResourcesFromIrgFiles()) {
      return FALSE;
    }

    if (!g_pResourceMgr->LoadPrimaryDataLibraryWithErrorDialog(primaryDataLibNameD8)) {
      return FALSE;
    }

    g_nStartupAutoResolutionMode = ShowAutoResolutionDialogIfNeeded();
    ApplyAutoResolutionModeAndPersist(g_nStartupAutoResolutionMode);

    if (!g_pResourceMgr->LoadModuleLibrarySlotWithErrorDialog(localizedPictGobNameD0, 0)) {
      return FALSE;
    }
    if (!g_pResourceMgr->LoadModuleLibrarySlotWithErrorDialog("Data/PictPaid.gob", 1)) {
      return FALSE;
    }
    if (!g_pResourceMgr->LoadModuleLibrarySlotWithErrorDialog("Data/PictUniv.gob", 3)) {
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

    g_pAmbitApplication = new TAmbitApplication();
    g_pAmbitApplication->IAmbitApplication();

    g_pSfxPlaybackSystem = new TSoundPlayer();
    g_pSfxPlaybackSystem->ISoundPlayer(0xf);

    CIncludeView* mainView = GetMainViewHostFromActiveThread();
    mainView->SetUiRuntimeContextAndActivateMain(g_pDisplayMgr->activeDialog);

    if (cmdInfo.m_strMainWindowTitle38.Compare(g_szEmptyString) != 0) {
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
  if (g_pResourceMgr != nullptr) {
    delete g_pResourceMgr;
    g_pResourceMgr = nullptr;
  }
  if (g_pMacViewMgr != nullptr) {
    g_pMacViewMgr->Free();
    g_pMacViewMgr = nullptr;
  }
  if (g_pAssetMgr != nullptr) {
    g_pAssetMgr->Free();
    g_pAssetMgr = nullptr;
  }
  if (g_pSfxPlaybackSystem != nullptr) {
    g_pSfxPlaybackSystem->Free();
    g_pSfxPlaybackSystem = nullptr;
  }
  if (g_pAmbitApplication != nullptr) {
    g_pAmbitApplication->Free();
    g_pAmbitApplication = nullptr;
  }
  DisposeTemporaryRegionCache();

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
void ImperialismApp::PostStartupCommand100() {
  PostMessageA(m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
}

// FUNCTION: IMPERIALISM 0x00413950
void ImperialismApp::HandleStartupCommand100() {
  int waitCursorAnchor;
  AfxGetApp()->BeginWaitCursor();
  waitCursorAnchorC0 = &waitCursorAnchor;
  if (g_pSimMgr != nullptr) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
  }
  waitCursorAnchorC0 = 0;
  AfxGetApp()->EndWaitCursor();
}

// FUNCTION: IMPERIALISM 0x004139f0
void ImperialismApp::RestoreWaitCursorIfStartupBusy() {
  if (waitCursorAnchorC0 != 0) {
    AfxGetApp()->RestoreWaitCursor();
  }
}

// FUNCTION: IMPERIALISM 0x00413a20
BOOL ImperialismApp::PreTranslateMessage(MSG* pMsg) {
#ifdef IMPERIALISM_RUNTIME_TESTS
  if (RuntimeTestDriver::HandleMessage(pMsg)) {
    return TRUE;
  }
#endif
  RefreshBackdropOnInputMessages(pMsg);
  return CWinThread::PreTranslateMessage(pMsg);
}

// FUNCTION: IMPERIALISM 0x00413d00
void ImperialismApp::OnTestSomething() {
  g_pResourceMgr->NoOpRetailCacheHook();
}

// FUNCTION: IMPERIALISM 0x00413d20
void ImperialismApp::OnSwitchGreatPower() {
  TSwitchGreatPowerDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();
  dialog.slider.SetRange(0, 6, FALSE);
  dialog.slider.SetPos(g_pSimMgr->GetPlayerCountry());

  if (dialog.DoModal() == IDOK) {
    short nationSlot = static_cast<short>(dialog.slider.GetPos());
    g_pSimMgr->SetPlayerCountry(nationSlot);
    if (g_pSimMgr->mode == kGamePhaseTechnology) {
      g_apNationStates[g_pSimMgr->GetPlayerCountry()]
          ->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    }
    g_pViewMgr->DispatchTurnEvent(g_pViewMgr->currentTurnEventCode, g_pSimMgr->GetPlayerCountry());
  }
}

// FUNCTION: IMPERIALISM 0x00413f60
void ImperialismApp::OnRunOffTurns() {
  TRunOffTurnsDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();
  short savedCooldown = g_nTurnCooldownDeferCounter006A43C4;

  if (dialog.DoModal() == IDOK) {
    g_nTurnCooldownDeferCounter006A43C4 = savedCooldown;
    g_nTurnCooldownSideFlag00698B10 = static_cast<short>(g_pSimMgr->mode);
    PostMessageA(m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004140f0
void ImperialismApp::OnBequeathGoodies() {
  TBequeathGoodiesDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();
  dialog.slider.SetRange(0, 6, FALSE);
  dialog.slider.SetPos(g_pSimMgr->GetPlayerCountry());

  if (dialog.DoModal() == IDOK) {
    int nationSlot = dialog.slider.GetPos();
    TCity* city = g_apNationStates[nationSlot] != 0 ? g_apNationStates[nationSlot]->city : 0;
    for (short commodity = 0; commodity < 0x17; ++commodity) {
      city->CityStockByType(commodity) = static_cast<short>(
          city->CityStockByType(commodity) + static_cast<short>(dialog.commodityAdjustment));
      city->VerifyStocks();
    }

    short populationDelta = static_cast<short>(-static_cast<int>(dialog.populationAdjustment));
    city->productionSummary->RemovePopulation(1, populationDelta);
    city->productionSummary->RemovePopulation(2, populationDelta);
    city->productionSummary->RemovePopulation(4, populationDelta);
  }
}

// FUNCTION: IMPERIALISM 0x004143b0
void ImperialismApp::OnPeekAtDib() {
  TPeekAtDibDialog inputDialog(0);
  if (inputDialog.DoModal() != IDOK) {
    return;
  }

  int inputValue = inputDialog.editValue5c;
  CDib* dib;
  if (inputValue < 20000) {
    dib = g_pResourceMgr->LoadBmpResourceByIdCached(static_cast<unsigned short>(inputValue));
  } else {
    dib = static_cast<CDib*>(PointerFromAddressLong32(inputValue));
  }

  if (dib != 0 && AfxIsValidAddress(dib, sizeof(CDib), FALSE) &&
      dib->IsKindOf(RUNTIME_CLASS(CDib))) {
    TDibPreviewDialog previewDialog(0);
    if (inputDialog.checkFlag60 != 0) {
      dib->BuildMonochromeOutlineMaskInPlace();
    }
    previewDialog.picture = dib;
    previewDialog.drawOutline = inputDialog.checkFlag64;
    previewDialog.fillPolygon = inputDialog.checkFlag68;
    previewDialog.renderMode = inputDialog.checkFlag6c;
    previewDialog.windowTitle = "The DIB you requested";
    previewDialog.DoModal();
  } else {
    MessageBoxA(0, "You Fool!", "That's No Dib", 0);
  }

  if (inputValue < 20000 && dib != 0) {
    g_pResourceMgr->ReleaseRecordById(static_cast<short>(inputValue));
  }
}

// FUNCTION: IMPERIALISM 0x004145f0
BOOL ImperialismApp::OnIdle(LONG lCount) {
  CWinApp::OnIdle(lCount);
  if (lCount == 0) {
    g_pAmbitApplication->Idle(0);
  }
  g_pAmbitApplication->Idle(1);
#ifdef IMPERIALISM_RUNTIME_TESTS
  if (lCount == 0) {
    RuntimeTestDriver::OnIdle();
  }
#endif
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x00414640
void ImperialismApp::OnHuman() {
  if (g_pAmbitDeveloperAssertProbe_006A1358 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Ambit.cpp", 0x3b6);
  }
}

// FUNCTION: IMPERIALISM 0x00414670
void ImperialismApp::OnUpdateHuman(CCmdUI* commandUi) {
  commandUi->Enable(FALSE);
}

BOOL QueryVolumeInformationForDriveIndex(char driveIndex, CString* volumeName, LPDWORD serial);
bool QueryDriveTypeByDriveIndex(char driveIndex);

// FUNCTION: IMPERIALISM 0x004147b0
void ImperialismApp::OnSlowMemoryChecking() {}

// FUNCTION: IMPERIALISM 0x004147d0
void ImperialismApp::OnUpdateSlowMemoryChecking(CCmdUI* commandUi) {
  (void)commandUi;
}

// FUNCTION: IMPERIALISM 0x004147f0
void ImperialismApp::OnTraceEnabled() {}

// FUNCTION: IMPERIALISM 0x00414810
void ImperialismApp::OnUpdateTraceEnabled(CCmdUI* commandUi) {
  (void)commandUi;
}

// FUNCTION: IMPERIALISM 0x00414830
void ImperialismApp::OnPeekAtGWorld() {}

// FUNCTION: IMPERIALISM 0x00414850
const char* GetDataDirectoryPathLiteral() {
  return s_DataDirectoryPath_006942A8;
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

// FUNCTION: IMPERIALISM 0x004149a0
BOOL ImperialismApp::LoadLanguageResourcesFromIrgFiles() {
  CString savedLanguage =
      GetProfileString(g_pRegistrySettingsSection_0063E040, g_pRegistryLanguageKey_0063E04C, 0);

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

    if (savedLanguage.Compare(languageLabel) == 0) {
      WriteProfileString(g_pRegistrySettingsSection_0063E040, g_pRegistryLanguageKey_0063E04C,
                         savedLanguage);

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
      LoadStringA(irgModule, 0x323, languageCodeString.GetBufferSetLength(0x21), 0x20);
      languageCodeString.ReleaseBuffer(-1);

      unsigned char languageCodeByte0 = languageCodeString[0];
      unsigned char languageCodeByte1 = languageCodeString[1];
      unsigned char languageCodeByte2 = languageCodeString[2];
      languagePackIdE4 = (static_cast<unsigned int>(languageCodeByte2) * 0x100U +
                          static_cast<unsigned int>(languageCodeByte1)) *
                             0x100U +
                         static_cast<unsigned int>(languageCodeByte0);
    }
    FreeLibrary(irgModule);

    if (_findnext(findHandle, &findData) == -1) {
      CloseCrtFindHandleIfOpen(findHandle);
    }
  }

  // "L!" on the command line: scan/report languages, then abort startup.
  BOOL keepStarting = cmdInfo.m_bQuitAfterLanguageScan == 0;
  CloseCrtFindHandleIfOpen(findHandle);
  return keepStarting;
}

// FUNCTION: IMPERIALISM 0x00415090
int ImperialismApp::ShowAutoResolutionDialogIfNeeded() {
  int autoResMode = GetProfileInt(g_pRegistrySettingsSection_0063E040,
                                  g_pRegistryAutoResKey_0063E048, kAutoResPromptSentinel);

  CString languageOverride;
  ImperialismCommandLineInfo cmdInfo(&languageOverride);
  ParseCommandLine(cmdInfo);

  if (cmdInfo.m_bForceAutoResOff40) {
    autoResMode = 0;
  }
  if (cmdInfo.m_bForceAutoResOn) {
    autoResMode = 1;
  }

  if (cmdInfo.m_bShowSetupDialog || autoResMode == kAutoResPromptSentinel) {
    TAutoResolutionDialog dialog(nullptr);
    dialog.PrepareAndCreateModalFromTemplate();
    dialog.autoResolutionCheckState = autoResMode;
    dialog.UpdateData(FALSE);
    dialog.DoModal();
    autoResMode = dialog.autoResolutionCheckState;
  }

  WriteProfileInt(g_pRegistrySettingsSection_0063E040, g_pRegistryAutoResKey_0063E048, autoResMode);
  return autoResMode;
}

// FUNCTION: IMPERIALISM 0x004154e0
UINT ImperialismApp::GetSettingValueFromSettingsSection(LPCTSTR key, int defaultValue) {
  return GetProfileInt(g_pRegistrySettingsSectionAlt_0063E044, key, defaultValue);
}

// FUNCTION: IMPERIALISM 0x00415510
BOOL ImperialismApp::WriteSettingValueToSettingsSection(LPCTSTR key, int value) {
  return WriteProfileInt(g_pRegistrySettingsSectionAlt_0063E044, key, value);
}

// FUNCTION: IMPERIALISM 0x00415580
BOOL ImperialismApp::SetSettingValueInSettingsSection(LPCTSTR key, LPCTSTR value) {
  return WriteProfileString(g_pRegistrySettingsSectionAlt_0063E044, key, value);
}

// FUNCTION: IMPERIALISM 0x004155b0
BOOL ImperialismApp::ApplyAutoResolutionModeAndPersist(int mode) {
  if (appliedAutoResModeC8 != mode) {
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
      WriteProfileInt(g_pRegistrySettingsSection_0063E040, g_pRegistryAutoResKey_0063E048,
                      appliedAutoResModeC8);
      return TRUE;
    }
    return FALSE;
  }
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x00415760
BOOL WarnLowDiskSpaceAndConfirmContinue() {
  const UINT dirSize = GetWindowsDirectoryA(nullptr, 0);
  if (dirSize == 0) {
    return TRUE;
  }

  CString windowsDirectory;
  LPSTR buffer = windowsDirectory.GetBuffer(dirSize);
  if (GetWindowsDirectoryA(buffer, dirSize) == 0) {
    windowsDirectory.ReleaseBuffer(0);
    return TRUE;
  }
  windowsDirectory.ReleaseBuffer(-1);

  int freeMegabytes = 0x7fffffff;
  ULARGE_INTEGER freeBytesAvailable;
  ULARGE_INTEGER totalBytes;
  ULARGE_INTEGER totalFreeBytes;
  freeBytesAvailable.QuadPart = 0;
  totalBytes.QuadPart = 0;
  totalFreeBytes.QuadPart = 0;

  typedef BOOL(WINAPI * GetDiskFreeSpaceExProc)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER,
                                                PULARGE_INTEGER);
  HMODULE kernel32 = LoadLibraryA("KERNEL32.DLL");
  GetDiskFreeSpaceExProc getDiskFreeSpaceEx = 0;
  if (kernel32 != 0) {
    getDiskFreeSpaceEx = (GetDiskFreeSpaceExProc)GetProcAddress(kernel32, "GetDiskFreeSpaceExA");
  }
  if (getDiskFreeSpaceEx != 0 &&
      getDiskFreeSpaceEx(windowsDirectory, &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
    freeMegabytes = (int)(freeBytesAvailable.QuadPart / (1024UL * 1024UL));
  } else {
    DWORD sectorsPerCluster = 0;
    DWORD bytesPerSector = 0;
    DWORD numberOfFreeClusters = 0;
    DWORD totalClusters = 0;
    if (GetDiskFreeSpaceA(windowsDirectory, &sectorsPerCluster, &bytesPerSector,
                          &numberOfFreeClusters, &totalClusters)) {
      const DWORD freeBytes = sectorsPerCluster * bytesPerSector * numberOfFreeClusters;
      freeMegabytes = (int)(freeBytes / (1024UL * 1024UL));
    }
  }
  if (kernel32 != 0) {
    FreeLibrary(kernel32);
  }
  if (freeMegabytes >= 0x19) {
    return TRUE;
  }

  CString templateText;
  CString formattedText;
  CString scratch;
  if (g_pResourceMgr != nullptr) {
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&templateText, 0x2763, 0x19);
  }
  scratch.Format(g_szDecimalFormat, freeMegabytes);
  scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(scratch));

  TLowDiskWarningDialog dialog(nullptr);
  dialog.promptText = formattedText;
  if (!dialog.PrepareAndCreateModalFromTemplate()) {
    return FALSE;
  }
  dialog.UpdateData(FALSE);
  return dialog.DoModal() == 1 ? TRUE : FALSE;
}

// FUNCTION: IMPERIALISM 0x005de830
void ImperialismApp::OnMissionSnooper() {
  TWindow* window =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(static_cast<TurnEventId>(0x3a99));
  if (window == nullptr) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x327);
  }

  TextStyle style;
  style.fontFamily = 0x16;
  style.fontStyleFlags = 0;
  style.fontSize = 9;
  style.textColor = 0;
  DispatchToSelectableTextOptionEntries(window, &style, 0);
  window->Open();
}

// FUNCTION: IMPERIALISM 0x005df7a0
BOOL QueryVolumeInformationForDriveIndex(char driveIndex, CString* volumeName, LPDWORD serial) {
  UINT previousErrorMode = SetErrorMode(SEM_FAILCRITICALERRORS);
  CString rootPath(static_cast<char>('A' + driveIndex), 1);
  rootPath += ":\\";
  BOOL result =
      GetVolumeInformationA(rootPath, volumeName->GetBuffer(0x1e), 0x1e, serial, 0, 0, 0, 0);
  SetErrorMode(previousErrorMode);
  volumeName->ReleaseBuffer(-1);
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
