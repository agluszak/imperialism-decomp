#include "game/ImperialismApp.h"
#include "game/ImperialismCommandLineInfo.h"
#include "game/app_init_globals.h"
#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TAmbitApplication.h"
#include "game/TBackdropWindow.h" // RefreshBackdropOnInputMessages
#include "game/TSoundPlayer.h"
#include "game/TDisplayMgr.h"
#include "game/CAmbitDocument.h"
#include "game/CIncludeView.h"
#include "game/CMainFrame.h"
#include "game/TMacViewMgr.h"
#include "game/TAssetMgr.h"
#include "game/TC2TemplateDialog.h"
#include "game/TCity.h"
#include "game/CDib.h"
#include "game/TGreatPower.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/ui_invalidation_guard.h"
#include "game/CString.h"
#include "game/mfc.h"
#include "game/TAutoResolutionDialog.h"
#include "game/TModalTemplateDialog.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_regions.h"

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

// Sibling of ReadOrCreateRegistryStringValueWithFallback's key-opening prologue, one level
// shallower (no <section> subkey). Caller owns the returned HKEY (RegCloseKey). No live
// caller found (zero Ghidra xrefs to 0x00412640) -- kept as ported dead code per its real
// address, not wired to any current call site.
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

// Reads HKEY_CURRENT_USER\Software\<company>\<product>\<section>, value <valueName>,
// returning it as a CString; falls back to defaultValue if any registry step fails or the
// value isn't present. No live caller found (zero Ghidra xrefs to 0x00412840); InitInstance
// below inlines its own equivalent registry-clear sequence rather than calling this.
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
    LPBYTE buffer = reinterpret_cast<LPBYTE>(value.GetBuffer(dataSize));
    status = RegQueryValueExA(hFinal, valueName, nullptr, &dataType, buffer, &dataSize);
    value.ReleaseBuffer(-1);
  }
  RegCloseKey(hFinal);
  if (status == ERROR_SUCCESS) {
    return value;
  }
  return CString(defaultValue);
}

namespace {
CFrameWnd* GetMainFrameFromActiveThread() {
  CWinThread* thread = AfxGetThread();
  if (thread == nullptr) {
    return nullptr;
  }
  // Original calls CWinThread vtable slot +0x7c; m_pMainWnd is the recovered host until that
  // virtual is promoted onto CWinThread. The SDI main frame is always a CFrameWnd here.
  return static_cast<CFrameWnd*>(thread->m_pMainWnd);
}
} // namespace

// The main thread's CWinThread::m_pMainWnd (the SDI CMainFrame), via its real
// CFrameWnd::GetActiveView(). Always a CIncludeView in this app (the only registered
// document-template view class).
// FUNCTION: IMPERIALISM 0x00412a70
CIncludeView* GetMainViewHostFromActiveThread() {
  CFrameWnd* mainFrame = GetMainFrameFromActiveThread();
  if (mainFrame == nullptr) {
    return nullptr;
  }
  return static_cast<CIncludeView*>(mainFrame->GetActiveView());
}

// GetMessageMap (vtable index 12, slot 0x30) is compiler-generated by the message-map
// macros below.
// SYNTHETIC: IMPERIALISM 0x00412aa0
// ImperialismApp::GetMessageMap
#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(ImperialismApp, CWinApp)
ON_COMMAND(0x8015, OnSelectActiveNation)
ON_COMMAND(0x8016, OnApplyTurnCooldownOverride)
ON_COMMAND(0x8017, OnAdjustNationResourcesAndPopulation)
ON_COMMAND(0x8018, OnPreviewDibResource)
ON_COMMAND(0x8019, OnRunAmbitDeveloperAssert)
ON_UPDATE_COMMAND_UI(0x8019, OnUpdateAmbitDeveloperAssert)
END_MESSAGE_MAP()
#endif

// FUNCTION: IMPERIALISM 0x00412ac0
ImperialismApp::ImperialismApp()
    : CWinApp(), waitCursorAnchorC0(0), field_C4(), appliedAutoResModeC8(0), languageLabelCC(),
      localizedPictGobNameD0(), field_D4(), primaryDataLibNameD8(), field_DC(),
      languageCodeStringE0(), languagePackIdE4(0) {}

// SYNTHETIC: IMPERIALISM 0x00412c30
// ImperialismApp::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00412c60
ImperialismApp::~ImperialismApp() {}

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

    if (!g_pModuleLibraryCacheState->LoadPrimaryDataLibraryWithErrorDialog(primaryDataLibNameD8)) {
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
    g_pGlobalUiRootController->InitializeGlobalRuntimeSystems();

    g_pSfxPlaybackSystem = new TSoundPlayer();
    g_pSfxPlaybackSystem->InitializeSoundSubsystemAndAllocateChannelLists(0xf);

    CIncludeView* mainView = GetMainViewHostFromActiveThread();
    mainView->SetUiRuntimeContextAndActivateMain(g_pDisplayMgr->activeDialog);

    if (_mbscmp(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(
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

// CWinThread::PreTranslateMessage override (vtable slot +0x60): give the tiled backdrop a
// chance to repaint on input traffic, then defer to the normal CWinThread pump. (Was
// previously mis-attributed to CMainFrame::PreTranslateMessage with a CFrameWnd base call;
// the vtable slot and the CWinThread base call both prove it is the CWinApp-level override.)
// FUNCTION: IMPERIALISM 0x00413a20
BOOL ImperialismApp::PreTranslateMessage(MSG* pMsg) {
  RefreshBackdropOnInputMessages(pMsg);
  return CWinThread::PreTranslateMessage(pMsg);
}

// Let the developer choose the active nation, rebuild the active nation's derived resource
// state when the simulation is in setup mode, then redispatch the currently displayed turn
// event for the newly selected nation.
// FUNCTION: IMPERIALISM 0x00413d20
void ImperialismApp::OnSelectActiveNation() {
  TDBTemplateDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();
  dialog.slider.SetRange(0, 6, FALSE);
  dialog.slider.SetPos(g_pSimMgr->GetActiveNationId());

  if (dialog.DoModal() == IDOK) {
    short nationSlot = static_cast<short>(dialog.slider.GetPos());
    g_pSimMgr->SetActiveNationSlotAndRefreshCityCapabilityUiHandles(nationSlot);
    if (g_pSimMgr->mode == 0x11) {
      g_apNationStates[g_pSimMgr->GetActiveNationId()]
          ->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    }
    g_pUiRuntimeContext->DispatchTurnEvent(g_pUiRuntimeContext->currentTurnEventCode,
                                           g_pSimMgr->GetActiveNationId());
  }
}

// Preserve the turn-flow cooldown across the modal edit, copy the current simulation mode
// into the side flag, and ask the main frame to advance command 100 asynchronously.
// FUNCTION: IMPERIALISM 0x00413f60
void ImperialismApp::OnApplyTurnCooldownOverride() {
  TDCTemplateDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();
  short savedCooldown = g_nTurnCooldownDeferCounter006A43C4;

  if (dialog.DoModal() == IDOK) {
    g_nTurnCooldownDeferCounter006A43C4 = savedCooldown;
    g_nTurnCooldownSideFlag00698B10 = static_cast<short>(g_pSimMgr->mode);
    PostMessageA(m_pMainWnd->m_hWnd, WM_COMMAND, 100, 0);
  }
}

// Apply the DE diagnostic dialog's two edits to the selected nation's city: one delta is
// added to every commodity stock and the other is passed as a negative population removal,
// which is the original UI's way of adding population in each skill band.
// FUNCTION: IMPERIALISM 0x004140f0
void ImperialismApp::OnAdjustNationResourcesAndPopulation() {
  TDETemplateDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();
  dialog.slider.SetRange(0, 6, FALSE);
  dialog.slider.SetPos(g_pSimMgr->GetActiveNationId());

  if (dialog.DoModal() == IDOK) {
    int nationSlot = dialog.slider.GetPos();
    TCity* city = g_apNationStates[nationSlot] != 0 ? g_apNationStates[nationSlot]->city : 0;
    for (short commodity = 0; commodity < 0x17; ++commodity) {
      city->CityStockByType(commodity) = static_cast<short>(
          city->CityStockByType(commodity) + static_cast<short>(dialog.commodityAdjustmentB4));
      city->VerifyStocks();
    }

    short populationDelta = static_cast<short>(-static_cast<int>(dialog.populationAdjustmentB0));
    city->productionSummary1d8->RemovePopulation(1, populationDelta);
    city->productionSummary1d8->RemovePopulation(2, populationDelta);
    city->productionSummary1d8->RemovePopulation(4, populationDelta);
  }
}

// Preview either a cached bitmap resource (IDs below 20000) or a direct CDib pointer entered
// in the DF developer dialog. The preview options map directly to the DD dialog's outline,
// fill and rendering controls.
// FUNCTION: IMPERIALISM 0x004143b0
void ImperialismApp::OnPreviewDibResource() {
  TDFTemplateDialog inputDialog(0);
  if (inputDialog.DoModal() != IDOK) {
    return;
  }

  int inputValue = inputDialog.editValue5c;
  CDib* dib;
  if (inputValue < 20000) {
    dib = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(
        static_cast<unsigned short>(inputValue));
  } else {
    dib = reinterpret_cast<CDib*>(inputValue);
  }

  if (dib != 0 && AfxIsValidAddress(dib, sizeof(CDib), FALSE) &&
      dib->IsKindOf(RUNTIME_CLASS(CDib))) {
    TDDTemplateDialog previewDialog(0);
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
    g_pModuleLibraryCacheState->ReleaseRecordById(static_cast<short>(inputValue));
  }
}

// CWinThread::OnIdle override (vtable slot +0x68): after the base idle work, give the game
// UI root controller its per-phase Idle ticks (phase 0 only on the first idle pass, phase 1
// every pass), and keep requesting idle time.
// FUNCTION: IMPERIALISM 0x004145f0
BOOL ImperialismApp::OnIdle(LONG lCount) {
  CWinApp::OnIdle(lCount);
  if (lCount == 0) {
    g_pGlobalUiRootController->Idle(0);
  }
  g_pGlobalUiRootController->Idle(1);
  return TRUE;
}

// The retail debug menu retains this explicit assert probe. Its backing pointer has no
// writer in the image, and the paired update handler keeps the command disabled in normal
// menus; preserving both behaviors makes the dormant command safe and structurally honest.
// FUNCTION: IMPERIALISM 0x00414640
void ImperialismApp::OnRunAmbitDeveloperAssert() {
  if (g_pAmbitDeveloperAssertProbe_006A1358 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Ambit.cpp", 0x3b6);
  }
}

// FUNCTION: IMPERIALISM 0x00414670
void ImperialismApp::OnUpdateAmbitDeveloperAssert(CCmdUI* commandUi) {
  commandUi->Enable(FALSE);
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

BOOL QueryVolumeInformationForDriveIndex(char driveIndex, CString* volumeName, LPDWORD serial);
bool QueryDriveTypeByDriveIndex(char driveIndex);

// Returns the on-disk data directory prefix. Used by TLanguageMgr's table loaders (real
// caller: TLanguageMgr::LoadNewsTabTexResourcesAndBuildEntries, 0x00507e50).
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

    if (_mbscmp(const_cast<unsigned char*>(
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
    dialog.DoModal();
    autoResMode = dialog.autoResolutionCheckState;
  }

  WriteProfileInt(SettingsSection(), AutoResValueName(), autoResMode);
  return autoResMode;
}

// FUNCTION: IMPERIALISM 0x00415580
BOOL ImperialismApp::SetSettingValueInSettingsSection(LPCTSTR key, LPCTSTR value) {
  return WriteProfileString(SettingsSection(), key, value);
}

// FUNCTION: IMPERIALISM 0x004155b0
BOOL ImperialismApp::ApplyAutoResolutionModeAndPersist(int mode) {
  if (appliedAutoResModeC8 == mode) {
    return TRUE;
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
    return TRUE;
  }
  return FALSE;
}

namespace {

int QueryFreeDiskMegabytesOnWindowsVolume(LPCSTR windowsDirectory) {
  ULARGE_INTEGER freeBytesAvailable;
  ULARGE_INTEGER totalBytes;
  ULARGE_INTEGER totalFreeBytes;
  freeBytesAvailable.QuadPart = 0;
  totalBytes.QuadPart = 0;
  totalFreeBytes.QuadPart = 0;

  typedef BOOL(WINAPI * GetDiskFreeSpaceExProc)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER,
                                                PULARGE_INTEGER);
  HMODULE kernel32 = LoadLibraryA("KERNEL32.DLL");
  if (kernel32 != 0) {
    GetDiskFreeSpaceExProc getDiskFreeSpaceEx =
        (GetDiskFreeSpaceExProc)GetProcAddress(kernel32, "GetDiskFreeSpaceExA");
    if (getDiskFreeSpaceEx != 0 &&
        getDiskFreeSpaceEx(windowsDirectory, &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
      FreeLibrary(kernel32);
      return (int)(freeBytesAvailable.QuadPart / (1024UL * 1024UL));
    }
    FreeLibrary(kernel32);
  }

  DWORD sectorsPerCluster = 0;
  DWORD bytesPerSector = 0;
  DWORD numberOfFreeClusters = 0;
  DWORD totalClusters = 0;
  if (!GetDiskFreeSpaceA(windowsDirectory, &sectorsPerCluster, &bytesPerSector,
                         &numberOfFreeClusters, &totalClusters)) {
    return 0x7fffffff;
  }
  const DWORD freeBytes = sectorsPerCluster * bytesPerSector * numberOfFreeClusters;
  return (int)(freeBytes / (1024UL * 1024UL));
}

const unsigned int kAddrDecimalFormat = 0x0069430c;

} // namespace

// The low-disk-space startup gate: warns and asks to continue if free space on the Windows
// install volume drops below 25 MB.
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

  const int freeMegabytes = QueryFreeDiskMegabytesOnWindowsVolume(windowsDirectory);
  if (freeMegabytes >= 0x19) {
    return TRUE;
  }

  CString templateText;
  CString formattedText;
  CString scratch;
  if (g_pModuleLibraryCacheState != nullptr) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&templateText, 0x2763, 0x19);
  }
  scratch.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), freeMegabytes);
  scanBracketExpressions(g_pSimMgr, &formattedText, templateText.GetBuffer(0));

  TLowDiskWarningDialog dialog(nullptr);
  dialog.SetPromptText(formattedText);
  if (!dialog.PrepareAndCreateModalFromTemplate()) {
    return FALSE;
  }
  dialog.UpdateData(FALSE);
  return dialog.DoModal() == 1 ? TRUE : FALSE;
}

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
