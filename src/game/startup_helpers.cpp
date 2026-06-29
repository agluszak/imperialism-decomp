#include "game/startup_helpers.h"

#include "game/app_init_globals.h"

#include "game/ImperialismApp.h"
#include "game/TAmbitApplication.h"
#include "game/TAssetMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TLanguageMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TSimMgr.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/config.h"
#include "game/THelpMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TModalTemplateDialog.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/localization_text_helpers.h"

namespace {

const unsigned int kAddrDecimalFormat = 0x0069430c;

void* GetObjectValueAtOffset98(void* object) {
  if (object == nullptr) {
    return nullptr;
  }
  return *reinterpret_cast<void**>(reinterpret_cast<char*>(object) + 0x98);
}

void* GetMainContextFromActiveThread() {
  CWinThread* thread = AfxGetThread();
  if (thread == nullptr) {
    return nullptr;
  }
  // Original calls CWinThread vtable slot +0x7c; m_pMainWnd is the recovered host until that
  // virtual is promoted onto CWinThread.
  return thread->m_pMainWnd;
}

void InvokeLoadUiStringResourceByGroupAndIndex(CString* dest, int group, int index) {
  if (g_pModuleLibraryCacheState != nullptr) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(dest, group, index);
  }
}

void InvokeScanBracketExpressions(TSimMgr* ctx, CString* out, char* input) {
  scanBracketExpressions(ctx, out, input);
}

void FormatStringWithVarArgsToSharedRef(CString* dest, const char* format, int value) {
  dest->Format(format, value);
}

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

} // namespace

// FUNCTION: IMPERIALISM 0x00412a70
void* GetMainViewHostFromActiveThread() {
  return GetObjectValueAtOffset98(GetMainContextFromActiveThread());
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

  const int freeMegabytes = QueryFreeDiskMegabytesOnWindowsVolume(windowsDirectory);
  if (freeMegabytes >= 0x19) {
    return TRUE;
  }

  CString templateText;
  CString formattedText;
  CString scratch;
  InvokeLoadUiStringResourceByGroupAndIndex(&templateText, 0x2763, 0x19);
  FormatStringWithVarArgsToSharedRef(&scratch, reinterpret_cast<const char*>(kAddrDecimalFormat),
                                     freeMegabytes);
  InvokeScanBracketExpressions(g_pLocalizationTable, &formattedText, templateText.GetBuffer(0));

  TLowDiskWarningDialog dialog(nullptr);
  dialog.SetPromptText(formattedText);
  if (!dialog.PrepareAndCreateModalFromTemplate()) {
    return FALSE;
  }
  dialog.UpdateData(FALSE);
  return dialog.FinalizeModalDialogAndRestoreOwnerFocus() == 1 ? TRUE : FALSE;
}

// FUNCTION: IMPERIALISM 0x00483340
void SetUiRuntimeContextAndActivateMain(TView* mainViewHost, TView* activeDialog) {
  if (mainViewHost == nullptr) {
    return;
  }
  *reinterpret_cast<TView**>(reinterpret_cast<char*>(mainViewHost) + 0x40) = activeDialog;
  mainViewHost->PropagateUiResourceContextRecursive(reinterpret_cast<CWnd*>(mainViewHost));
  if (activeDialog != nullptr) {
    activeDialog->ResolveControlByTag(0x6d61696e);
  }
}

// FUNCTION: IMPERIALISM 0x00497230
GlobalViewportRectDefaultsRecord** InitializeGlobalRectDefaultsIfUninitialized() {
  if (g_pGlobalViewportRectDefaultsRecord == nullptr) {
    g_globalViewportRectDefaultsRecord.field0 = 0;
    g_globalViewportRectDefaultsRecord.left = 0;
    g_globalViewportRectDefaultsRecord.top = 0;
    g_globalViewportRectDefaultsRecord.right = 0x280;
    g_globalViewportRectDefaultsRecord.bottom = 0x1e0;
    g_pGlobalViewportRectDefaultsRecord = &g_globalViewportRectDefaultsRecord;
  }
  return &g_pGlobalViewportRectDefaultsRecord;
}

// FUNCTION: IMPERIALISM 0x0049cc40
void SetCachedAppShellCommand(UINT shellCommand) {
  // Stores cmdInfo.m_nShellCommand — see g_cachedAppShellCommand @ 0x006a2018.
  g_cachedAppShellCommand = shellCommand;
}

// FUNCTION: IMPERIALISM 0x0049ded0
void InitializeGlobalRuntimeSystemsFromConfig(TAmbitApplication* app) {
  app->field_48 = 0;
  app->field_50 = theApp.field_E4;

  if (g_pLanguageMgr == nullptr) {
    g_pLanguageMgr = new TLanguageMgr();
  }

  g_pLanguageMgr->ReloadPreplutNewsTableAndResources(app->field_50);

  TSimMgr* simMgr = new TSimMgr();
  if (simMgr != nullptr) {
    simMgr->InitializeTurnFlowStateDefaults();
  }
  g_pLocalizationTable = simMgr;

  TAssetMgr* assetMgr = new TAssetMgr();
  ForwardEnsurePictWvDataGobLoadedBySlot(app->field_50);
  g_pUiViewManager = assetMgr;

  EnsureTurnEventDialogFactoryRegistryInitialized();

  TViewMgr* viewMgr = new TViewMgr();
  if (viewMgr != nullptr) {
    viewMgr->LoadTurnEventCursorTable();
  }
  g_pUiRuntimeContext = viewMgr;

  TDisplayMgr* displayMgr = new TDisplayMgr();
  if (displayMgr != nullptr) {
    displayMgr->InitializeTurnOrderNavigationDialogByViewportSize();
  }
  g_pDisplayMgr = displayMgr;

  TMacViewMgr* mapView = new TMacViewMgr();
  if (mapView != nullptr) {
    mapView->InitializeStrategicMapViewSystem();
  }
  g_pStrategicMapViewSystem = mapView;

  if (g_pHelpMgr == nullptr) {
    g_pHelpMgr = new THelpMgr();
  }
  if (g_pHelpMgr != nullptr) {
    g_pHelpMgr->InitializeHelpManagerIndexArrayAndState();
  }

  if (g_pGameFlowState != nullptr) {
    reinterpret_cast<TObject*>(g_pGameFlowState)->Free();
    g_pGameFlowState = nullptr;
  }

  Config configScratch;
  g_pGameFlowState = configScratch.InitDefaults();
  if (g_pGameFlowState != nullptr) {
    reinterpret_cast<TMultiplayerMgr*>(g_pGameFlowState)
        ->InitializeMultiplayerManagerForSessionContext(CString());
  }
}

// FUNCTION: IMPERIALISM 0x005e7a80
void* SetGlobalCallback6A7FACAndReturnPrevious(void* callback) {
  extern undefined4 EnterIndexedCriticalSectionWithLazyInit();
  extern undefined4 LeaveIndexedCriticalSection();
  reinterpret_cast<void(__cdecl*)(int)>(EnterIndexedCriticalSectionWithLazyInit)(9);
  void* prev = g_pGlobalCallback_006a7fac;
  g_pGlobalCallback_006a7fac = callback;
  reinterpret_cast<void(__cdecl*)(int)>(LeaveIndexedCriticalSection)(9);
  return prev;
}
