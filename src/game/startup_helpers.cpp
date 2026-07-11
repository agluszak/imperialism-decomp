#include "game/startup_helpers.h"

#include "game/app_init_globals.h"

#include "game/CIncludeView.h"
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
#include "game/THelpMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TModalTemplateDialog.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/localization_text_helpers.h"

namespace {

const unsigned int kAddrDecimalFormat = 0x0069430c;

CFrameWnd* GetMainFrameFromActiveThread() {
  CWinThread* thread = AfxGetThread();
  if (thread == nullptr) {
    return nullptr;
  }
  // Original calls CWinThread vtable slot +0x7c; m_pMainWnd is the recovered host until that
  // virtual is promoted onto CWinThread. The SDI main frame is always a CFrameWnd here.
  return static_cast<CFrameWnd*>(thread->m_pMainWnd);
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

// FUNCTION: IMPERIALISM 0x00412a70
CIncludeView* GetMainViewHostFromActiveThread() {
  CFrameWnd* mainFrame = GetMainFrameFromActiveThread();
  if (mainFrame == nullptr) {
    return nullptr;
  }
  return static_cast<CIncludeView*>(mainFrame->GetActiveView());
}

// Returns the on-disk data directory prefix. The Ghidra-era name claimed it was a
// news-tab resource loader; the whole function is this literal (used by TLanguageMgr's
// table loaders, original caller 0x507e50).
// FUNCTION: IMPERIALISM 0x00414850
const char* GetDataDirectoryPathLiteral() {
  return s_DataDirectoryPath_006942A8;
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
  InvokeScanBracketExpressions(g_pSimMgr, &formattedText, templateText.GetBuffer(0));

  TLowDiskWarningDialog dialog(nullptr);
  dialog.SetPromptText(formattedText);
  if (!dialog.PrepareAndCreateModalFromTemplate()) {
    return FALSE;
  }
  dialog.UpdateData(FALSE);
  return dialog.FinalizeModalDialogAndRestoreOwnerFocus() == 1 ? TRUE : FALSE;
}

// FUNCTION: IMPERIALISM 0x00493250
unsigned int GetTickCountDiv16() {
  return GetTickCount() >> 4;
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
void SetCachedShowSplashFlag(BOOL showSplash) {
  g_cachedShowSplashFlag = showSplash;
}
