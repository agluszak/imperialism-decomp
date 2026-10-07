#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

class CIncludeView;

// The Imperialism MFC application object (the global `theApp`, CWinApp singleton at
// DAT_006a1210, cached in g_pImperialismApp by InitInstance). Constructed by the CRT
// static-init bootstrap (0x00412d40); its vtable at 0x0063e2d0 drives
// DispatchMfcAppLifecycle (InitInstance slot +0x58, ExitInstance slot +0x70). Derives
// from the retail MFC CWinApp; adds startup/localization state at +0xC0.
//
// Startup layering: ImperialismApp is the MFC shell (window, registry, resources,
// command line via ImperialismCommandLineInfo); it creates the game-side UI root
// TAmbitApplication (a TApplication) in InitInstance, which in turn builds the
// manager singletons (TSimMgr/TViewMgr/TDisplayMgr/...).
//
// LAYOUT: retail retains CCmdTarget's OLE/automation slots, including
// IsInvokeAllowed at slot 7.
// VTABLE: IMPERIALISM 0x0063e2d0
class ImperialismApp : public CWinApp {
public:
  ImperialismApp();
  virtual ~ImperialismApp() override;

  // CWinApp lifecycle overrides resolved by DispatchMfcAppLifecycle.
  virtual BOOL InitInstance() override;                 // slot +0x58, 0x00412dc0
  virtual int ExitInstance() override;                  // slot +0x70, 0x00413780
  virtual BOOL PreTranslateMessage(MSG* pMsg) override; // slot +0x60, 0x00413a20
  virtual BOOL OnIdle(LONG lCount) override;            // slot +0x68, 0x004145f0

  int ShowAutoResolutionDialogIfNeeded();                                 // 0x00415090
  BOOL SetSettingValueInSettingsSection(LPCTSTR key, LPCTSTR value);      // 0x00415580
  UINT GetSettingValueFromSettingsSection(LPCTSTR key, int defaultValue); // 0x004154e0
  BOOL WriteSettingValueToSettingsSection(LPCTSTR key, int value);        // 0x00415510
  BOOL ApplyAutoResolutionModeAndPersist(int mode);                       // 0x004155b0
  BOOL LoadLanguageResourcesFromIrgFiles();                               // 0x004149a0
  void HandleStartupCommand100();                                         // 0x00413950
  void PostStartupCommand100();                                           // 0x004138b0
  LPCTSTR DetectImperialismInstallDriveAndSetPathPrefix();                // 0x00414870
  void RestoreWaitCursorIfStartupBusy();                                  // 0x004139f0

  // Developer UI commands recovered from the ImperialismApp message map.
  afx_msg void OnTestSomething();                             // 0x00413d00
  afx_msg void OnSwitchGreatPower();                          // 0x00413d20
  afx_msg void OnRunOffTurns();                               // 0x00413f60
  afx_msg void OnBequeathGoodies();                           // 0x004140f0
  afx_msg void OnPeekAtDib();                                 // 0x004143b0
  afx_msg void OnHuman();                                     // 0x00414640
  afx_msg void OnUpdateHuman(CCmdUI* commandUi);              // 0x00414670
  afx_msg void OnMissionSnooper();                            // 0x005de830
  afx_msg void OnSlowMemoryChecking();                        // 0x004147b0
  afx_msg void OnUpdateSlowMemoryChecking(CCmdUI* commandUi); // 0x004147d0
  afx_msg void OnTraceEnabled();                              // 0x004147f0
  afx_msg void OnUpdateTraceEnabled(CCmdUI* commandUi);       // 0x00414810
  afx_msg void OnPeekAtGWorld();                              // 0x00414830

  int* waitCursorAnchor; // 0xC0
  CString installDrivePrefix;
  int appliedAutoResMode;       // 0xC8 — auto-resolution mode currently applied to the display
  CString languageLabel;        // 0xCC — string 0x1e36, the language display label
  CString localizedPictGobName; // 0xD0 — string 0x2c6, localized Pict .gob path (lib slot 0)
  CString field_D4;             // 0xD4 — string 0x840
  CString primaryDataLibName;   // 0xD8 — string 0x297, primary data library path
  CString field_DC;             // 0xDC — string 0x80
  CString languageCodeString;   // 0xE0 — string 0x323, three-letter language code
  int languagePackId;           // 0xE4 — languageCodeString packed little-endian

  DECLARE_MESSAGE_MAP()
};

extern ImperialismApp theApp;

int __cdecl ShowOutOfMemoryErrorNewHandler(size_t allocationSize);

HKEY OpenOrCreateCompanyProductRegistryKey(LPCSTR company, LPCSTR product);

CString ReadOrCreateRegistryStringValueWithFallback(LPCSTR company, LPCSTR product, LPCSTR section,
                                                    LPCSTR valueName, LPCSTR defaultValue);

CIncludeView* GetMainViewHostFromActiveThread();

const char* GetDataDirectoryPathLiteral();

BOOL WarnLowDiskSpaceAndConfirmContinue();
