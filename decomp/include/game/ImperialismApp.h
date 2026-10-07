#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

class CIncludeView;

// The MFC application object (theApp); InitInstance creates the TAmbitApplication UI root.
// LAYOUT: retail retains CCmdTarget's OLE/automation slots, including IsInvokeAllowed at slot 7.
// VTABLE: IMPERIALISM 0x0063e2d0
class ImperialismApp : public CWinApp {
public:
  ImperialismApp();
  virtual ~ImperialismApp() override;

  // CWinApp lifecycle overrides resolved by DispatchMfcAppLifecycle.
  virtual BOOL InitInstance() override;
  virtual int ExitInstance() override;
  virtual BOOL PreTranslateMessage(MSG* pMsg) override;
  virtual BOOL OnIdle(LONG lCount) override;

  int ShowAutoResolutionDialogIfNeeded();
  BOOL SetSettingValueInSettingsSection(LPCTSTR key, LPCTSTR value);
  UINT GetSettingValueFromSettingsSection(LPCTSTR key, int defaultValue);
  BOOL WriteSettingValueToSettingsSection(LPCTSTR key, int value);
  BOOL ApplyAutoResolutionModeAndPersist(int mode);
  BOOL LoadLanguageResourcesFromIrgFiles();
  void HandleStartupCommand100();
  void PostStartupCommand100();
  LPCTSTR DetectImperialismInstallDriveAndSetPathPrefix();
  void RestoreWaitCursorIfStartupBusy();

  // Developer UI commands recovered from the ImperialismApp message map.
  afx_msg void OnTestSomething();
  afx_msg void OnSwitchGreatPower();
  afx_msg void OnRunOffTurns();
  afx_msg void OnBequeathGoodies();
  afx_msg void OnPeekAtDib();
  afx_msg void OnHuman();
  afx_msg void OnUpdateHuman(CCmdUI* commandUi);
  afx_msg void OnMissionSnooper();
  afx_msg void OnSlowMemoryChecking();
  afx_msg void OnUpdateSlowMemoryChecking(CCmdUI* commandUi);
  afx_msg void OnTraceEnabled();
  afx_msg void OnUpdateTraceEnabled(CCmdUI* commandUi);
  afx_msg void OnPeekAtGWorld();

  int* waitCursorAnchor;
  CString installDrivePrefix;
  int appliedAutoResMode;       // auto-resolution mode currently applied to the display
  CString languageLabel;        // string 0x1e36, the language display label
  CString localizedPictGobName; // string 0x2c6, localized Pict .gob path (lib slot 0)
  CString assetLibraryName;     // string 0x840
  CString primaryDataLibName;   // string 0x297, primary data library path
  CString soundLibraryName;     // string 0x80
  CString languageCodeString;   // string 0x323, three-letter language code
  int languagePackId;           // languageCodeString packed little-endian

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
