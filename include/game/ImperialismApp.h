#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

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
// NB: no `// VTABLE: IMPERIALISM 0x0063e2d0` annotation yet. This is NOT an OLE layout
// divergence (an earlier note here claimed the game's MFC "lacked OLE slots" — that is
// false). The game's MFC was built WITH OLE/automation support: ImperialismApp's vtable
// slot 7 (0x0063e2ec -> 0x00606c4e) is the shared CCmdTarget::IsInvokeAllowed stub, and
// the whole OLE-gated CCmdTarget slot run (IsInvokeAllowed / GetDispatchIID / the
// type-library getters / the dispatch-connection-interface map getters) is present and
// already matched — with those exact slots — in the CDialog vtable (0x0066fc2c, 54 slots)
// we drive to 100%. The vtable here is simply un-annotated: the
// CObject->CCmdTarget->CWinApp LIBRARY per-slot pass (the CObject.cpp / CDialog-vtable
// pattern) has not been run for this class, so its shared trivial MFC stubs still pair
// ambiguously and carry mislabeled game-class names. Doing that pass would let the vtable
// be asserted. (Note: OnCmdMsg and GetMessageMap are NOT OLE-gated — both remain even
// under _AFX_NO_OLE_SUPPORT — so neither was ever an "OLE slot" difference.) The CWinApp
// inheritance itself is correct and drives DispatchMfcAppLifecycle as designed.
// VTABLE: IMPERIALISM 0x0063e2d0
class ImperialismApp : public CWinApp {
public:
  ImperialismApp();
  virtual ~ImperialismApp() override;

  // CWinApp lifecycle overrides resolved by DispatchMfcAppLifecycle.
  virtual BOOL InitInstance() override; // slot +0x58, 0x00412dc0
  virtual int ExitInstance() override;  // slot +0x70, 0x00413780
  // CWinThread::PreTranslateMessage override (vtable slot +0x60): refresh the tiled
  // backdrop on input messages, then chain to the base pump.
  virtual BOOL PreTranslateMessage(MSG* pMsg) override; // slot +0x60, 0x00413a20
  // CWinThread::OnIdle override (vtable slot +0x68): drive the game UI root's per-phase
  // Idle after the base idle work.
  virtual BOOL OnIdle(LONG lCount) override; // slot +0x68, 0x004145f0

  int ShowAutoResolutionDialogIfNeeded();                            // 0x00415090
  BOOL SetSettingValueInSettingsSection(LPCTSTR key, LPCTSTR value); // 0x00415580
  BOOL ApplyAutoResolutionModeAndPersist(int mode);                  // 0x004155b0
  BOOL LoadLanguageResourcesFromIrgFiles();                          // 0x004149a0
  void HandleStartupCommand100();                                    // 0x00413950
  void PostStartupCommand100();                                      // 0x004138b0
  LPCTSTR DetectImperialismInstallDriveAndSetPathPrefix();           // 0x00414870
  // Modal-pump helper (ExecuteViewModalStateWithPushPopChain 0x48da60,
  // ShowDialogTemplateE0ModalAndReleaseCapture 0x498cc0 — both call it on
  // g_pImperialismApp): keep the wait cursor up while HandleStartupCommand100 runs.
  void RestoreWaitCursorIfStartupBusy(); // 0x004139f0

  // Subclass state laid out immediately after the CWinApp base (offset 0xC0).
  // While HandleStartupCommand100 runs, points at a stack local so the modal pump
  // (RestoreAppWaitCursorDuringModalLoop) knows to keep the wait cursor up.
  int* waitCursorAnchorC0;  // 0xC0
  CString field_C4;         // 0xC4
  int appliedAutoResModeC8; // 0xC8 — auto-resolution mode currently applied to the display
  // 0xCC..0xE0: strings loaded from the matching language .irg module
  // (LoadLanguageResourcesFromIrgFiles).
  CString languageLabelCC;        // 0xCC — string 0x1e36, the language display label
  CString localizedPictGobNameD0; // 0xD0 — string 0x2c6, localized Pict .gob path (lib slot 0)
  CString field_D4;               // 0xD4 — string 0x840
  CString primaryDataLibNameD8;   // 0xD8 — string 0x297, primary data library path
  CString field_DC;               // 0xDC — string 0x80
  CString languageCodeStringE0;   // 0xE0 — string 0x323, three-letter language code
  int languagePackIdE4;           // 0xE4 — languageCodeStringE0 packed little-endian

  DECLARE_MESSAGE_MAP()
};

extern ImperialismApp theApp;

// 0x00412d90 — out-of-memory box; installed via the CRT _set_new_handler in InitInstance.
int __cdecl ShowOutOfMemoryErrorNewHandler(size_t allocationSize);

void PostWmCloseToMainThreadWindow(); // 0x004146d0
