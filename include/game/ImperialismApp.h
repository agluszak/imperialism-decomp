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
// NB: deliberately no `// VTABLE: IMPERIALISM 0x0063e2d0` annotation. The original game
// linked an MFC built without OLE/automation, so its CCmdTarget/CWinApp vtable lacks the
// OLE slots (OnCmdMsg, GetDispatchMap, GetMessageMap, …) that retail nafxcw.lib emits.
// Asserting the vtable would fail on that accepted layout divergence; the inheritance
// itself is correct and drives DispatchMfcAppLifecycle as designed.
class ImperialismApp : public CWinApp {
public:
  ImperialismApp();

  // CWinApp lifecycle overrides resolved by DispatchMfcAppLifecycle.
  virtual BOOL InitInstance(); // slot +0x58, 0x00412dc0
  virtual int ExitInstance();  // slot +0x70, 0x00413780

  int ShowAutoResolutionDialogIfNeeded();           // 0x00415090
  void ApplyAutoResolutionModeAndPersist(int mode); // 0x004155b0
  BOOL LoadLanguageResourcesFromIrgFiles();         // 0x004149a0
  void HandleStartupCommand100();                   // 0x00413950
  void PostStartupCommand100();                     // 0x004138b0
  // Modal-pump helper (ExecuteViewModalStateWithPushPopChain 0x48da60,
  // ShowDialogTemplateE0ModalAndReleaseCapture 0x498cc0 — both call it on
  // g_pImperialismApp): keep the wait cursor up while HandleStartupCommand100 runs.
  void RestoreWaitCursorIfStartupBusy();            // 0x004139f0

  // Subclass state laid out immediately after the CWinApp base (offset 0xC0).
  // While HandleStartupCommand100 runs, points at a stack local so the modal pump
  // (RestoreAppWaitCursorDuringModalLoop) knows to keep the wait cursor up.
  int* waitCursorAnchorC0;         // 0xC0
  CString field_C4;                // 0xC4
  int appliedAutoResModeC8;        // 0xC8 — auto-resolution mode currently applied to the display
  // 0xCC..0xE0: strings loaded from the matching language .irg module
  // (LoadLanguageResourcesFromIrgFiles).
  CString languageLabelCC;         // 0xCC — string 0x1e36, the language display label
  CString localizedPictGobNameD0;  // 0xD0 — string 0x2c6, localized Pict .gob path (lib slot 0)
  CString field_D4;                // 0xD4 — string 0x840
  CString primaryDataLibNameD8;    // 0xD8 — string 0x297, primary data library path
  CString field_DC;                // 0xDC — string 0x80
  CString languageCodeStringE0;    // 0xE0 — string 0x323, three-letter language code
  int languagePackIdE4;            // 0xE4 — languageCodeStringE0 packed little-endian
};

extern ImperialismApp theApp;

// 0x00412d90 — out-of-memory box; installed via the CRT _set_new_handler in InitInstance.
int __cdecl ShowOutOfMemoryErrorNewHandler(size_t allocationSize);

void PostWmCloseToMainThreadWindow(); // 0x004146d0
