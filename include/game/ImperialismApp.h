#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

// The Imperialism MFC application object (the global `theApp`, CWinApp singleton at
// DAT_006a1210). Constructed by the CRT static-init bootstrap (0x00412d40); its vtable
// at 0x0063e2d0 drives DispatchMfcAppLifecycle (InitInstance slot +0x58, ExitInstance
// slot +0x70). Derives from the retail MFC CWinApp; adds path/string state at +0xC0.
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
  virtual BOOL InitInstance();  // slot +0x58, 0x00412dc0
  virtual int ExitInstance();   // slot +0x70, 0x00413780

  int ShowAutoResolutionDialogIfNeeded();            // 0x00415090
  void ApplyAutoResolutionModeAndPersist(int mode);  // 0x004155b0

  // Subclass state laid out immediately after the CWinApp base (offset 0xC0).
  int field_C0;       // 0xC0
  CString field_C4;   // 0xC4
  int field_C8;       // 0xC8
  CString field_CC;   // 0xCC
  CString field_D0;   // 0xD0
  CString field_D4;   // 0xD4
  CString field_D8;   // 0xD8
  CString field_DC;   // 0xDC
  CString field_E0;   // 0xE0
  int field_E4;       // 0xE4
};

extern ImperialismApp theApp;
