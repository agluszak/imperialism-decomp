#pragma once

#include "game/mfc.h"

// SDI main frame for ProcessShellCommand (CRuntimeClass @ 0x00648628, m_lpszClassName
// "CMainFrame"). Ghidra buckets frame helpers under provisional TMacViewMgr_* labels.
// No // VTABLE: annotation — retail MFC lacks OLE slots that nafxcw.lib emits (see ImperialismApp).
class CMainFrame : public CFrameWnd {
public:
  DECLARE_DYNCREATE(CMainFrame)
  DECLARE_MESSAGE_MAP()

  CMainFrame();

  afx_msg void OnStartupCommand100();

  int field_BC;
  int field_C0;
  int field_C4;
  int field_CC;
};

void DispatchStartupCommand100ToAppSingleton();
