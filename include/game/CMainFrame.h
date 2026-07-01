#pragma once

#include "game/CDibPal.h"
#include "game/mfc.h"

// SDI main frame for ProcessShellCommand (CRuntimeClass @ 0x00648628, m_lpszClassName
// "CMainFrame"). Ghidra buckets frame helpers under provisional TMacViewMgr_* labels.
// No // VTABLE: annotation — retail MFC lacks OLE slots that nafxcw.lib emits (see ImperialismApp).
class CMainFrameRefTarget {
public:
  virtual ~CMainFrameRefTarget();
  virtual void ReleaseWithFlag(int freeMemory) = 0;
};

class CMainFrame : public CFrameWnd {
public:
  DECLARE_DYNCREATE(CMainFrame)
  DECLARE_MESSAGE_MAP()

public:
  CMainFrame();
  ~CMainFrame();

  afx_msg BOOL PreCreateWindow(CREATESTRUCT& cs);
  afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
  afx_msg void OnStartupCommand100();
  afx_msg void OnPaletteChanged(CWnd* pFocusWnd);
  afx_msg LRESULT OnMsg030F(WPARAM wParam, LPARAM lParam);
  afx_msg void OnCommand8009();
  afx_msg void OnCommand800C();

  virtual BOOL PreTranslateMessage(MSG* msg);

  void ConfigureTopLevelWindowStyleAndPlacement(int width, int height);
  int TryRealizeViewPaletteAndInvalidateWindow();

  CDibPal* field_BC;
  int field_C0;
  CObject* field_C4;
  int field_CC;
};

void DispatchStartupCommand100ToAppSingleton();
