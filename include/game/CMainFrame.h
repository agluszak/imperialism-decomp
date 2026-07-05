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
  // ON_COMMAND(100): the startup command InitInstance posts once the frame is up.
  afx_msg void OnStartupCommand100(); // 0x00484fd0
  // ON_MESSAGE(0x464): same handling as command 100, LRESULT-shaped.
  afx_msg LRESULT OnMsg0464(WPARAM wParam, LPARAM lParam); // 0x00484fb0
  afx_msg void OnPaletteChanged(CWnd* pFocusWnd);
  // ON_WM_QUERYNEWPALETTE (0x30F): realize the cached palette into the active view DC
  // (also called directly from OnCreate / OnCommand8009 / OnPaletteChanged).
  afx_msg BOOL OnQueryNewPalette(); // 0x00484ff0
  // Message 0x2420 (posted by TApplication::PostTurnEventCodeMessage2420): dispatch the
  // carried turn-event code into the UI runtime with the active nation as payload.
  afx_msg LRESULT HandleCustomMessage2420DispatchTurnEvent(WPARAM wParam, LPARAM lParam);
  afx_msg void OnCommand8009();
  afx_msg void OnCommand800C();
  afx_msg void OnPaint();                                             // 0x00485bd0
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);         // 0x00485c00
  afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized); // 0x00485c60

  virtual BOOL PreTranslateMessage(MSG* msg);

  void ConfigureTopLevelWindowStyleAndPlacement(int width, int height);
  int SetFieldC0AndInvalidateWindowIfChanged(int styleValue); // 0x00485990

  CDibPal* field_BC;
  int field_C0;
  CObject* field_C4;
  int field_CC;
};
