#pragma once

#include "game/CDib.h"
#include "game/CDibPal.h"
#include "game/mfc.h"

// SDI main frame for ProcessShellCommand (CRuntimeClass @ 0x00648628, m_lpszClassName
// "CMainFrame"). Ghidra buckets frame helpers under provisional TMacViewMgr_* labels.
// No // VTABLE: annotation yet — the CObject->CCmdTarget->CFrameWnd LIBRARY per-slot pass
// (the CDialog-vtable pattern) has not been run for this class, so its shared trivial MFC
// stubs still pair ambiguously. This is NOT an OLE divergence: the game's MFC has OLE
// support and its vtables carry the OLE-gated CCmdTarget slots (see ImperialismApp).
class CMainFrameRefTarget {
public:
  virtual ~CMainFrameRefTarget();
  virtual void ReleaseWithFlag(int freeMemory) = 0;
};

// VTABLE: IMPERIALISM 0x006488d8
class CMainFrame : public CFrameWnd {
public:
  DECLARE_DYNCREATE(CMainFrame)
  DECLARE_MESSAGE_MAP()

public:
  CMainFrame();
  ~CMainFrame() override;

  afx_msg BOOL PreCreateWindow(CREATESTRUCT& cs) override;
  // WinHelp override (vtable slot 0x74): instead of launching help, post a WM_KEYDOWN
  // VK_F1 to the main include-view host window. 0x00485c20.
  void WinHelp(DWORD dwData, UINT nCmd) override; // 0x00485c20
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
  afx_msg void OnPaint();                                                 // 0x00485bd0
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);             // 0x00485c00
  afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized); // 0x00485c60
  // ON_WM_ACTIVATEAPP: when the app loses activation and isn't already minimized, park
  // the (fullscreen) frame off-screen minimized. 0x00485c90.
  afx_msg void OnActivateApp(BOOL bActive, DWORD dwThreadID);
  // ON_COMMAND(0x800D): forward through the UI runtime context's slot 0x19 (byte 0x64).
  // 0x00485590.
  afx_msg void OnCommand800D();
  // ON_WM_ERASEBKGND: when field_C0 is the tiled-backdrop sentinel, lazily load the
  // backdrop CDib and tile it 128x128 across the client area; otherwise realize the
  // default palette and solid-fill with field_C0. 0x004859d0.
  afx_msg BOOL OnEraseBkgnd(CDC* pDC);
  // ON_MESSAGE(0xBC0): validate then execute a queued UI command object carried in
  // lParam (posted by TApplication::DispatchQueuedUiCommandAndRelease). 0x00485960.
  afx_msg LRESULT OnMsg0BC0(WPARAM wParam, LPARAM lParam);

  void ConfigureTopLevelWindowStyleAndPlacement(int width, int height);
  int SetFieldC0AndInvalidateWindowIfChanged(int styleValue); // 0x00485990

  CDibPal* field_BC;
  int field_C0;
  CDib* field_C4; // backdrop DIB (tiled-background path of OnEraseBkgnd)
  int field_CC;

  // Original object size is 0xd0 (CRuntimeClass m_nObjectSize); the source class ended at 0xcc. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int fieldcc;
};
