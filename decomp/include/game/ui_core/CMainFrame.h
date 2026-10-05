#pragma once

#include "game/menu_commands.h"
#include "compat.h"

#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"
#include "game/mfc.h"

// SDI main frame for ProcessShellCommand (CRuntimeClass @ 0x00648628, m_lpszClassName
// "CMainFrame").
// No // VTABLE: annotation yet — the CObject->CCmdTarget->CFrameWnd LIBRARY per-slot pass
// (the CDialog-vtable pattern) has not been run for this class, so its shared trivial MFC
// stubs still pair ambiguously. This is NOT an OLE divergence: the game's MFC has OLE
// support and its vtables carry the OLE-gated CCmdTarget slots (see ImperialismApp).

const COLORREF kTiledBackdropSentinelColor = PALETTEINDEX(0x5f);

// VTABLE: IMPERIALISM 0x006488d8
class CMainFrame : public CFrameWnd {
public:
  DECLARE_DYNCREATE(CMainFrame)
  DECLARE_MESSAGE_MAP()

public:
  CMainFrame();
  ~CMainFrame() override;

  afx_msg BOOL PreCreateWindow(CREATESTRUCT& cs) override;
  void WinHelp(DWORD dwData, UINT nCmd) override; // 0x00485c20
  afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
  // ON_COMMAND(100): the startup command InitInstance posts once the frame is up.
  afx_msg void OnStartupCommand100(); // 0x00484fd0
  // ON_MESSAGE(0x464): same handling as command 100, LRESULT-shaped.
  afx_msg LRESULT OnMsg0464(WPARAM wParam, LPARAM lParam); // 0x00484fb0
  afx_msg void OnPaletteChanged(CWnd* pFocusWnd);
  afx_msg BOOL OnQueryNewPalette();                    // 0x00484ff0
  CDibPal* ReplacePaletteAndRealize(CDibPal* palette); // 0x00485150
  afx_msg LRESULT OnTurnEventCodeMessage(WPARAM wParam, LPARAM lParam);
  afx_msg void OnResetPalette();
  afx_msg void OnWarpToScreen();
  afx_msg void OnConductDiplomacy();                                           // 0x004855b0
  afx_msg void OnPaint();                                                 // 0x00485bd0
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);             // 0x00485c00
  afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized); // 0x00485c60
  afx_msg void OnActivateApp(BOOL bActive, DWORD dwThreadID);
  afx_msg void OnShowDealBook();
  afx_msg BOOL OnEraseBkgnd(CDC* pDC);
  afx_msg LRESULT OnMsg0BC0(WPARAM wParam, LPARAM lParam);

  void ConfigureTopLevelWindowStyleAndPlacement(int width, int height);
  // Returns the previous colour; repaints only on an actual change. 0x00485990.
  COLORREF SetBackgroundColorAndInvalidate(COLORREF color);

  CDibPal* field_BC;
  COLORREF m_backgroundColor;
  CDib* field_C4; // 0xc4 — backdrop DIB (tiled-background path of OnEraseBkgnd)
  int field_C8;
  int field_CC;
};
ASSERT_SIZE(CMainFrame, 0xd0);
