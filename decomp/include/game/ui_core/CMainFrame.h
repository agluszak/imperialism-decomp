#pragma once

#include "game/menu_commands.h"
#include "compat.h"

#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"
#include "game/mfc.h"

// SDI main frame created by ProcessShellCommand.

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
  void WinHelp(DWORD dwData, UINT nCmd) override;
  afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
  // ON_COMMAND(100): the startup command InitInstance posts once the frame is up.
  afx_msg void OnStartupCommand100();
  // ON_MESSAGE(0x464): same handling as command 100, LRESULT-shaped.
  afx_msg LRESULT OnMsg0464(WPARAM wParam, LPARAM lParam);
  afx_msg void OnPaletteChanged(CWnd* pFocusWnd);
  afx_msg BOOL OnQueryNewPalette();
  CDibPal* ReplacePaletteAndRealize(CDibPal* palette);
  afx_msg LRESULT OnTurnEventCodeMessage(WPARAM wParam, LPARAM lParam);
  afx_msg void OnResetPalette();
  afx_msg void OnWarpToScreen();
  afx_msg void OnConductDiplomacy();
  afx_msg void OnPaint();
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized);
  afx_msg void OnActivateApp(BOOL bActive, DWORD dwThreadID);
  afx_msg void OnShowDealBook();
  afx_msg BOOL OnEraseBkgnd(CDC* pDC);
  afx_msg LRESULT OnMsg0BC0(WPARAM wParam, LPARAM lParam);

  void ConfigureFrameWindow(int width, int height);
  // Returns the previous colour; repaints only on an actual change.
  COLORREF SetBackgroundColorAndInvalidate(COLORREF color);

  CDibPal* m_pDibPalette;
  COLORREF m_backgroundColor;
  CDib* m_pBackdropDib; // tiled OnEraseBkgnd background
  int field_C8;
  int field_CC;
};
ASSERT_SIZE(CMainFrame, 0xd0);
