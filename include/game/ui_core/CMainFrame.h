#pragma once

#include "compat.h"

#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"
#include "game/mfc.h"

// SDI main frame for ProcessShellCommand (CRuntimeClass @ 0x00648628, m_lpszClassName
// "CMainFrame"). Ghidra buckets frame helpers under provisional TMacViewMgr_* labels.
// No // VTABLE: annotation yet — the CObject->CCmdTarget->CFrameWnd LIBRARY per-slot pass
// (the CDialog-vtable pattern) has not been run for this class, so its shared trivial MFC
// stubs still pair ambiguously. This is NOT an OLE divergence: the game's MFC has OLE
// support and its vtables carry the OLE-gated CCmdTarget slots (see ImperialismApp).

// PALETTEINDEX(0x5f). Not a colour anyone wants painted: OnEraseBkgnd treats exactly this
// value as "no solid fill — tile the backdrop DIB", so it is the frame's default and the
// value TMovieView restores when the movie ends.
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
  afx_msg BOOL OnQueryNewPalette();                    // 0x00484ff0
  CDibPal* ReplacePaletteAndRealize(CDibPal* palette); // 0x00485150
  // Message 0x2420 (posted by TApplication::PostTurnEventCodeMessage2420): dispatch the
  // carried turn-event code into the UI runtime with the active nation as payload.
  afx_msg LRESULT HandleCustomMessage2420DispatchTurnEvent(WPARAM wParam, LPARAM lParam);
  afx_msg void OnCommand8009();
  afx_msg void OnCommand800C();
  afx_msg void OnCommand8013();                                           // 0x004855b0
  afx_msg void OnPaint();                                                 // 0x00485bd0
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);             // 0x00485c00
  afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized); // 0x00485c60
  // ON_WM_ACTIVATEAPP: when the app loses activation and isn't already minimized, park
  // the (fullscreen) frame off-screen minimized. 0x00485c90.
  afx_msg void OnActivateApp(BOOL bActive, DWORD dwThreadID);
  // ON_COMMAND(0x800D): forward through the UI runtime context's slot 0x19 (byte 0x64).
  // 0x00485590.
  afx_msg void OnCommand800D();
  // ON_WM_ERASEBKGND: when m_backgroundColor is the tiled-backdrop sentinel, lazily load the
  // backdrop CDib and tile it 128x128 across the client area; otherwise realize the
  // default palette and solid-fill with m_backgroundColor. 0x004859d0.
  afx_msg BOOL OnEraseBkgnd(CDC* pDC);
  // ON_MESSAGE(0xBC0): validate then execute a queued UI command object carried in
  // lParam (posted by TApplication::DispatchQueuedUiCommandAndRelease). 0x00485960.
  afx_msg LRESULT OnMsg0BC0(WPARAM wParam, LPARAM lParam);

  void ConfigureTopLevelWindowStyleAndPlacement(int width, int height);
  // Returns the previous colour; repaints only on an actual change. 0x00485990.
  COLORREF SetBackgroundColorAndInvalidate(COLORREF color);

  CDibPal* field_BC;
  // 0xc0 — the frame's erase-background colour, a palette-relative COLORREF. The ctor
  // installs the PALETTEINDEX(0x5f) sentinel, which OnEraseBkgnd reads as "tile the
  // backdrop DIB instead of solid-filling"; TMovieView swaps in PALETTEINDEX(0) for the
  // duration of a movie and restores the sentinel afterwards.
  COLORREF m_backgroundColor;
  CDib* field_C4; // 0xc4 — backdrop DIB (tiled-background path of OnEraseBkgnd)
  // 0xc8 — not written by the constructor and no reader located yet. It sits where the
  // old `field_CC` was declared; that name was one slot early, which put the ctor's
  // `= 1` store at 0xc8 instead of the 0xcc the original writes (0x00484bfa).
  int field_C8;
  // 0xcc — set to 1 by the ctor and cleared by ConfigureTopLevelWindowStyleAndPlacement
  // (0x00484d80, MOV [ESI+0xcc],EDI) before it strips WS_CAPTION for fullscreen.
  int field_CC;
};
ASSERT_SIZE(CMainFrame, 0xd0);
