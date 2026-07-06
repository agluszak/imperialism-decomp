#pragma once

#include "game/CDib.h"
#include "game/mfc.h"

class TControl;
class TView;

// MFC view class for the SDI doc template (CRuntimeClass @ 0x006481c8, m_lpszClassName
// CIncludeView, m_nObjectSize 0x94). Not TIncludeView @ 0x6495d0 (game UI hierarchy).
//
// This is the real receiver of ImperialismApp::InitInstance's post-startup hookup: it is
// CFrameWnd::m_pViewActive for the SDI main frame, so it is what
// GetMainViewHostFromActiveThread() (0x00412a70) actually returns — not a TView.
//
// It is also the main-screen paint host (bd 1uj.10): the whole activeDialog TView tree's
// nativeWindow50 is this view (propagated by SetUiRuntimeContextAndActivateMain at init
// and re-propagated by the 0x4ef message handler after each turn-event dialog factory
// runs), and every on-screen paint of that tree flows through OnDraw's slot-0x43
// PaintVisibleChildrenIntersectingClipRect recursion.
class CIncludeView : public CView {
public:
  DECLARE_DYNCREATE(CIncludeView)

  CIncludeView();

  void SetUiRuntimeContextAndActivateMain(TView* activeDialog); // 0x00483340

protected:
  void OnInitialUpdate() override; // 0x00483750
  void OnActivateView(BOOL bActivate, CView* pActivateView,
                      CView* pDeactiveView) override; // 0x00483720
  void OnDraw(CDC* pDC) override;                     // 0x00482c90

  afx_msg BOOL OnEraseBkgnd(CDC* pDC); // 0x004835a0
  // Custom message 0x4ef from TIncludeView::NoOpUiLifecycleHook / turn-event rebuilds:
  // wParam 1 = re-propagate this view as the tree's native window and re-resolve 'main';
  // wParam 0 = detach the dialog context (one-shot assert if the gate flag is clear).
  afx_msg LRESULT OnDialogTreeHostMsg4EF(WPARAM wParam, LPARAM lParam); // 0x00482bf0
  // WM_LBUTTONDOWN: forward the click into the dialog tree (skips a playing movie). 0x004839e0
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point); // 0x004839e0
  // WM_LBUTTONUP: complete the click — slot-0x48 mouse-up dispatch into the dialog tree,
  // then end the global mouse capture. 0x00483b00
  afx_msg void OnLButtonUp(UINT nFlags, CPoint point); // 0x00483b00
  // WM_MOUSEMOVE: update the global capture drag state, drive this view's own captured
  // control (m_capturedControl74 + the +0x78 point triple), feed the cursor to the UI
  // root controller, and (while the app is active) run the dialog tree's hover
  // hit-test. 0x004838b0
  afx_msg void OnMouseMove(UINT nFlags, CPoint point); // 0x004838b0
  // WM_PARENTNOTIFY: a click landed on a native child window (e.g. the movie MCIWnd) —
  // replay it as a full down+up click into the dialog tree. 0x00484190
  afx_msg void OnParentNotify(UINT message, LPARAM lParam); // 0x00484190
  // WM_KEYDOWN: translate the keystroke into the shared UI command event and forward it
  // into the active window's TView tree (via ForwardParam). This is the entry point that
  // lets ESC/Space/Enter reach TGameWindow::ForwardParam, e.g. to skip a playing movie.
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags); // 0x00484260
  // WM_CHAR: no game handling (defers to DefWindowProc), matching the original.
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags); // 0x004840b0
  // MCIWNDM_NOTIFYMODE (0x4c8): when the movie MCIWnd reports MCI_MODE_STOP (whether it
  // ended on its own or was stopped/skipped), advance the turn state (post the followup
  // event code and clear the active movie view).
  afx_msg LRESULT OnMciNotifyMode(WPARAM wParam, LPARAM mciMode); // 0x00484230
  DECLARE_MESSAGE_MAP()

public:
  TView* m_activeDialogContext; // 0x40 — g_pDisplayMgr->activeDialog tree hosted here
  int m_field44;                // 0x44 — cleared together with the context by msg 0x4ef
  CDib* m_pOffscreenDib;        // 0x48 — 640x480x8 surface created in OnInitialUpdate
  unsigned char pad4c[0x6c - 0x4c];
  UINT m_tickTimerId; // 0x6c — 17ms UI tick timer (id 0xd00d) driving cursor dispatch
  unsigned char pad70[4];
  // 0x74 — this view's own captured-control track (a second copy of the
  // TMouseCaptureState shape: control + start/last/current points). OnMouseMove sends
  // it the state-1 drag command through TControl slots 0x67/0x68; the writer that arms
  // it is not yet located.
  TControl* m_capturedControl74;
  CPoint m_captureStartPoint78;   // 0x78
  CPoint m_captureLastPoint80;    // 0x80
  CPoint m_captureCurrentPoint88; // 0x88
  // 0x90 — nonzero while the UI is interactive; TApplication::InModalState (0x486960)
  // reports TRUE while it is 0. Writer not yet located.
  int m_uiInteractiveFlag90;

  int GetUiInteractiveFlag90(); // 0x00484060
};

ASSERT_SIZE(CIncludeView, 0x94);
