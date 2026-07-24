#pragma once

#include "game/gfx/CDib.h"
#include "game/ui_tags_common.h"
#include <afxtempl.h>

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
// 0x18-byte dirty-rect record queued on CIncludeView's overlay repaint list; the list's
// CList<Rec,Rec&>::Serialize moves these raw (POD).
struct IncludeViewOverlayRectRecord {
  RECT rect;           // +0x00 — client-area rect awaiting repaint
  int processedFlag10; // +0x10 — set once the repaint pass has consumed the rect
  int field14;

  // Writes the rect's (width, height) span into `out`. 0x00483220.
  void ComputeSpan(POINT* out) const;
};
ASSERT_SIZE(IncludeViewOverlayRectRecord, 0x18);

// Full 68-slot vtable. The two game overrides (PreCreateWindow 0x64, OnCommand 0x80),
// CalcWindowRect 0x68, OnInitialUpdate/OnActivateView/OnDraw and the message-map handlers
// are modelled here; every inherited CObject/CCmdTarget/CWnd/CView library slot is claimed
// by the reviewed nafxcw identity overrides in config/msvc500_library_overrides.csv (the
// CView-family MFC-vtable pass — GetScrollBarCtrl, PostNcDestroy, the OLE drag-drop /
// scroll / print virtuals, etc.; heuristics note 88).
// VTABLE: IMPERIALISM 0x00648418
class CIncludeView : public CView {
public:
  DECLARE_DYNCREATE(CIncludeView)

  CIncludeView();
  virtual ~CIncludeView() override; // 0x00482ab0 (scalar deleting destructor 0x4829c0)

  void SetUiRuntimeContextAndActivateMain(TView* activeDialog); // 0x00483340

protected:
  // Registers the "AmbitGameWindow" WNDCLASS and pins cs.lpszClass + cs.style before
  // chaining to CView::PreCreateWindow. (vtable slot 0x64.)
  BOOL PreCreateWindow(CREATESTRUCT& cs) override; // 0x00483db0
  // On a custom notify code 0x400, refresh the sending control's owning TView (recovered
  // from its GWL_USERDATA) and reset the hosted dialog tree's input capture, then default.
  // (vtable slot 0x80.)
  BOOL OnCommand(WPARAM wParam, LPARAM lParam) override; // 0x00483e80
  // The layout keystone for the whole main screen: whatever client rect the frame's
  // RecalcLayout/RepositionBars proposes for the leftover pane, reinterpret it as "a
  // 640x480 view centered in that rect" (clamped to the top-left when smaller). This is
  // what keeps the game view centered 640x480 inside the maximized frame — the movie
  // MCIWnd then CenterWindow()s against the same region and every click stays coherent.
  void CalcWindowRect(LPRECT lpClientRect, UINT nAdjustType) override; // 0x004840d0
  void OnInitialUpdate() override;                                     // 0x00483750
  void OnActivateView(BOOL bActivate, CView* pActivateView,
                      CView* pDeactiveView) override; // 0x00483720
  void OnDraw(CDC* pDC) override;                     // 0x00482c90

  // Blit the offscreen map surface (m_field44's bitmap) to `dc` (or a fresh window DC
  // when null), clipped to the intersection of the caller clip / client rect / the
  // offscreen DIB's natural bounds. 0x00482d00.
  void BlitMapDialogSurfaceToHdcWithClipBounds(CDC* dc, RECT* clipRect);

  // Drain the overlay dirty-rect queue in three passes: blit each unprocessed hint rect
  // into the offscreen surface, repaint the hosted dialog tree over it, then flush every
  // finished (flag 2) rect to the screen DC and remove it. 0x00482fc0.
  void UpdateAndRenderMapTileHintOverlayQueue(CDC* dc, RECT* clipRect);

  afx_msg BOOL OnEraseBkgnd(CDC* pDC); // 0x004835a0
  // WM_CTLCOLOR: bind the shared indexed palette for native edit controls and apply the
  // owning TControl's text color while returning the stock hollow brush.
  afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor); // 0x00483660
  // Custom message 0x4ef from TIncludeView::DoPostCreate / turn-event rebuilds:
  // wParam 1 = re-propagate this view as the tree's native window and re-resolve 'main';
  // wParam 0 = detach the dialog context (one-shot assert if the gate flag is clear).
  afx_msg LRESULT OnDialogTreeHostMsg4EF(WPARAM wParam, LPARAM lParam); // 0x00482bf0
  // WM_LBUTTONDOWN: forward the click into the dialog tree (skips a playing movie). 0x004839e0
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point); // 0x004839e0
  // WM_LBUTTONUP: complete the click — slot-0x48 mouse-up dispatch into the dialog tree,
  // then end the global mouse capture. 0x00483b00
  afx_msg void OnLButtonUp(UINT nFlags, CPoint point); // 0x00483b00
  // WM_LBUTTONDBLCLK: let MFC default-route the message only while UI input is enabled.
  afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point); // 0x00483b70
  // Private frame commands used to refresh the wait cursor and force an immediate repaint.
  afx_msg void OnRefreshWaitCursorCommand(); // 0x00483d60, command 0x8011
  afx_msg void OnUpdateWindowCommand();      // 0x00483d90, command 0x8012
  // WM_SETCURSOR is deliberately left to the MFC default dispatcher.
  afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message); // 0x00483ef0
  // WM_RBUTTONDOWN/UP use the same hosted-tree dispatch as the left button. The down
  // event carries mouseButton24=1; the up event closes the shared capture state.
  afx_msg void OnRButtonDown(UINT nFlags, CPoint point); // 0x00483f10
  afx_msg void OnRButtonUp(UINT nFlags, CPoint point);   // 0x00483ff0
  // WM_MOUSEMOVE: update the global capture drag state, drive this view's own captured
  // control (m_capturedControl74 + the +0x78 point triple), feed the cursor to the UI
  // root controller, and (while the app is active) run the dialog tree's hover
  // hit-test. 0x004838b0
  afx_msg void OnMouseMove(UINT nFlags, CPoint point); // 0x004838b0
  // WM_PARENTNOTIFY: a click landed on a native child window (e.g. the movie MCIWnd) —
  // replay it as a full down+up click into the dialog tree. 0x00484190
  afx_msg void OnParentNotify(UINT message, LPARAM lParam); // 0x00484190
  // WM_KEYDOWN: translate the keystroke into the shared UI command event and forward it
  // into the active window's TView tree (via DoKeyEvent). This is the entry point that
  // lets ESC/Space/Enter reach TGameWindow::DoKeyEvent, e.g. to skip a playing movie.
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags); // 0x00484260
  // WM_CHAR: no game handling (defers to DefWindowProc), matching the original.
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags); // 0x004840b0
  // MCIWNDM_NOTIFYMODE (0x4c8): when the movie MCIWnd reports MCI_MODE_STOP (whether it
  // ended on its own or was stopped/skipped), advance the turn state (post the followup
  // event code and clear the active movie view).
  afx_msg LRESULT OnMciNotifyMode(WPARAM wParam, LPARAM mciMode); // 0x00484230
  DECLARE_MESSAGE_MAP()

public:
  // Blit the main-pane bitmap (m_field44) into the offscreen surface, clipped to
  // `clipRect` when one is supplied. 0x00482ed0, __thiscall.
  void BlitMainPaneBitmapToOffscreenClipped(RECT* clipRect);

  // Tear down the hosted dialog tree, re-resolve the 'main' pane picture, blit its bitmap
  // into the offscreen surface and force a full window repaint. Returns the (now cleared)
  // dialog context. One stack argument is accepted and never read. 0x004833b0, __thiscall.
  TView* ReinitializeIncludeViewMainPaneAndRedrawWindow(int unusedArg);

  TView* m_activeDialogContext; // 0x40 — g_pDisplayMgr->activeDialog tree hosted here
  // 0x44 — the offscreen map surface DIB, cleared (to 0) together with the context by
  // msg 0x4ef. Blitted to the window DC by BlitMapDialogSurfaceToHdcWithClipBounds; the
  // writer that installs a live surface here is in still-unported paint setup.
  CDib* m_field44;
  CDib* m_pOffscreenDib; // 0x48 — 640x480x8 surface created in OnInitialUpdate
  // 0x4c — overlay dirty-rect queue. The original emitted the CList<Rec,Rec&>
  // instantiation twice (ctor TU vtable 0x648560, dtor/Serialize TU vtable 0x648578) —
  // the twin-copy template pattern; both are the same class.
  CList<IncludeViewOverlayRectRecord, IncludeViewOverlayRectRecord&> m_overlayRectQueue;
  POSITION m_overlayRectCursor68; // 0x68 — iteration cursor of the repaint pass (0x482fc0)
  UINT m_tickTimerId;             // 0x6c — 17ms UI tick timer (id 0xd00d) driving cursor dispatch
  int m_field70;                  // 0x70 — ctor-zeroed dword, purpose not yet resolved
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

  int GetUiInteractiveFlag90();                          // 0x00484060
  int SetUiInteractiveFlag90(unsigned char interactive); // 0x00484080
};

ASSERT_SIZE(CIncludeView, 0x94);
