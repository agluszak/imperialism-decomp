#pragma once

#include "game/CDib.h"
#include <afxtempl.h>

#include "game/mfc.h"

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
};
ASSERT_SIZE(IncludeViewOverlayRectRecord, 0x18);

class CIncludeView : public CView {
public:
  DECLARE_DYNCREATE(CIncludeView)

  CIncludeView();
  virtual ~CIncludeView(); // 0x00482ab0 (scalar deleting destructor 0x4829c0)

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
  // 0x4c — overlay dirty-rect queue. The original emitted the CList<Rec,Rec&>
  // instantiation twice (ctor TU vtable 0x648560, dtor/Serialize TU vtable 0x648578) —
  // the twin-copy template pattern; both are the same class.
  CList<IncludeViewOverlayRectRecord, IncludeViewOverlayRectRecord&> m_overlayRectQueue;
  POSITION m_overlayRectCursor68; // 0x68 — iteration cursor of the repaint pass (0x482fc0)
  UINT m_tickTimerId;             // 0x6c — 17ms UI tick timer (id 0xd00d) driving cursor dispatch
  int m_field70;                  // 0x70 — zeroed in the ctor
  // 0x74 — pointer-update receiver: OnMouseMove (0x4838b0) forwards cursor updates into
  // this view via the slot 0x67/0x68 virtuals.
  TView* m_pointerDispatchView74;
  unsigned char pad78[0x90 - 0x78];
  // 0x90 — nonzero while the UI is interactive; TApplication::InModalState (0x486960)
  // reports TRUE while it is 0. Writer not yet located.
  int m_uiInteractiveFlag90;

  int GetUiInteractiveFlag90(); // 0x00484060
};

ASSERT_SIZE(CIncludeView, 0x94);
