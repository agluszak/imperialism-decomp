#pragma once

#include "game/CDib.h"
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
  DECLARE_MESSAGE_MAP()

public:
  TView* m_activeDialogContext; // 0x40 — g_pDisplayMgr->activeDialog tree hosted here
  int m_field44;                // 0x44 — cleared together with the context by msg 0x4ef
  CDib* m_pOffscreenDib;        // 0x48 — 640x480x8 surface created in OnInitialUpdate
  unsigned char pad4c[0x6c - 0x4c];
  UINT m_tickTimerId; // 0x6c — 17ms UI tick timer (id 0xd00d) driving cursor dispatch
  unsigned char pad70[0x94 - 0x70];
};

ASSERT_SIZE(CIncludeView, 0x94);
