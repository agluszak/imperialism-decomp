#pragma once

#include "game/gfx/CDib.h"
#include "game/ui_tags_common.h"
#include <afxtempl.h>

#include "game/mfc.h"

class TControl;
class TView;

struct IncludeViewOverlayRectRecord {
  RECT rect;         // client-area rect awaiting repaint
  int processedFlag; // set once the repaint pass has consumed the rect
  int field14;

  CPoint ComputeSpan() const;
};
ASSERT_SIZE(IncludeViewOverlayRectRecord, 0x18);

class CIncludeViewOverlayRectQueue {
public:
  CList<IncludeViewOverlayRectRecord, IncludeViewOverlayRectRecord&> records;
  POSITION cursor;
  void AddHead(RECT* rect, int processedFlag, int field14);
  IncludeViewOverlayRectRecord* UpdateNextRecordProcessedFlagFromCursor(int matchFlag, int newFlag);
};
ASSERT_SIZE(CIncludeViewOverlayRectQueue, 0x20);

// VTABLE: IMPERIALISM 0x00648418
class CIncludeView : public CView {
public:
  DECLARE_DYNCREATE(CIncludeView)

  CIncludeView();
  virtual ~CIncludeView() override;

  void SetUiRuntimeContextAndActivateMain(TView* activeDialog);
  void RefreshActiveDialogHost(int unusedArg);
  void TearDownActiveDialogContext();

protected:
  BOOL PreCreateWindow(CREATESTRUCT& cs) override;
  BOOL OnCommand(WPARAM wParam, LPARAM lParam) override;
  void CalcWindowRect(LPRECT lpClientRect, UINT nAdjustType) override;
  void OnInitialUpdate() override;
  void OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView) override;
  void OnDraw(CDC* pDC) override;

  void BlitMapDialogSurfaceToHdcWithClipBounds(CDC* dc, RECT* clipRect);

  void UpdateAndRenderMapTileHintOverlayQueue(CDC* dc, RECT* clipRect);

  afx_msg BOOL OnEraseBkgnd(CDC* pDC);
  void BlitMainPaneBitmapRectToWindow(RECT* rect);
  afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
  afx_msg LRESULT OnDialogTreeHostMsg4EF(WPARAM wParam, LPARAM lParam);
#ifdef IMPERIALISM_RUNTIME_TESTS
  afx_msg LRESULT OnRuntimeAction(WPARAM wParam, LPARAM lParam);
#endif
  // WM_LBUTTONDOWN: forward the click into the dialog tree (skips a playing movie)
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
  afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
  // WM_LBUTTONDBLCLK: let MFC default-route the message only while UI input is enabled.
  afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point);
  // Private frame commands used to refresh the wait cursor and force an immediate repaint.
  afx_msg void OnDumpViewHierarchy();
  afx_msg void OnRefresh();
  // WM_SETCURSOR is deliberately left to the MFC default dispatcher.
  afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
  afx_msg void OnRButtonDown(UINT nFlags, CPoint point);
  afx_msg void OnRButtonUp(UINT nFlags, CPoint point);
  afx_msg void OnMouseMove(UINT nFlags, CPoint point);
  afx_msg void OnParentNotify(UINT message, LPARAM lParam);
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
  // WM_CHAR: no game handling (defers to DefWindowProc), matching the original.
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);
  afx_msg LRESULT OnMciNotifyMode(WPARAM wParam, LPARAM mciMode);
  DECLARE_MESSAGE_MAP()

public:
  void BlitMainPaneBitmapToOffscreenClipped(RECT* clipRect);
  void QueueOrMergeOverlayDirtyRect(RECT* rect, int processedFlag, int field14);

  TView* ResetMainPane(int unusedArg);

  TView* m_activeDialogContext; // g_pDisplayMgr->activeDialog tree hosted here
  CDib* m_pMainPaneDib;
  CDib* m_pOffscreenDib; // 640x480x8 surface created in OnInitialUpdate
  CIncludeViewOverlayRectQueue m_overlayRectQueue;
  UINT m_tickTimerId; // 17ms UI tick timer (id 0xd00d) driving cursor dispatch
  int m_unused70;     // ctor-write only; field-xrefs show no reader
  TControl* m_capturedControl;

  void AssertOverlayQueueGate();

  void BeginTracking(CPoint* startPoint, TControl* tracker);
  CPoint m_captureStartPoint;
  CPoint m_captureLastPoint;
  CPoint m_captureCurrentPoint;
  int m_uiInteractiveFlag;

  int GetUiInteractiveFlag();
  int SetUiInteractiveFlag(bool interactive);
};

ASSERT_SIZE(CIncludeView, 0x94);
