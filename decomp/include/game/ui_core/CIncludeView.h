#pragma once

#include "game/gfx/CDib.h"
#include "game/ui_tags_common.h"
#include <afxtempl.h>

#include "game/mfc.h"

class TControl;
class TView;

struct IncludeViewOverlayRectRecord {
  RECT rect;         // +0x00 — client-area rect awaiting repaint
  int processedFlag; // +0x10 — set once the repaint pass has consumed the rect
  int field14;

  CPoint ComputeSpan() const; // 0x00483220
};
ASSERT_SIZE(IncludeViewOverlayRectRecord, 0x18);

class CIncludeViewOverlayRectQueue {
public:
  CList<IncludeViewOverlayRectRecord, IncludeViewOverlayRectRecord&> records;
  POSITION cursor;
  void AddHead(RECT* rect, int processedFlag, int field14); // 0x00483ba0
  IncludeViewOverlayRectRecord* UpdateNextRecordProcessedFlagFromCursor(int matchFlag, int newFlag);
};
ASSERT_SIZE(CIncludeViewOverlayRectQueue, 0x20);

// VTABLE: IMPERIALISM 0x00648418
class CIncludeView : public CView {
public:
  DECLARE_DYNCREATE(CIncludeView)

  CIncludeView();
  virtual ~CIncludeView() override; // 0x00482ab0 (scalar deleting destructor 0x4829c0)

  void SetUiRuntimeContextAndActivateMain(TView* activeDialog); // 0x00483340
  void RefreshActiveDialogHost(int unusedArg);                  // 0x00483380
  void TearDownActiveDialogContext();                           // 0x00483530

protected:
  BOOL PreCreateWindow(CREATESTRUCT& cs) override;                     // 0x00483db0
  BOOL OnCommand(WPARAM wParam, LPARAM lParam) override;               // 0x00483e80
  void CalcWindowRect(LPRECT lpClientRect, UINT nAdjustType) override; // 0x004840d0
  void OnInitialUpdate() override;                                     // 0x00483750
  void OnActivateView(BOOL bActivate, CView* pActivateView,
                      CView* pDeactiveView) override; // 0x00483720
  void OnDraw(CDC* pDC) override;                     // 0x00482c90

  void BlitMapDialogSurfaceToHdcWithClipBounds(CDC* dc, RECT* clipRect);

  void UpdateAndRenderMapTileHintOverlayQueue(CDC* dc, RECT* clipRect);

  afx_msg BOOL OnEraseBkgnd(CDC* pDC); // 0x004835a0
  void BlitMainPaneBitmapRectToWindow(RECT* rect);
  afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);      // 0x00483660
  afx_msg LRESULT OnDialogTreeHostMsg4EF(WPARAM wParam, LPARAM lParam); // 0x00482bf0
#ifdef IMPERIALISM_RUNTIME_TESTS
  afx_msg LRESULT OnRuntimeAction(WPARAM wParam, LPARAM lParam);
#endif
  // WM_LBUTTONDOWN: forward the click into the dialog tree (skips a playing movie). 0x004839e0
  afx_msg void OnLButtonDown(UINT nFlags, CPoint point); // 0x004839e0
  afx_msg void OnLButtonUp(UINT nFlags, CPoint point);   // 0x00483b00
  // WM_LBUTTONDBLCLK: let MFC default-route the message only while UI input is enabled.
  afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point); // 0x00483b70
  // Private frame commands used to refresh the wait cursor and force an immediate repaint.
  afx_msg void OnDumpViewHierarchy(); // 0x00483d60
  afx_msg void OnRefresh();           // 0x00483d90
  // WM_SETCURSOR is deliberately left to the MFC default dispatcher.
  afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message); // 0x00483ef0
  afx_msg void OnRButtonDown(UINT nFlags, CPoint point);             // 0x00483f10
  afx_msg void OnRButtonUp(UINT nFlags, CPoint point);               // 0x00483ff0
  afx_msg void OnMouseMove(UINT nFlags, CPoint point);               // 0x004838b0
  afx_msg void OnParentNotify(UINT message, LPARAM lParam);          // 0x00484190
  afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);     // 0x00484260
  // WM_CHAR: no game handling (defers to DefWindowProc), matching the original.
  afx_msg void OnChar(UINT nChar, UINT nRepCnt, UINT nFlags);     // 0x004840b0
  afx_msg LRESULT OnMciNotifyMode(WPARAM wParam, LPARAM mciMode); // 0x00484230
  DECLARE_MESSAGE_MAP()

public:
  void BlitMainPaneBitmapToOffscreenClipped(RECT* clipRect);
  void QueueOrMergeOverlayDirtyRect(RECT* rect, int processedFlag, int field14); // 0x482f70

  TView* ReinitializeIncludeViewMainPaneAndRedrawWindow(int unusedArg);

  TView* m_activeDialogContext; // 0x40 — g_pDisplayMgr->activeDialog tree hosted here
  CDib* m_pMainPaneDib;
  CDib* m_pOffscreenDib; // 0x48 — 640x480x8 surface created in OnInitialUpdate
  CIncludeViewOverlayRectQueue m_overlayRectQueue;
  UINT m_tickTimerId; // 0x6c — 17ms UI tick timer (id 0xd00d) driving cursor dispatch
  int m_unused70;     // 0x70 — ctor-write only; field-xrefs show no reader
  TControl* m_capturedControl;

  void AssertOverlayQueueGate();

  void BeginTracking(CPoint* startPoint, TControl* tracker);
  CPoint m_captureStartPoint;   // 0x78
  CPoint m_captureLastPoint;    // 0x80
  CPoint m_captureCurrentPoint; // 0x88
  int m_uiInteractiveFlag;

  int GetUiInteractiveFlag90();                 // 0x00484060
  int SetUiInteractiveFlag90(bool interactive); // 0x00484080
};

ASSERT_SIZE(CIncludeView, 0x94);
