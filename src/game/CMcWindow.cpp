#include "game/CMcWindow.h"

#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(CMcWindow, CWnd)

// Original AFX_MSGMAP_ENTRY order (0x0064b5f0). WM_LBUTTONUP, WM_MOUSEMOVE,
// WM_CTLCOLOR, WM_CHAR and message 0x36a are still unported (see CMcWindow.h).
BEGIN_MESSAGE_MAP(CMcWindow, CWnd)
ON_WM_PAINT()
ON_WM_LBUTTONDOWN()
ON_WM_CLOSE()
ON_WM_KEYDOWN()
ON_WM_KEYUP()
ON_WM_QUERYNEWPALETTE()
ON_WM_PALETTECHANGED()
ON_MESSAGE(0x468, OnWindowStateMsg468)
END_MESSAGE_MAP()

// Build the host window for a TWindow descriptor: construct the CWnd base, record the
// owner backref, derive the CreateEx window style from the descriptor's type code, then
// create and bring up the window via the real MFC CWnd surface. (The original also fires
// one-shot debug asserts for unrecognized type codes; those validation-only calls are
// omitted here.)
// FUNCTION: IMPERIALISM 0x00493470
CMcWindow::CMcWindow(TWindow* descriptor) : CWnd() {
  m_pOwnerWindow = descriptor;

  DWORD dwExStyle = 0;
  DWORD dwStyle = (descriptor->windowStyleType != 0) ? 0x44020000 : 0x44000000;
  int typeCode = static_cast<int>(descriptor->windowStyleType) & ~0x8;
  switch (typeCode) {
  case 0x00:
    dwStyle |= 0x00fc0000;
    dwExStyle = 0x80;
    break;
  case 0x01:
    dwStyle |= 0x00400000;
    break;
  case 0x02:
    break;
  case 0x03:
    dwStyle |= 0x00800000;
    break;
  case 0x04:
    dwStyle |= 0x00c80000;
    dwExStyle = 0x80;
    break;
  case 0x05:
    dwStyle |= 0x00cc0000;
    break;
  case 0x30:
  case 0x1f40:
    dwExStyle = 0x80;
    if (descriptor->field6d == 0) {
      dwStyle |= 0x80c00000;
    } else {
      dwStyle |= 0x00c80000;
    }
    break;
  default:
    // Other type codes (0x10, 0x7c3, ...) add no style bits; the original only
    // validates them with debug asserts.
    break;
  }
  if (descriptor->field70 != 0) {
    dwExStyle |= 0x8; // WS_EX_TOPMOST
  }

  CRect rect;
  rect.left = descriptor->ownerOffsetX;
  rect.top = descriptor->ownerOffsetY;
  rect.right = rect.left + descriptor->field34;
  rect.bottom = rect.top + descriptor->field38;
  ::AdjustWindowRectEx(&rect, dwStyle, FALSE, dwExStyle);

  CWnd* mainWnd = AfxGetMainWnd();
  HWND parent = (mainWnd != NULL) ? mainWnd->m_hWnd : NULL;
  CreateEx(dwExStyle, NULL, NULL, dwStyle, rect.left, rect.top, rect.Width(), rect.Height(), parent,
           NULL, NULL);
  SetWindowPos(&CWnd::wndTop, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
  BringWindowToTop();
}

// Window-state command from the owning TWindow layer: wParam 2 = show, 3 = hide,
// 4 = destroy the native window and delete this host object; 0/1 (sent by
// TWindow::DispatchSlot9CToLinkedChildren / CallVoidSlotA0 with the control tag in
// lParam) are accepted no-ops. Unknown codes fire the McWindow.cpp:184 one-shot assert.
// FUNCTION: IMPERIALISM 0x00493800
LRESULT CMcWindow::OnWindowStateMsg468(WPARAM wParam, LPARAM lParam) {
  (void)lParam;
  switch (wParam & 0xff) {
  case 0:
  case 1:
    break;
  case 2:
    ShowWindow(SW_SHOW);
    break;
  case 3:
    ShowWindow(SW_HIDE);
    break;
  case 4:
    DestroyWindow();
    m_pOwnerWindow = NULL;
    delete this;
    break;
  default:
    if (g_nMcWindowStateMsgAssertGate_006A1C74 == 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcWindowSourcePath_006950D8, 0xb8);
    }
    break;
  }
  return 0;
}

// Paint dispatch for the hosted TView tree: everything a TWindow-rooted control tree
// ever draws on screen flows through here. Clip-box → owner TWindow's
// PaintVisibleChildrenIntersectingClipRect (TView slot 0x43) with the CPaintDC, which
// BindScopedMapQuickDrawDcHandle then binds as the active QuickDraw DC.
// FUNCTION: IMPERIALISM 0x004938c0
void CMcWindow::OnPaint() {
  CPaintDC dc(this);
  RECT clipBox;
  dc.GetClipBox(&clipBox);
  if (m_pOwnerWindow != NULL) {
    RECT paintRect;
    CopyRect(&paintRect, &clipBox);
    m_pOwnerWindow->PaintVisibleChildrenIntersectingClipRect(&paintRect, &dc);
  }
}

// Let default processing run, raise this window, then forward the point to the owner
// tree's slot-0x46 mouse dispatch. (nFlags is unused; the owner pointer is not
// null-checked in the original either.)
// FUNCTION: IMPERIALISM 0x00493990
void CMcWindow::OnLButtonDown(UINT nFlags, CPoint point) {
  (void)nFlags;
  Default();
  ::BringWindowToTop(m_hWnd);
  CPoint pt(point);
  m_pOwnerWindow->DispatchUiMouseMoveToChildren(&pt, 0, 0, 0);
}

// Close request: run default processing, then forward to the owning TWindow's
// slot-0x74 close chain; the native window itself is not destroyed here (the owner
// layer decides).
// FUNCTION: IMPERIALISM 0x00493b00
void CMcWindow::OnClose() {
  Default();
  if (m_pOwnerWindow != NULL) {
    m_pOwnerWindow->OrphanCallChain_C2_I10_0048e120();
  }
}

// Deliberately empty: suppresses default WM_KEYDOWN processing (no Default() call).
// FUNCTION: IMPERIALISM 0x00493b30
void CMcWindow::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags) {
  (void)nChar;
  (void)nRepCnt;
  (void)nFlags;
}

// FUNCTION: IMPERIALISM 0x00493b50
void CMcWindow::OnKeyUp(UINT nChar, UINT nRepCnt, UINT nFlags) {
  (void)nChar;
  (void)nRepCnt;
  (void)nFlags;
  Default();
}

// FUNCTION: IMPERIALISM 0x00493ca0
BOOL CMcWindow::OnQueryNewPalette() {
  return static_cast<BOOL>(Default());
}

// FUNCTION: IMPERIALISM 0x00493cc0
void CMcWindow::OnPaletteChanged(CWnd* pFocusWnd) {
  (void)pFocusWnd;
  Default();
}
