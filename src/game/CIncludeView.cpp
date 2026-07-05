#include "game/CIncludeView.h"

#include "game/TAmbitApplication.h"
#include "game/TView.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

// The 17ms UI tick (timer id 0xd00d, armed in OnInitialUpdate): track the cursor in
// client coordinates and, while the main frame is the foreground window, feed the
// position into the global UI root's per-tick cursor dispatch (edge auto-scroll etc.).
// FUNCTION: IMPERIALISM 0x00482760
static void CALLBACK UiCursorTickTimerProc(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime) {
  (void)uMsg;
  (void)idEvent;
  (void)dwTime;
  POINT cursorPos;
  GetCursorPos(&cursorPos);
  ScreenToClient(hWnd, &cursorPos);
  if (g_pGlobalUiRootController != 0) {
    CWnd* foreground = CWnd::FromHandle(GetForegroundWindow());
    CWnd* mainWnd = (AfxGetThread() != 0) ? AfxGetThread()->GetMainWnd() : 0;
    if (foreground == mainWnd) {
      static_cast<TAmbitApplication*>(g_pGlobalUiRootController)
          ->HandleCursor(cursorPos.x, cursorPos.y, 0);
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x00482850
// CIncludeView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00482930
// CIncludeView::GetRuntimeClass

IMPLEMENT_DYNCREATE(CIncludeView, CView)

// Original AFX_MSGMAP_ENTRY order (entries @ 0x6489e8). Still unported:
// WM_LBUTTONDOWN 0x4839e0, WM_LBUTTONUP 0x483b00, WM_MOUSEMOVE 0x4838b0,
// WM_LBUTTONDBLCLK 0x483b70, WM_COMMAND id 0x8011/0x8012 0x483d60/0x483d90,
// WM_SETCURSOR 0x483ef0, WM_RBUTTONDOWN 0x483f10, WM_RBUTTONUP 0x483ff0,
// WM_CHAR 0x4840b0, WM_PARENTNOTIFY 0x484190, WM_CTLCOLOR 0x483660,
// WM_KEYDOWN 0x484260, and message 0x4c8 0x484230 (turn-state exit; blocked on
// porting TViewMgr::HandleTurnStateExitAndPostFollowupEventCode 0x5db620).
BEGIN_MESSAGE_MAP(CIncludeView, CView)
ON_WM_ERASEBKGND()
ON_MESSAGE(0x4ef, OnDialogTreeHostMsg4EF)
END_MESSAGE_MAP()

CIncludeView::CIncludeView() : CView() {}

// FUNCTION: IMPERIALISM 0x00482bf0
LRESULT CIncludeView::OnDialogTreeHostMsg4EF(WPARAM wParam, LPARAM lParam) {
  (void)lParam;
  switch (wParam & 0xff) {
  case 0:
    if (g_nIncludeViewAssertGate_006A17B0 == 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szIncludeViewSourcePath_00694D10, 0x77);
    }
    m_activeDialogContext = 0;
    m_field44 = 0;
    break;
  case 1:
    m_activeDialogContext->PropagateUiResourceContextRecursive(this);
    m_activeDialogContext->ResolveControlByTag(0x6d61696e); // 'main'
    break;
  default:
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szIncludeViewSourcePath_00694D10, 0x84);
    break;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00482c90
void CIncludeView::OnDraw(CDC* pDC) {
  RECT clipBox;
  pDC->GetClipBox(&clipBox);
  if (m_activeDialogContext != 0) {
    if (GetMcAppUiActiveFlag() != 0) {
      RECT paintRect;
      CopyRect(&paintRect, &clipBox);
      m_activeDialogContext->PaintVisibleChildrenIntersectingClipRect(&paintRect, pDC);
    }
  }
}

// Install this view as the native host window for the given TView (and its whole
// subtree), then let it resolve the 'main' control tag against itself.
// FUNCTION: IMPERIALISM 0x00483340
void CIncludeView::SetUiRuntimeContextAndActivateMain(TView* activeDialog) {
  m_activeDialogContext = activeDialog;
  m_activeDialogContext->PropagateUiResourceContextRecursive(this);
  m_activeDialogContext->ResolveControlByTag(0x6d61696e); // 'main'
}

// The original computes the clip box and client rect but uses neither; returning
// nonzero suppresses the default background erase (the tree repaints every pixel).
// FUNCTION: IMPERIALISM 0x004835a0
BOOL CIncludeView::OnEraseBkgnd(CDC* pDC) {
  RECT clipBox;
  pDC->GetClipBox(&clipBox);
  RECT clientRect;
  GetClientRect(&clientRect);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00483720
void CIncludeView::OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView) {
  CView::OnActivateView(bActivate, pActivateView, pDeactiveView);
}

// First-update hookup for the main-screen host: (re)create the 640x480x8 offscreen
// CDib, realize its DIB section against the window DC, size the view to 640x480, arm
// the 17ms cursor-tick timer, and force a full OnUpdate repaint.
// FUNCTION: IMPERIALISM 0x00483750
void CIncludeView::OnInitialUpdate() {
  if (m_pOffscreenDib != 0) {
    delete m_pOffscreenDib;
  }
  m_pOffscreenDib = new CDib(0x280, 0x1e0, 8);
  HDC hdc = ::GetDC(m_hWnd);
  CDC* dc = CDC::FromHandle(hdc);
  m_pOffscreenDib->EnsureDibSectionCreated(dc);
  ::ReleaseDC(m_hWnd, dc->m_hDC);
  CWnd* mainWnd = (AfxGetThread() != 0) ? AfxGetThread()->GetMainWnd() : 0;
  mainWnd->SetWindowPos(0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER);
  SetWindowPos(0, 0, 0, 0x280, 0x1e0, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (m_tickTimerId == 0) {
    m_tickTimerId = ::SetTimer(m_hWnd, 0xd00d, 0x11, UiCursorTickTimerProc);
  }
  OnUpdate(0, 0, 0);
}

// Everything the hosted activeDialog TView tree ever draws on screen flows through
// here (CView::OnPaint -> OnDraw): clip box -> slot-0x43 paint recursion, gated on the
// global UI-active flag (deliberately 0 while a dialog factory body runs).
// FUNCTION: IMPERIALISM 0x00484060
int CIncludeView::GetUiInteractiveFlag90() {
  return m_uiInteractiveFlag90;
}
