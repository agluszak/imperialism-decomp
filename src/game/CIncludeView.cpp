#include "game/CIncludeView.h"

#include "game/CMcWindow.h"
#include "game/TAmbitApplication.h"
#include "game/TControl.h"
#include "game/TEvent.h"
#include "game/TUiEvent.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

// MCIWNDM_NOTIFYMODE / MCI_MODE_STOP for the movie stop-notify handler. NOAVIFILE keeps
// this to the MCIWnd control messages without pulling in the AVIFile COM interfaces.
#define NOAVIFILE
#include <vfw.h>

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

// The shared keyboard command event (original object @ 0x6a1780) lives as a function-local
// static so first use constructs it once; the whole block is forwarded (as an int, == &event)
// into the active TView tree. Layout/type shared with TGameWindow::ForwardParam (which reads
// commandCode/handledMarker) and the not-yet-ported CMcWindow WM_CHAR handler 0x493ce0 via
// game/TUiEvent.h (TKeyCommandEvent).
static void PopulateKeyCommandBlock(TKeyCommandEvent& block, UINT nChar, UINT nRepCnt,
                                    UINT nFlags) {
  block.commandCode = (nChar == VK_F1) ? 0x68 : static_cast<short>(nChar);
  block.keyFlags = static_cast<short>(nFlags & 0xf);
  block.handledMarker = static_cast<short>(nRepCnt);
  unsigned int mods = block.modifierFlags;
  mods = (mods & ~1u) | ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0 ? 1u : 0u);
  mods = (mods & ~2u) | (((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0 ? 1u : 0u) << 1);
  mods = (mods & ~4u) | (((GetAsyncKeyState(VK_MENU) & 0x8000) != 0 ? 1u : 0u) << 2);
  mods = (mods & ~8u) | (((GetAsyncKeyState(VK_RWIN) & 0x8000) != 0 ? 1u : 0u) << 3);
  block.modifierFlags = mods;
}

// Local mouse event the click handlers forward into the dialog tree: a TUiEvent header
// followed by the click coordinates (a separate stack-local instance from the persistent
// keyboard command event above, but the same underlying class @ vtable 0x648590).
struct UiMouseEventBlock {
  TUiEvent event; // 0x00 TEvent-derived header (0x14; installs vtable 0x648590)
  int x;          // 0x14
  int y;          // 0x18
  int pad1c;      // 0x1c
  int pad20;      // 0x20
  int pad24;      // 0x24
};

// Active-window/native-host accessors used by OnKeyDown; defined below in address order
// (their bodies live at 0x48dxxx, past this file's other markers).
static CWnd* GetModalStackTopHostView();
static CWnd* GetLiveRegistryHeadHostView();

// SYNTHETIC: IMPERIALISM 0x00482850
// CIncludeView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00482930
// CIncludeView::GetRuntimeClass

IMPLEMENT_DYNCREATE(CIncludeView, CView)

// Original AFX_MSGMAP_ENTRY order (entries @ 0x6489e8). Still unported:
// WM_LBUTTONDBLCLK 0x483b70, WM_COMMAND id 0x8011/0x8012 0x483d60/0x483d90,
// WM_SETCURSOR 0x483ef0, WM_RBUTTONDOWN 0x483f10, WM_RBUTTONUP 0x483ff0,
// WM_CTLCOLOR 0x483660.
BEGIN_MESSAGE_MAP(CIncludeView, CView)
ON_WM_ERASEBKGND()
ON_WM_LBUTTONDOWN()
ON_WM_LBUTTONUP()
ON_WM_MOUSEMOVE()
ON_WM_PARENTNOTIFY()
ON_WM_KEYDOWN()
ON_WM_CHAR()
ON_MESSAGE(0x4ef, OnDialogTreeHostMsg4EF)
ON_MESSAGE(0x4c8, OnMciNotifyMode) // MCIWNDM_NOTIFYMODE
END_MESSAGE_MAP()

CIncludeView::CIncludeView() : CView() {
  // The original ctor (0x482950) initializes the view's fields, including the interactive
  // flag (offset 0x90 == 1) that gates the click/paren-notify dispatch and the embedded
  // owned-buffer registry at 0x4c (vtable 0x648560). Minimal init for now; full port TODO.
  m_activeDialogContext = 0;
  m_field44 = 0;
  m_pOffscreenDib = 0;
  m_tickTimerId = 0;
  m_uiInteractiveFlag90 = 1;
}

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

// Pointer tracking on the host view: update the global capture drag state, drive this
// view's own captured-control track (the +0x74 control with its +0x78 start/last/current
// point triple, sent the state-1 drag command through TControl slots 0x67/0x68), hand the
// cursor position to the UI root controller, and — while the McApp UI active flag is
// set — run the dialog tree's hover selection hit-test.
// FUNCTION: IMPERIALISM 0x004838b0
void CIncludeView::OnMouseMove(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag90 == 0) {
    return;
  }
  g_McAppMouseCaptureState.NotifyCaptureOwnerState1AndMaybeUpdateCoords(nFlags, point.x, point.y);
  if (m_capturedControl74 != 0) {
    if (g_nIncludeViewPointerAssertGate_006A17C4 == 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szIncludeViewSourcePath_00694D10, 0x2b7);
    }
    CPoint controlRelativePoint(point);
    m_capturedControl74->SubtractPosAndDispatchToOwnerSlot19C(&controlRelativePoint);
    m_captureLastPoint80 = m_captureCurrentPoint88;
    m_captureCurrentPoint88 = controlRelativePoint;
    m_capturedControl74->DispatchPictureResourceCommand(
        1, &m_captureStartPoint78, &m_captureLastPoint80, &m_captureCurrentPoint88);
  }
  static_cast<TAmbitApplication*>(g_pGlobalUiRootController)->HandleCursor(point.x, point.y, 0);
  if (m_activeDialogContext != 0 && GetMcAppUiActiveFlag() != 0) {
    CPoint pt(point);
    m_activeDialogContext->HandleCursorHoverSelectionByChildHitTestAndFallback(&pt, 0);
  }
}

// WM_LBUTTONDOWN: forward the click into the hosted dialog tree as a mouse event
// (TView slot 0x46). For a playing movie this reaches TMovieView::DispatchUiMouseMoveToChildren,
// which stops (skips) the movie. Clicking the view outside the centered movie lands here;
// clicking the movie window itself arrives via OnParentNotify.
// FUNCTION: IMPERIALISM 0x004839e0
void CIncludeView::OnLButtonDown(UINT nFlags, CPoint point) {
  (void)nFlags;
  if (m_uiInteractiveFlag90 != 0 && m_activeDialogContext != 0) {
    UiMouseEventBlock evt;
    evt.x = point.x;
    evt.y = point.y;
    evt.pad1c = 0;
    evt.pad24 = 0;
    m_activeDialogContext->DispatchUiMouseMoveToChildren(&point, reinterpret_cast<int>(&evt), 0, 0);
  }
}

// Complete a click on the host view: forward the point to the dialog tree's slot-0x48
// mouse-up dispatch, then end the global mouse capture. The original reuses the incoming
// point pair as the dispatch buffer.
// FUNCTION: IMPERIALISM 0x00483b00
void CIncludeView::OnLButtonUp(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag90 != 0) {
    if (m_activeDialogContext != 0) {
      CPoint pt(point);
      m_activeDialogContext->DispatchUiMouseEventToChildrenOrSelf_Impl(&pt, 0, 0, 0);
    }
    g_McAppMouseCaptureState.EndMouseCaptureAndStopRepeatTimer(nFlags, point.x, point.y);
  }
}

// Everything the hosted activeDialog TView tree ever draws on screen flows through
// here (CView::OnPaint -> OnDraw): clip box -> slot-0x43 paint recursion, gated on the
// global UI-active flag (deliberately 0 while a dialog factory body runs).
// FUNCTION: IMPERIALISM 0x00484060
int CIncludeView::GetUiInteractiveFlag90() {
  return m_uiInteractiveFlag90;
}

// WM_CHAR: no game handling; defers to DefWindowProc (matches the original).
// FUNCTION: IMPERIALISM 0x004840b0
void CIncludeView::OnChar(UINT nChar, UINT nRepCnt, UINT nFlags) {
  (void)nChar;
  (void)nRepCnt;
  (void)nFlags;
  Default();
}

// A click on a native child window (e.g. the movie MCIWnd) never reaches the view's own
// button handlers — WM_PARENTNOTIFY replays it as a full click: run the down handler,
// then the up dispatch + capture end, all at the child-relative point packed in lParam.
// FUNCTION: IMPERIALISM 0x00484190
void CIncludeView::OnParentNotify(UINT message, LPARAM lParam) {
  CWnd::OnParentNotify(message, lParam);
  CPoint point(static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam)));
  if (static_cast<unsigned short>(message) == WM_LBUTTONDOWN) {
    OnLButtonDown(0, point);
    if (m_uiInteractiveFlag90 != 0) {
      if (m_activeDialogContext != 0) {
        CPoint pt(point);
        m_activeDialogContext->DispatchUiMouseEventToChildrenOrSelf_Impl(&pt, 0, 0, 0);
      }
      g_McAppMouseCaptureState.EndMouseCaptureAndStopRepeatTimer(0, point.x, point.y);
    }
  }
}

// MCIWNDM_NOTIFYMODE: when the movie MCIWnd reports MCI_MODE_STOP (whether the movie ended
// on its own or was stopped/skipped by StopMovieIfActive), run the screen-exit path so the
// followup turn-event code (main menu, etc.) gets posted and the active movie view cleared.
// FUNCTION: IMPERIALISM 0x00484230
LRESULT CIncludeView::OnMciNotifyMode(WPARAM wParam, LPARAM mciMode) {
  (void)wParam;
  if (mciMode == MCI_MODE_STOP) {
    g_pUiRuntimeContext->HandleTurnStateExitAndPostFollowupEventCode(0);
  }
  return 0;
}

// Translate a keystroke into the shared UI command event and forward it into the active
// window's TView tree. Two dispatch targets are consulted: the modal-stack top host (as a
// CIncludeView -> its hosted dialog tree) and the live-registry head host (as a CMcWindow
// -> its owning TWindow and embedded dialog behaviour). This is how ESC/Space/Enter reach
// TGameWindow::ForwardParam, e.g. to stop (skip) a playing movie.
// FUNCTION: IMPERIALISM 0x00484260
void CIncludeView::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags) {
  static TKeyCommandEvent s_keyCommand;
  const int commandParam = reinterpret_cast<int>(&s_keyCommand);

  CWnd* target = GetModalStackTopHostView();
  if (target == 0) {
    target = this;
  }
  if (target != 0 && target->IsKindOf(RUNTIME_CLASS(CIncludeView))) {
    CIncludeView* view = static_cast<CIncludeView*>(target);
    if (view->m_activeDialogContext != 0) {
      PopulateKeyCommandBlock(s_keyCommand, nChar, nRepCnt, nFlags);
      view->m_activeDialogContext->ForwardParam(commandParam);
    }
  }

  if (target == this) {
    target = GetLiveRegistryHeadHostView();
  }
  if (target != 0 && target->IsKindOf(RUNTIME_CLASS(CMcWindow))) {
    TWindow* ownerWindow = static_cast<CMcWindow*>(target)->m_pOwnerWindow;
    if (ownerWindow != 0) {
      PopulateKeyCommandBlock(s_keyCommand, nChar, nRepCnt, nFlags);
      ownerWindow->ForwardParam(commandParam);
      if (ownerWindow->GetEmbeddedDialogBehavior() != 0) {
        ownerWindow->GetEmbeddedDialogBehavior()->OrphanCallChain_C11_I88_004874b0(commandParam);
      }
    }
  }
  Default();
}

// Native host view (TView::nativeWindow50) of the top window on the modal stack.
// FUNCTION: IMPERIALISM 0x0048d290
static CWnd* GetModalStackTopHostView() {
  if (g_ModalViewStack.GetHeadPosition() != NULL) {
    TView* window = static_cast<TView*>(g_ModalViewStack.GetHead());
    window->AssertValid();
    if (window->nativeWindow50 != 0) {
      return window->nativeWindow50;
    }
  }
  return 0;
}

// Native host view of the head window in the live-view registry.
// FUNCTION: IMPERIALISM 0x0048d840
static CWnd* GetLiveRegistryHeadHostView() {
  if (g_LiveViewRegistry.GetHeadPosition() != NULL) {
    TView* window = static_cast<TView*>(g_LiveViewRegistry.GetHead());
    window->AssertValid();
    if (window->nativeWindow50 != 0) {
      return window->nativeWindow50;
    }
  }
  return 0;
}
