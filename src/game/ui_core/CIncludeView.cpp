#include "game/ui_core/CIncludeView.h"
#include "game/ui_tags_common.h"

#include "game/ui_core/CMcWindow.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TPicture.h"
#include "game/TEvent.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

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
      g_pGlobalUiRootController->HandleCursor(cursorPos.x, cursorPos.y, 0);
    }
  }
}

// The shared keyboard command event (original object @ 0x6a1780) lives as a function-local
// static so first use constructs it once; the whole block is forwarded as a typed event
// into the active TView tree. Layout/type shared with TGameWindow::DoKeyEvent (which reads
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

// Active-window/native-host accessors used by OnKeyDown; defined below in address order
// (their bodies live at 0x48dxxx, past this file's other markers).
static CWnd* GetModalStackTopHostView();
static CWnd* GetLiveRegistryHeadHostView();

// SYNTHETIC: IMPERIALISM 0x00482850
// CIncludeView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00482930
// CIncludeView::GetRuntimeClass

IMPLEMENT_DYNCREATE(CIncludeView, CView)

// Original AFX_MSGMAP_ENTRY order (entries @ 0x6489e8).
//
// clang-cl's lint build rejects the MFC message-map macros' unqualified `&OnPaint`-style
// ?Serialize@?$CList@UIncludeViewOverlayRectRecord@@AAU1@@@UAEXAAVCArchive@@@Z

// Every field is initialized in the member-initializer list in declaration order: the
// original zeroes 0x40/0x44/0x48 before constructing the embedded m_overlayRectQueue
// CList (0x4c), then 0x6c/0x70/0x74 and 0x90 after it, and writes the vptr LAST — the
// MSVC signature of an all-init-list ctor with an empty body. Body assignments would
// instead run after member construction and after the vptr write, scrambling the order.
// m_overlayRectQueue (default CList ctor), m_overlayRectCursor68, and the capture CPoints
// are left default/uninitialized, matching the original (no stores to 0x68 or 0x78-0x8f).
// FUNCTION: IMPERIALISM 0x00482950
CIncludeView::CIncludeView()
    : CView(), m_activeDialogContext(0), m_pMainPaneDib(0), m_pOffscreenDib(0), m_tickTimerId(0),
      m_field70(0), m_capturedControl74(0), m_uiInteractiveFlag90(1) {}

// SYNTHETIC: IMPERIALISM 0x004829c0
// CIncludeView::`scalar deleting destructor'

// Compiler-emitted bodies of the m_overlayRectQueue CList<IncludeViewOverlayRectRecord,
// IncludeViewOverlayRectRecord&> instantiation. The original emitted the set twice (one
// copy per TU): vtable 0x648560 + these two in the ctor's TU, vtable 0x648578 + the
// 0x4847xx copies and the single Serialize body in the other.
// TEMPLATE: IMPERIALISM 0x004829f0
// ??_G?$CList@UIncludeViewOverlayRectRecord@@AAU1@@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x00482a20
// ??1?$CList@UIncludeViewOverlayRectRecord@@AAU1@@@UAE@XZ

// FUNCTION: IMPERIALISM 0x00482ab0
CIncludeView::~CIncludeView() {
  if (m_tickTimerId != 0) {
    m_tickTimerId = 0;
  }
  m_pMainPaneDib = 0;
  if (m_activeDialogContext != 0) {
    int previousUiActive = ClearGlobalUiInvalidationFlagAndReturnPrevious();
    m_activeDialogContext->nativeWindow50 = 0;
    if (m_activeDialogContext != 0) {
      m_activeDialogContext->Free();
    }
    m_activeDialogContext = 0;
    SetGlobalUiInvalidationFlagAndReturnPrevious(previousUiActive);
  }
  if (m_pOffscreenDib != 0) {
    delete m_pOffscreenDib;
  }
  // m_overlayRectQueue's inlined ~CList and CView::~CView emit from the real member and
  // real inheritance.
}
// address-of-member-function (a long-standing MSVC extension clang doesn't implement for
// this context); this is MFC dispatch-table plumbing, not game logic, so it's skipped in
// the compile-only lint build (never linked, so the missing definition is harmless there).
//
// GetMessageMap (vtable index 12, slot 0x30) is compiler-generated by the message-map
// macros below.
// SYNTHETIC: IMPERIALISM 0x00482bd0
// CIncludeView::GetMessageMap
#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(CIncludeView, CView)
ON_WM_ERASEBKGND()
ON_WM_LBUTTONDOWN()
ON_WM_LBUTTONUP()
ON_WM_MOUSEMOVE()
ON_WM_LBUTTONDBLCLK()
ON_COMMAND(0x8011, OnRefreshWaitCursorCommand)
ON_COMMAND(0x8012, OnUpdateWindowCommand)
ON_WM_SETCURSOR()
ON_WM_RBUTTONDOWN()
ON_WM_RBUTTONUP()
ON_WM_CHAR()
ON_WM_PARENTNOTIFY()
ON_WM_CTLCOLOR()
ON_WM_KEYDOWN()
ON_MESSAGE(0x4ef, OnDialogTreeHostMsg4EF)
ON_MESSAGE(0x4c8, OnMciNotifyMode) // MCIWNDM_NOTIFYMODE
END_MESSAGE_MAP()
#endif

// FUNCTION: IMPERIALISM 0x00482bf0
LRESULT CIncludeView::OnDialogTreeHostMsg4EF(WPARAM wParam, LPARAM lParam) {
  (void)lParam;
  switch (wParam & 0xff) {
  case 0:
    if (g_nIncludeViewAssertGate_006A17B0 == 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szIncludeViewSourcePath_00694D10, 0x77);
    }
    m_activeDialogContext = 0;
    m_pMainPaneDib = 0;
    break;
  case 1:
    m_activeDialogContext->PropagateUiResourceContextRecursive(this);
    m_activeDialogContext->ResolveControlByTag(kControlTagMain); // 'main'
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

// FUNCTION: IMPERIALISM 0x00482d00
void CIncludeView::BlitMapDialogSurfaceToHdcWithClipBounds(CDC* dc, RECT* clipRect) {
  CDC* targetDc = dc;
  if (targetDc == 0) {
    // LIBRARY: CDC::FromHandle (0x00612736)
    targetDc = CDC::FromHandle(::GetDC(m_hWnd));
  }
  RECT localClip;
  if (clipRect != 0) {
    CopyRect(&localClip, clipRect);
  } else {
    ::GetClientRect(m_hWnd, &localClip);
  }
  RECT clipBox;
  targetDc->GetClipBox(&clipBox);
  RECT surfaceBounds;
  int surfaceHeight = m_pOffscreenDib->m_pInfoHeader->bmiHeader.biHeight;
  if (surfaceHeight < 1) {
    surfaceHeight = -surfaceHeight;
  }
  surfaceBounds.left = 0;
  surfaceBounds.top = 0;
  surfaceBounds.right = m_pOffscreenDib->m_pInfoHeader->bmiHeader.biWidth - 1;
  surfaceBounds.bottom = surfaceHeight;
  // Two distinct destination rects, not one reused: the original's frame is SUB ESP,0x54
  // against the 0x40 four RECTs alone would need, and the extra 0x14 is this second RECT
  // plus the `this` spill at [ESP+0x10].
  RECT clippedToBox;
  IntersectRect(&clippedToBox, &localClip, &clipBox);
  RECT blitRect;
  IntersectRect(&blitRect, &clippedToBox, &surfaceBounds);
  m_pMainPaneDib->SelectAndRealizeDibPalette(targetDc, 0);
  HDC memDc = CreateCompatibleDC(targetDc->m_hDC);
  HGDIOBJ oldBitmap = SelectObject(memDc, m_pMainPaneDib->m_hBitmap);
  BitBlt(targetDc->m_hDC, blitRect.left, blitRect.top, blitRect.right - blitRect.left,
         blitRect.bottom - blitRect.top, memDc, blitRect.left, blitRect.top, SRCCOPY);
  SelectObject(memDc, oldBitmap);
  DeleteDC(memDc);
  if (dc == 0) {
    ::ReleaseDC(m_hWnd, targetDc->m_hDC);
  }
}

// Blit the main-pane bitmap into the offscreen surface. The blit rect starts as the
// bitmap's full extent and is narrowed by `clipRect` when one is supplied. Note the
// original passes the rect's left edge as BOTH srcX and srcY (only destY uses top);
// that asymmetry is reproduced as-is.
// FUNCTION: IMPERIALISM 0x00482ed0
void CIncludeView::BlitMainPaneBitmapToOffscreenClipped(RECT* clipRect) {
  CPoint bitmapSize;
  m_pMainPaneDib->CopyBitmapDimensionsToPoint(&bitmapSize);

  RECT blitRect;
  blitRect.left = 0;
  blitRect.top = 0;
  blitRect.right = bitmapSize.x;
  blitRect.bottom = bitmapSize.y;
  if (clipRect != 0) {
    ::IntersectRect(&blitRect, clipRect, &blitRect);
  }

  m_pMainPaneDib->BlitSurfaceRectSkippingTransparentColor(
      m_pOffscreenDib, blitRect.left, blitRect.left, blitRect.right - blitRect.left,
      blitRect.bottom - blitRect.top, blitRect.left, blitRect.top, -1);
}

// FUNCTION: IMPERIALISM 0x00482fc0
void CIncludeView::UpdateAndRenderMapTileHintOverlayQueue(CDC* dc, RECT* clipRect) {
  // Pass 1: blit each not-yet-processed hint rect into the offscreen surface.
  m_overlayRectCursor68 = m_overlayRectQueue.GetHeadPosition();
  while (m_overlayRectCursor68 != 0) {
    IncludeViewOverlayRectRecord& rec = m_overlayRectQueue.GetNext(m_overlayRectCursor68);
    if (rec.processedFlag10 == 0) {
      rec.processedFlag10 = 1;
      CPoint dimensions;
      m_pMainPaneDib->CopyBitmapDimensionsToPoint(&dimensions);
      IncludeViewOverlayRectRecord surfaceRect;
      surfaceRect.rect.left = 0;
      surfaceRect.rect.top = 0;
      surfaceRect.rect.right = dimensions.x;
      surfaceRect.rect.bottom = dimensions.y;
      IntersectRect(&surfaceRect.rect, &rec.rect, &surfaceRect.rect);
      CPoint span = surfaceRect.ComputeSpan();
      POINT corner;
      corner.x = surfaceRect.rect.left;
      corner.y = surfaceRect.rect.top;
      m_pMainPaneDib->ForwardBlitSurfaceRectSkippingTransparentColor(m_pOffscreenDib, &corner,
                                                                     &span, &corner, -1);
    }
  }
  // Pass 2: repaint the hosted dialog tree over each remaining unprocessed rect.
  m_overlayRectCursor68 = m_overlayRectQueue.GetHeadPosition();
  while (m_overlayRectCursor68 != 0) {
    IncludeViewOverlayRectRecord& rec = m_overlayRectQueue.GetNext(m_overlayRectCursor68);
    if (rec.processedFlag10 == 0) {
      rec.processedFlag10 = 1;
      RECT paintRect;
      CopyRect(&paintRect, &rec.rect);
      m_activeDialogContext->PaintVisibleChildrenIntersectingClipRect(&paintRect, 0);
    }
  }
  // Pass 3: flush every finished (flag 2) rect to the screen DC and remove it.
  CDC* targetDc = dc;
  if (targetDc == 0) {
    // LIBRARY: CDC::FromHandle (0x00612736)
    targetDc = CDC::FromHandle(::GetDC(m_hWnd));
  }
  m_overlayRectCursor68 = m_overlayRectQueue.GetHeadPosition();
  while (m_overlayRectCursor68 != 0) {
    POSITION current = m_overlayRectCursor68;
    IncludeViewOverlayRectRecord& rec = m_overlayRectQueue.GetNext(m_overlayRectCursor68);
    if (rec.processedFlag10 == 2) {
      RECT flushRect = rec.rect;
      m_overlayRectQueue.RemoveAt(current);
      BlitMapDialogSurfaceToHdcWithClipBounds(targetDc, &flushRect);
    }
  }
  if (dc == 0) {
    ::ReleaseDC(m_hWnd, targetDc->m_hDC);
  }
}

// FUNCTION: IMPERIALISM 0x00483220
CPoint IncludeViewOverlayRectRecord::ComputeSpan() const {
  return CPoint(rect.right - rect.left, rect.bottom - rect.top);
}

// Install this view as the native host window for the given TView (and its whole
// subtree), then let it resolve the 'main' control tag against itself.
// FUNCTION: IMPERIALISM 0x00483340
void CIncludeView::SetUiRuntimeContextAndActivateMain(TView* activeDialog) {
  m_activeDialogContext = activeDialog;
  m_activeDialogContext->PropagateUiResourceContextRecursive(this);
  m_activeDialogContext->ResolveControlByTag(kControlTagMain); // 'main'
}

// FUNCTION: IMPERIALISM 0x00483380
void CIncludeView::RefreshActiveDialogHost(int unusedArg) {
  (void)unusedArg;
  m_activeDialogContext->PropagateUiResourceContextRecursive(this);
  m_activeDialogContext->ResolveControlByTag(kControlTagMain);
}

// Tear the hosted dialog tree down, re-resolve the 'main' pane picture, blit its cached
// bitmap into the offscreen surface and force a full repaint of the host window. The one
// stack argument is accepted and never read; the (now cleared) dialog context is returned.
// FUNCTION: IMPERIALISM 0x004833b0
TView* CIncludeView::ReinitializeIncludeViewMainPaneAndRedrawWindow(int unusedArg) {
  (void)unusedArg;
  m_pMainPaneDib = 0;
  if (m_activeDialogContext != 0) {
    int previousFlag = ClearGlobalUiInvalidationFlagAndReturnPrevious();
    m_activeDialogContext->nativeWindow50 = 0;
    if (m_activeDialogContext != 0) {
      m_activeDialogContext->Free();
    }
    m_activeDialogContext = 0;
    SetGlobalUiInvalidationFlagAndReturnPrevious(previousFlag);
  }
  if (g_nIncludeViewReinitAssertGate_006A17BC == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szIncludeViewSourcePath_00694D10, 0x1d2);
  }

  TPicture* mainPane =
      static_cast<TPicture*>(m_activeDialogContext->ResolveControlByTag(kControlTagMain));
  m_pMainPaneDib = mainPane->cachedBitmap;

  CPoint bitmapSize;
  m_pMainPaneDib->CopyBitmapDimensionsToPoint(&bitmapSize);
  POINT sourceOrigin;
  POINT blitSize;
  POINT destOrigin;
  blitSize.x = bitmapSize.x;
  blitSize.y = bitmapSize.y;
  sourceOrigin.x = 0;
  sourceOrigin.y = 0;
  destOrigin.x = 0;
  destOrigin.y = 0;
  m_pMainPaneDib->ForwardBlitSurfaceRectSkippingTransparentColor(m_pOffscreenDib, &sourceOrigin,
                                                                 &blitSize, &destOrigin, -1);

  ::InvalidateRect(m_hWnd, 0, TRUE);
  ::RedrawWindow(m_hWnd, 0, 0, RDW_INVALIDATE);

  if (g_nIncludeViewReinitThreadOnceGate_006A17C0 == 0) {
    g_nIncludeViewReinitThreadOnceGate_006A17C0 = 1;
  }
  return m_activeDialogContext;
}

// FUNCTION: IMPERIALISM 0x00483530
void CIncludeView::TearDownActiveDialogContext() {
  m_pMainPaneDib = 0;
  if (m_activeDialogContext != 0) {
    int previousFlag = ClearGlobalUiInvalidationFlagAndReturnPrevious();
    m_activeDialogContext->nativeWindow50 = 0;
    if (m_activeDialogContext != 0) {
      m_activeDialogContext->Free();
    }
    m_activeDialogContext = 0;
    SetGlobalUiInvalidationFlagAndReturnPrevious(previousFlag);
  }
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

// FUNCTION: IMPERIALISM 0x004835e0
void CIncludeView::BlitMainPaneBitmapRectToWindow(RECT* rect) {
  HDC hdc = ::GetDC(m_hWnd);
  // LIBRARY: CDC::FromHandle (0x00612736)
  CDC* dc = CDC::FromHandle(hdc);
  m_pMainPaneDib->SelectAndRealizeDibPalette(dc, FALSE);
  m_pMainPaneDib->StretchDibitsRectAtNaturalSize(rect->left, rect->top, dc, rect->left, rect->top,
                                                 rect->right - rect->left,
                                                 rect->bottom - rect->top);
  ::ReleaseDC(m_hWnd, dc->m_hDC);
}

// Native edit controls store their owning TControl in GWL_USERDATA. Select the game's
// indexed palette into the supplied DC, use the fixed edit background key, and resolve
// the control's resource-derived text color (the style override when present, otherwise
// TControl::textStyle78). Other native child types keep MFC's default coloring.
// FUNCTION: IMPERIALISM 0x00483660
HBRUSH CIncludeView::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) {
  CWnd::OnCtlColor(pDC, pWnd, nCtlColor);
  if (nCtlColor == CTLCOLOR_EDIT) {
    HWND controlWindow = pWnd != NULL ? pWnd->m_hWnd : NULL;
    TControl* control = reinterpret_cast<TControl*>(::GetWindowLong(controlWindow, GWL_USERDATA));
    if (control != NULL) {
      g_pModuleLibraryCacheState->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(pDC, FALSE);
      pDC->SetBkColor(0x0000ff00);
      unsigned int packedTextColor =
          control->stylePayload48 != NULL
              ? static_cast<unsigned int>(control->stylePayload48->styleWord)
              : static_cast<unsigned int>(control->textStyle78.textColor);
      pDC->SetTextColor(g_pModuleLibraryCacheState->ResolvePaletteIndexColor(packedTextColor));
    }
  }
  pDC->SetBkMode(TRANSPARENT);
  return reinterpret_cast<HBRUSH>(::GetStockObject(NULL_BRUSH));
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
    m_capturedControl74->WindowToLocal(&controlRelativePoint);
    m_captureLastPoint80 = m_captureCurrentPoint88;
    m_captureCurrentPoint88 = controlRelativePoint;
    m_capturedControl74->TrackMouse(kTrackPhaseUpdate, m_captureStartPoint78, m_captureLastPoint80,
                                    m_captureCurrentPoint88, 1);
  }
  g_pGlobalUiRootController->HandleCursor(point.x, point.y, 0);
  if (m_activeDialogContext != 0 && GetMcAppUiActiveFlag() != 0) {
    CPoint pt(point);
    m_activeDialogContext->HandleCursorHoverSelectionByChildHitTestAndFallback(&pt, 0);
  }
}

// WM_LBUTTONDOWN: forward the click into the hosted dialog tree as a mouse event
// (TView slot 0x46). For a playing movie this reaches TMovieView::HandleMouseDown,
// which stops (skips) the movie. Clicking the view outside the centered movie lands here;
// clicking the movie window itself arrives via OnParentNotify.
// FUNCTION: IMPERIALISM 0x004839e0
void CIncludeView::OnLButtonDown(UINT nFlags, CPoint point) {
  (void)nFlags;
  if (m_uiInteractiveFlag90 != 0 && m_activeDialogContext != 0) {
    TToolboxEvent event;
    event.mouseX = point.x;
    event.mouseY = point.y;
    event.mouseMetadata1c = 0;
    event.mouseButton24 = 0;
    m_activeDialogContext->HandleMouseDown(point, &event, CPoint(0, 0));
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
      m_activeDialogContext->HandleMouseUp(pt, 0, CPoint(0, 0));
    }
    g_McAppMouseCaptureState.EndMouseCaptureAndStopRepeatTimer(nFlags, point.x, point.y);
  }
}

// Double-clicks have no separate game action. While input is enabled, forward the
// original message to MFC's default window procedure; modal/input-gated periods swallow it.
// FUNCTION: IMPERIALISM 0x00483b70
void CIncludeView::OnLButtonDblClk(UINT nFlags, CPoint point) {
  (void)nFlags;
  (void)point;
  if (m_uiInteractiveFlag90 != 0) {
    Default();
  }
}

// Command 0x8011 momentarily enters and leaves MFC's wait-cursor state. This forces the
// application cursor to refresh without retaining a busy-cursor nesting level.
// FUNCTION: IMPERIALISM 0x00483d60
void CIncludeView::OnRefreshWaitCursorCommand() {
  AfxGetApp()->BeginWaitCursor();
  AfxGetApp()->EndWaitCursor();
}

// Command 0x8012 synchronously flushes this host view's pending paint.
// FUNCTION: IMPERIALISM 0x00483d90
void CIncludeView::OnUpdateWindowCommand() {
  UpdateWindow();
}

// Overrides CWnd::PreCreateWindow (vtable slot 0x64): register a private "AmbitGameWindow"
// window class (3 = CS_VREDRAW|CS_HREDRAW, DefWindowProc, app icon 0x7a02, background
// value 5) and force cs.lpszClass + the WS_CHILD|WS_VISIBLE style bits (0x06000000) before
// delegating to CView::PreCreateWindow.
// FUNCTION: IMPERIALISM 0x00483db0
BOOL CIncludeView::PreCreateWindow(CREATESTRUCT& cs) {
  WNDCLASS wndClass;
  memset(&wndClass, 0, sizeof(wndClass));
  wndClass.lpfnWndProc = ::DefWindowProc;
  wndClass.hInstance = AfxGetInstanceHandle();
  wndClass.style = CS_VREDRAW | CS_HREDRAW;
  wndClass.hbrBackground = reinterpret_cast<HBRUSH>(5);
  wndClass.lpszClassName = "AmbitGameWindow";
  wndClass.hIcon = ::LoadIcon(AfxGetResourceHandle(), MAKEINTRESOURCE(0x7a02));
  if (wndClass.hIcon == NULL) {
    wndClass.hIcon = ::LoadIcon(NULL, IDI_APPLICATION);
  }
  AfxRegisterClass(&wndClass);
  cs.lpszClass = "AmbitGameWindow";
  cs.style |= 0x06000000;
  return CView::PreCreateWindow(cs);
}

// Overrides CWnd::OnCommand (vtable slot 0x80). For a custom notify code 0x400 (HIWORD of
// wParam) from a child control, recover the control's owning TView from its GWL_USERDATA
// (both receivers are TView-hierarchy objects: the control's slot 0xe4 is TView::RefreshControl
// at 0x48b6d0, and m_activeDialogContext's slot 0x13c is TView::ForceRedraw at 0x48b700),
// refresh the control, and reset the hosted dialog tree's input capture. Then default-route.
// FUNCTION: IMPERIALISM 0x00483e80
BOOL CIncludeView::OnCommand(WPARAM wParam, LPARAM lParam) {
  if (HIWORD(wParam) == 0x400) {
    TView* controlView =
        reinterpret_cast<TView*>(::GetWindowLong(reinterpret_cast<HWND>(lParam), GWL_USERDATA));
    if (controlView != NULL) {
      controlView->RefreshControl();
      m_activeDialogContext->ForceRedraw();
    }
  }
  return CWnd::OnCommand(wParam, lParam);
}

// Keep cursor selection in the standard MFC/default-window path.
// FUNCTION: IMPERIALISM 0x00483ef0
BOOL CIncludeView::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message) {
  (void)pWnd;
  (void)nHitTest;
  (void)message;
  return static_cast<BOOL>(Default());
}

// Right-button clicks follow the same hosted-dialog path as left-button clicks. The
// TToolboxEvent button field distinguishes the two down events; mouse-up uses the shared
// tree dispatch and capture teardown.
// FUNCTION: IMPERIALISM 0x00483f10
void CIncludeView::OnRButtonDown(UINT nFlags, CPoint point) {
  (void)nFlags;
  if (m_uiInteractiveFlag90 != 0 && m_activeDialogContext != 0) {
    TToolboxEvent event;
    event.mouseX = point.x;
    event.mouseY = point.y;
    event.mouseMetadata1c = 0;
    event.mouseButton24 = 1;
    m_activeDialogContext->HandleMouseDown(point, &event, CPoint(0, 0));
  }
}

// FUNCTION: IMPERIALISM 0x00483ff0
void CIncludeView::OnRButtonUp(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag90 != 0) {
    if (m_activeDialogContext != 0) {
      CPoint pt(point);
      m_activeDialogContext->HandleMouseUp(pt, 0, CPoint(0, 0));
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

// Replace the main-view input gate and return its previous state. Dialog modal loops
// temporarily clear this gate and restore it only when it had been set on entry.
// FUNCTION: IMPERIALISM 0x00484080
int CIncludeView::SetUiInteractiveFlag90(unsigned char interactive) {
  int previous = m_uiInteractiveFlag90;
  m_uiInteractiveFlag90 = interactive;
  return previous;
}

// WM_CHAR: no game handling; defers to DefWindowProc (matches the original).
// FUNCTION: IMPERIALISM 0x004840b0
void CIncludeView::OnChar(UINT nChar, UINT nRepCnt, UINT nFlags) {
  (void)nChar;
  (void)nRepCnt;
  (void)nFlags;
  Default();
}

// RecalcLayout keystone: the frame's RepositionBars hands the leftover client rect to the
// pane's virtual CalcWindowRect; this override centers the fixed 640x480 view inside it
// (top-left-clamped when the rect is smaller) instead of filling it. Without this the
// maximize re-expands the view full-screen and the movie/menu/title layouts split apart.
// FUNCTION: IMPERIALISM 0x004840d0
void CIncludeView::CalcWindowRect(LPRECT lpClientRect, UINT nAdjustType) {
  (void)nAdjustType;
  RECT proposedRect;
  CopyRect(&proposedRect, lpClientRect);
  lpClientRect->left = ((proposedRect.right - proposedRect.left) - 0x280) / 2;
  if (lpClientRect->left < 0) {
    lpClientRect->left = 0;
  }
  lpClientRect->top = ((proposedRect.bottom - proposedRect.top) - 0x1e0) / 2;
  if (lpClientRect->top < 0) {
    lpClientRect->top = 0;
  }
  lpClientRect->right = lpClientRect->left + 0x280;
  lpClientRect->bottom = lpClientRect->top + 0x1e0;
  ::AdjustWindowRectEx(lpClientRect, 0, FALSE, GetExStyle());
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
        m_activeDialogContext->HandleMouseUp(pt, 0, CPoint(0, 0));
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
// TGameWindow::DoKeyEvent, e.g. to stop (skip) a playing movie.
// FUNCTION: IMPERIALISM 0x00484260
void CIncludeView::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags) {
  static TKeyCommandEvent s_keyCommand;

  CWnd* target = GetModalStackTopHostView();
  if (target == 0) {
    target = this;
  }
  if (target != 0 && target->IsKindOf(RUNTIME_CLASS(CIncludeView))) {
    CIncludeView* view = static_cast<CIncludeView*>(target);
    if (view->m_activeDialogContext != 0) {
      PopulateKeyCommandBlock(s_keyCommand, nChar, nRepCnt, nFlags);
      view->m_activeDialogContext->DoKeyEvent(&s_keyCommand);
    }
  }

  if (target == this) {
    target = GetLiveRegistryHeadHostView();
  }
  if (target != 0 && target->IsKindOf(RUNTIME_CLASS(CMcWindow))) {
    TWindow* ownerWindow = static_cast<CMcWindow*>(target)->m_pOwnerWindow;
    if (ownerWindow != 0) {
      PopulateKeyCommandBlock(s_keyCommand, nChar, nRepCnt, nFlags);
      ownerWindow->DoKeyEvent(&s_keyCommand);
      if (ownerWindow->GetDialogBehavior() != 0) {
        ownerWindow->GetDialogBehavior()->DoKeyEvent(&s_keyCommand);
      }
    }
  }
  Default();
}

// TEMPLATE: IMPERIALISM 0x00484610
// ?Serialize@?$CList@UIncludeViewOverlayRectRecord@@AAU1@@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x004847a0
// ??_G?$CList@UIncludeViewOverlayRectRecord@@AAU1@@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x004847d0
// ??1?$CList@UIncludeViewOverlayRectRecord@@AAU1@@@UAE@XZ

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
