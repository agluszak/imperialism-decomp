#include "game/menu_commands.h"
#include "game/ui_core/CIncludeView.h"
#include "game/ui_tags_common.h"

#include "game/ui_core/CMcWindow.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TPicture.h"
#include "game/TEvent.h"
#include "game/gfx/TResourceMgr.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/view_registries.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/pointer_representation.h"
#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeObservation.h"
#include "RuntimeTestDriver.h"
#include "RuntimeUiDriver.h"
#endif

#define NOAVIFILE
#include <vfw.h>

// FUNCTION: IMPERIALISM 0x00482760
static void CALLBACK UiCursorTickTimerProc(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime) {
  POINT cursorPos;
  GetCursorPos(&cursorPos);
  ScreenToClient(hWnd, &cursorPos);
  if (g_pAmbitApplication != 0) {
    CWnd* foreground = CWnd::FromHandle(GetForegroundWindow());
    CWnd* mainWnd = (AfxGetThread() != 0) ? AfxGetThread()->GetMainWnd() : 0;
    if (foreground == mainWnd) {
      g_pAmbitApplication->HandleCursor(cursorPos.x, cursorPos.y, 0);
    }
  }
}

static void PopulateKeyCommandBlock(TToolboxEvent& block, UINT nChar, UINT nRepCnt, UINT nFlags) {
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

static CWnd* GetModalStackTopHostView();
static CWnd* GetLiveRegistryHeadHostView();

IMPLEMENT_DYNCREATE(CIncludeView, CView)

// FUNCTION: IMPERIALISM 0x00482950
CIncludeView::CIncludeView()
    : m_activeDialogContext(0), m_pMainPaneDib(0), m_pOffscreenDib(0), m_tickTimerId(0),
      m_unused70(0), m_capturedControl(0), m_uiInteractiveFlag(1) {}

// FUNCTION: IMPERIALISM 0x00482ab0
CIncludeView::~CIncludeView() {
  if (m_tickTimerId != 0) {
    m_tickTimerId = 0;
  }
  m_pMainPaneDib = 0;
  if (m_activeDialogContext != 0) {
    int previousUiActive = ClearInvalidationFlag();
    m_activeDialogContext->nativeWindow = 0;
    if (m_activeDialogContext != 0) {
      m_activeDialogContext->Free();
    }
    m_activeDialogContext = 0;
    SetInvalidationFlag(previousUiActive);
  }

  delete m_pOffscreenDib;
}
#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(CIncludeView, CView)
ON_WM_ERASEBKGND()
ON_WM_LBUTTONDOWN()
ON_WM_LBUTTONUP()
ON_WM_MOUSEMOVE()
ON_WM_LBUTTONDBLCLK()
ON_COMMAND(kCmdDumpViewHierarchy, OnDumpViewHierarchy)
ON_COMMAND(kCmdRefresh, OnRefresh)
ON_WM_SETCURSOR()
ON_WM_RBUTTONDOWN()
ON_WM_RBUTTONUP()
ON_WM_CHAR()
ON_WM_PARENTNOTIFY()
ON_WM_CTLCOLOR()
ON_WM_KEYDOWN()
ON_MESSAGE(0x4ef, OnDialogTreeHostMsg4EF)
ON_MESSAGE(0x4c8, OnMciNotifyMode) // MCIWNDM_NOTIFYMODE
#ifdef IMPERIALISM_RUNTIME_TESTS
ON_MESSAGE(WM_RUNTIME_ACTION, OnRuntimeAction)
#endif
END_MESSAGE_MAP()
#endif

#ifdef IMPERIALISM_RUNTIME_TESTS
LRESULT CIncludeView::OnRuntimeAction(WPARAM wParam, LPARAM lParam) {
  MSG message;
  ZeroMemory(&message, sizeof(message));
  message.hwnd = m_hWnd;
  message.message = WM_RUNTIME_ACTION;
  message.wParam = wParam;
  message.lParam = lParam;
  RuntimeTestDriver::HandleMessage(&message);
  return 0;
}
#endif

// FUNCTION: IMPERIALISM 0x00482bf0
LRESULT CIncludeView::OnDialogTreeHostMsg4EF(WPARAM wParam, LPARAM lParam) {
  switch (wParam & 0xff) {
  case 0:
    if (g_nIncludeViewAssertGate == 0) {
      ReportAssertionFailure(g_szIncludeViewSourcePath, 0x77);
    }
    m_activeDialogContext = 0;
    m_pMainPaneDib = 0;
    break;
  case 1:
    m_activeDialogContext->PropagateUiResourceContextRecursive(this);
    m_activeDialogContext->FindSubView(kControlTagMain); // 'main'
    break;
  default:
    ReportAssertionFailure(g_szIncludeViewSourcePath, 0x84);
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
      m_activeDialogContext->PaintChildren(&paintRect, pDC);
    }
  }
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTestDriver::ObserveDeferred(kObservePaintCompleted);
#endif
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

// FUNCTION: IMPERIALISM 0x00482f70
void CIncludeView::QueueOrMergeOverlayDirtyRect(RECT* rect, int processedFlag, int field14) {
  RECT copiedRect;
  CopyRect(&copiedRect, rect);
  m_overlayRectQueue.AddHead(&copiedRect, processedFlag, field14);
}

// FUNCTION: IMPERIALISM 0x00482fc0
void CIncludeView::UpdateAndRenderMapTileHintOverlayQueue(CDC* dc, RECT* clipRect) {
  // Pass 1: blit each not-yet-processed hint rect into the offscreen surface.
  m_overlayRectQueue.cursor = m_overlayRectQueue.records.GetHeadPosition();
  while (m_overlayRectQueue.cursor != 0) {
    IncludeViewOverlayRectRecord& rec =
        m_overlayRectQueue.records.GetNext(m_overlayRectQueue.cursor);
    if (rec.processedFlag == 0) {
      rec.processedFlag = 1;
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
  m_overlayRectQueue.cursor = m_overlayRectQueue.records.GetHeadPosition();
  while (m_overlayRectQueue.cursor != 0) {
    IncludeViewOverlayRectRecord& rec =
        m_overlayRectQueue.records.GetNext(m_overlayRectQueue.cursor);
    if (rec.processedFlag == 0) {
      rec.processedFlag = 1;
      RECT paintRect;
      CopyRect(&paintRect, &rec.rect);
      m_activeDialogContext->PaintChildren(&paintRect, 0);
    }
  }
  // Pass 3: flush every finished (flag 2) rect to the screen DC and remove it.
  CDC* targetDc = dc;
  if (targetDc == 0) {
    // LIBRARY: CDC::FromHandle (0x00612736)
    targetDc = CDC::FromHandle(::GetDC(m_hWnd));
  }
  m_overlayRectQueue.cursor = m_overlayRectQueue.records.GetHeadPosition();
  while (m_overlayRectQueue.cursor != 0) {
    POSITION current = m_overlayRectQueue.cursor;
    IncludeViewOverlayRectRecord& rec =
        m_overlayRectQueue.records.GetNext(m_overlayRectQueue.cursor);
    if (rec.processedFlag == 2) {
      RECT flushRect = rec.rect;
      m_overlayRectQueue.records.RemoveAt(current);
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

// FUNCTION: IMPERIALISM 0x00483250
void CIncludeView::AssertOverlayQueueGate() {
  if (g_nIncludeViewQueueAssertGate == 0) {
    ReportAssertionFailure(g_szIncludeViewSourcePath, 0x166);
  }
}

// FUNCTION: IMPERIALISM 0x00483280
void CIncludeView::BeginTracking(CPoint* startPoint, TControl* tracker) {
  if (g_nIncludeViewCaptureAssertGate == 0) {
    ReportAssertionFailure(g_szIncludeViewSourcePath, 0x16e);
  }
  m_capturedControl = tracker;
  CWnd::FromHandle(::SetCapture(m_hWnd));

  // All three points start at the press position; the update phase moves last/current.
  m_captureStartPoint = *startPoint;
  m_captureLastPoint = *startPoint;
  m_captureCurrentPoint = *startPoint;

  tracker->TrackMouse(kTrackPhaseBegin, m_captureStartPoint, m_captureLastPoint,
                      m_captureCurrentPoint, true);
}

// FUNCTION: IMPERIALISM 0x00483340
void CIncludeView::SetUiRuntimeContextAndActivateMain(TView* activeDialog) {
  m_activeDialogContext = activeDialog;
  m_activeDialogContext->PropagateUiResourceContextRecursive(this);
  m_activeDialogContext->FindSubView(kControlTagMain); // 'main'
}

// FUNCTION: IMPERIALISM 0x00483380
void CIncludeView::RefreshActiveDialogHost(int unusedArg) {
  m_activeDialogContext->PropagateUiResourceContextRecursive(this);
  m_activeDialogContext->FindSubView(kControlTagMain);
}

// FUNCTION: IMPERIALISM 0x004833b0
TView* CIncludeView::ResetMainPane(int unusedArg) {
  TearDownActiveDialogContext();
  if (g_nIncludeViewReinitAssertGate == 0) {
    ReportAssertionFailure(g_szIncludeViewSourcePath, 0x1d2);
  }

  TPicture* mainPane = static_cast<TPicture*>(m_activeDialogContext->FindSubView(kControlTagMain));
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

  if (g_nIncludeViewReinitThreadOnceGate == 0) {
    g_nIncludeViewReinitThreadOnceGate = 1;
  }
  return m_activeDialogContext;
}

// FUNCTION: IMPERIALISM 0x00483530
void CIncludeView::TearDownActiveDialogContext() {
  m_pMainPaneDib = 0;
  if (m_activeDialogContext != 0) {
    int previousFlag = ClearInvalidationFlag();
    m_activeDialogContext->nativeWindow = 0;
    if (m_activeDialogContext != 0) {
      m_activeDialogContext->Free();
    }
    m_activeDialogContext = 0;
    SetInvalidationFlag(previousFlag);
  }
}

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

// FUNCTION: IMPERIALISM 0x00483660
HBRUSH CIncludeView::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) {
  CWnd::OnCtlColor(pDC, pWnd, nCtlColor);
  if (nCtlColor == CTLCOLOR_EDIT) {
    HWND controlWindow = pWnd != NULL ? pWnd->m_hWnd : NULL;
    TControl* control = static_cast<TControl*>(
        PointerFromAddressLong32(::GetWindowLong(controlWindow, GWL_USERDATA)));
    if (control != NULL) {
      g_pResourceMgr->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(pDC, FALSE);
      pDC->SetBkColor(0x0000ff00);
      unsigned int packedTextColor =
          control->stylePayload != NULL
              ? static_cast<unsigned int>(control->stylePayload->styleWord)
              : static_cast<unsigned int>(control->textStyle.textColor);
      pDC->SetTextColor(g_pResourceMgr->ResolvePaletteIndexColor(packedTextColor));
    }
  }
  pDC->SetBkMode(TRANSPARENT);
  return static_cast<HBRUSH>(
      PointerFromAddressLong32(PointerAddressLong32(::GetStockObject(NULL_BRUSH))));
}

// FUNCTION: IMPERIALISM 0x00483720
void CIncludeView::OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView) {
  CView::OnActivateView(bActivate, pActivateView, pDeactiveView);
}

// FUNCTION: IMPERIALISM 0x00483750
void CIncludeView::OnInitialUpdate() {

  delete m_pOffscreenDib;

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

// FUNCTION: IMPERIALISM 0x004838b0
void CIncludeView::OnMouseMove(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag == 0) {
    return;
  }
  g_McAppMouseCaptureState.NotifyTracking(nFlags, point.x, point.y);
  if (m_capturedControl != 0) {
    if (g_nIncludeViewPointerAssertGate == 0) {
      ReportAssertionFailure(g_szIncludeViewSourcePath, 0x2b7);
    }
    CPoint controlRelativePoint(point);
    m_capturedControl->WindowToLocal(&controlRelativePoint);
    m_captureLastPoint = m_captureCurrentPoint;
    m_captureCurrentPoint = controlRelativePoint;
    m_capturedControl->TrackMouse(kTrackPhaseUpdate, m_captureStartPoint, m_captureLastPoint,
                                  m_captureCurrentPoint, true);
  }
  g_pAmbitApplication->HandleCursor(point.x, point.y, 0);
  if (m_activeDialogContext != 0 && GetMcAppUiActiveFlag() != 0) {
    CPoint pt(point);
    m_activeDialogContext->AdjustCursor(&pt, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004839e0
void CIncludeView::OnLButtonDown(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag != 0 && m_activeDialogContext != 0) {
    TToolboxEvent event;
    event.mouseX = point.x;
    event.mouseY = point.y;
    event.commandCode = 0;
    event.keyFlags = 0;
    event.mouseButton = 0;
    m_activeDialogContext->HandleMouseDown(point, &event, CPoint(0, 0));
  }
}

// FUNCTION: IMPERIALISM 0x00483b00
void CIncludeView::OnLButtonUp(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag != 0) {
    if (m_activeDialogContext != 0) {
      CPoint pt(point);
      m_activeDialogContext->HandleMouseUp(pt, 0, CPoint(0, 0));
    }
    g_McAppMouseCaptureState.EndMouseCaptureAndStopRepeatTimer(nFlags, point.x, point.y);
  }
}

// FUNCTION: IMPERIALISM 0x00483b70
void CIncludeView::OnLButtonDblClk(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag != 0) {
    Default();
  }
}

// FUNCTION: IMPERIALISM 0x00483ba0
void CIncludeViewOverlayRectQueue::AddHead(RECT* rect, int processedFlag, int field14) {
  POSITION headPosition = records.GetHeadPosition();
  if (headPosition != 0) {
    IncludeViewOverlayRectRecord& head = records.GetAt(headPosition);
    RECT intersection;
    if (head.processedFlag != 2 && IntersectRect(&intersection, &head.rect, rect)) {
      UnionRect(&head.rect, &head.rect, rect);
      if (processedFlag != 0 && head.processedFlag != 0) {
        head.processedFlag = 0;
      }
      return;
    }
  }

  IncludeViewOverlayRectRecord record;
  record.rect = *rect;
  record.processedFlag = processedFlag != 0;
  record.field14 = field14;
  records.AddHead(record);
}

// FUNCTION: IMPERIALISM 0x00483d10
IncludeViewOverlayRectRecord*
CIncludeViewOverlayRectQueue::UpdateNextRecordProcessedFlagFromCursor(int matchFlag, int newFlag) {
  while (cursor != 0) {
    IncludeViewOverlayRectRecord& rec = records.GetNext(cursor);
    if (rec.processedFlag == matchFlag) {
      rec.processedFlag = newFlag;
      return &rec;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00483d60
void CIncludeView::OnDumpViewHierarchy() {
  AfxGetApp()->BeginWaitCursor();
  AfxGetApp()->EndWaitCursor();
}

// FUNCTION: IMPERIALISM 0x00483d90
void CIncludeView::OnRefresh() {
  UpdateWindow();
}

// FUNCTION: IMPERIALISM 0x00483db0
BOOL CIncludeView::PreCreateWindow(CREATESTRUCT& cs) {
  WNDCLASS wndClass;
  memset(&wndClass, 0, sizeof(wndClass));
  wndClass.lpfnWndProc = ::DefWindowProc;
  wndClass.hInstance = AfxGetInstanceHandle();
  wndClass.style = CS_VREDRAW | CS_HREDRAW;
  wndClass.hbrBackground = static_cast<HBRUSH>(PointerFromAddressLong32(5));
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

// FUNCTION: IMPERIALISM 0x00483e80
BOOL CIncludeView::OnCommand(WPARAM wParam, LPARAM lParam) {
  if (HIWORD(wParam) == 0x400) {
    HWND controlWindow = static_cast<HWND>(PointerFromAddressLong32(lParam));
    TView* controlView =
        static_cast<TView*>(PointerFromAddressLong32(::GetWindowLong(controlWindow, GWL_USERDATA)));
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
  return static_cast<BOOL>(Default());
}

// FUNCTION: IMPERIALISM 0x00483f10
void CIncludeView::OnRButtonDown(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag != 0 && m_activeDialogContext != 0) {
    TToolboxEvent event;
    event.mouseX = point.x;
    event.mouseY = point.y;
    event.commandCode = 0;
    event.keyFlags = 0;
    event.mouseButton = 1;
    m_activeDialogContext->HandleMouseDown(point, &event, CPoint(0, 0));
  }
}

// FUNCTION: IMPERIALISM 0x00483ff0
void CIncludeView::OnRButtonUp(UINT nFlags, CPoint point) {
  if (m_uiInteractiveFlag != 0) {
    if (m_activeDialogContext != 0) {
      CPoint pt(point);
      m_activeDialogContext->HandleMouseUp(pt, 0, CPoint(0, 0));
    }
    g_McAppMouseCaptureState.EndMouseCaptureAndStopRepeatTimer(nFlags, point.x, point.y);
  }
}

// FUNCTION: IMPERIALISM 0x00484060
int CIncludeView::GetUiInteractiveFlag() {
  return m_uiInteractiveFlag;
}

// FUNCTION: IMPERIALISM 0x00484080
int CIncludeView::SetUiInteractiveFlag(bool interactive) {
  int previous = m_uiInteractiveFlag;
  m_uiInteractiveFlag = interactive;
  return previous;
}

// WM_CHAR: no game handling; defers to DefWindowProc (matches the original).
// FUNCTION: IMPERIALISM 0x004840b0
void CIncludeView::OnChar(UINT nChar, UINT nRepCnt, UINT nFlags) {
  Default();
}

// FUNCTION: IMPERIALISM 0x004840d0
void CIncludeView::CalcWindowRect(LPRECT lpClientRect, UINT nAdjustType) {
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

// FUNCTION: IMPERIALISM 0x00484190
void CIncludeView::OnParentNotify(UINT message, LPARAM lParam) {
  CWnd::OnParentNotify(message, lParam);
  CPoint point(static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam)));
  if (static_cast<unsigned short>(message) == WM_LBUTTONDOWN) {
    OnLButtonDown(0, point);
    if (m_uiInteractiveFlag != 0) {
      if (m_activeDialogContext != 0) {
        CPoint pt(point);
        m_activeDialogContext->HandleMouseUp(pt, 0, CPoint(0, 0));
      }
      g_McAppMouseCaptureState.EndMouseCaptureAndStopRepeatTimer(0, point.x, point.y);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00484230
LRESULT CIncludeView::OnMciNotifyMode(WPARAM wParam, LPARAM mciMode) {
  if (mciMode == MCI_MODE_STOP) {
    g_pViewMgr->ExitTurnState(0);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00484260
void CIncludeView::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags) {
  static TToolboxEvent s_keyCommand;

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

// FUNCTION: IMPERIALISM 0x00484ea0
LPCSTR RegisterAmbitCadreEgoutWindowClass() {
  if (g_AmbitCadreEgoutWndClassAtom == 0) {
    WNDCLASS wndClass;
    memset(&wndClass, 0, sizeof(wndClass));
    wndClass.lpfnWndProc = ::DefWindowProc;
    wndClass.hInstance = AfxGetInstanceHandle();
    wndClass.hCursor = ::LoadCursor(NULL, IDC_ARROW);
    wndClass.style = 0x2000200;
    wndClass.lpszClassName = g_szAmbitCadreEgoutClassName;
    wndClass.hIcon = ::LoadIcon(AfxGetResourceHandle(), MAKEINTRESOURCE(0x7a01));
    if (wndClass.hIcon == NULL) {
      wndClass.hIcon = ::LoadIcon(NULL, IDI_APPLICATION);
    }
    g_AmbitCadreEgoutWndClassAtom = AfxRegisterClass(&wndClass);
  }
  return g_AmbitCadreEgoutWndClassAtom != 0 ? g_szAmbitCadreEgoutClassName : NULL;
}

// Native host view (TView::nativeWindow) of the top window on the modal stack.
// FUNCTION: IMPERIALISM 0x0048d290
static CWnd* GetModalStackTopHostView() {
  if (g_ModalViewStack.GetHeadPosition() != NULL) {
    TView* window = g_ModalViewStack.GetHead();
    window->AssertValid();
    if (window->nativeWindow != 0) {
      return window->nativeWindow;
    }
  }
  return 0;
}

// Native host view of the head window in the live-view registry.
// FUNCTION: IMPERIALISM 0x0048d840
static CWnd* GetLiveRegistryHeadHostView() {
  if (g_LiveViewRegistry.GetHeadPosition() != NULL) {
    TView* window = g_LiveViewRegistry.GetHead();
    window->AssertValid();
    if (window->nativeWindow != 0) {
      return window->nativeWindow;
    }
  }
  return 0;
}
