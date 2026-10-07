#include "game/mfc.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TApplication.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TBehavior.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TWindow.h"
#include "game/app/ui_resource_builder.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/CSubViewIterator.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/gfx/quickdraw_regions.h"
#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeObservation.h"
#include "RuntimeTestDriver.h"
#endif

extern "C" CRuntimeClass PTR_s_TView_006495a0;

// FUNCTION: IMPERIALISM 0x00427200
unsigned short TView::GetCursorID() {
  return cursorId;
}
// FUNCTION: IMPERIALISM 0x00427220
void TView::PostRender() {}

// FUNCTION: IMPERIALISM 0x00427240
void TView::HandleMouseCommandToSelf(CPoint& point, TToolboxEvent* event, CPoint origin) {}

// FUNCTION: IMPERIALISM 0x00427260
void TView::GetExtent(CRect* boundsOut) {
  boundsOut->left = 0;
  boundsOut->top = 0;
  boundsOut->right = frameWidth;
  boundsOut->bottom = frameHeight;
}
// FUNCTION: IMPERIALISM 0x00427290
void TView::GetFrame(CRect* boundsOut) {
  int width = frameWidth;
  int left = ownerLocalX;
  int height = frameHeight;
  int top = ownerLocalY;
  boundsOut->left = left;
  boundsOut->top = top;
  boundsOut->right = width + left;
  boundsOut->bottom = height + top;
}
// FUNCTION: IMPERIALISM 0x004272d0
void TView::TranslateRectToWindow(CRect* rect) {
  LocalToWindow(&rect->TopLeft());
  LocalToWindow(&rect->BottomRight());
}

// FUNCTION: IMPERIALISM 0x00427330
void TView::SuperToLocal(CPoint* point) {
  point->x -= ownerLocalX;
  point->y -= ownerLocalY;
}

// FUNCTION: IMPERIALISM 0x00429410
void TView::GetDrawableQDRect(CRect* rectOut) {
  GetQDExtent(rectOut);
}
// FUNCTION: IMPERIALISM 0x00430bd0
int TView::GetEventNumber() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00430bf0
void TView::Draw(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00430c10
void TView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {}

// FUNCTION: IMPERIALISM 0x00489f60
TView* TViewChildList::FindByTag(unsigned int tag) {
  POSITION position = GetHeadPosition();
  while (position != 0) {
    TView* entry = GetNext(position);
    if (static_cast<unsigned int>(entry->controlTag) == tag) {
      return entry;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00489f90
void TViewChildList::RemoveByTag(unsigned int tag) {
  POSITION position = GetHeadPosition();
  while (position != 0) {
    POSITION current = position;
    TView* child = GetNext(position);
    if (static_cast<unsigned int>(child->controlTag) == tag) {
      RemoveAt(current);
      return;
    }
  }
  if (g_McAppUiFlag_006A1AE0 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x152);
  }
}

// FUNCTION: IMPERIALISM 0x0048a070
void TViewChildList::FreeAll() {
  while (!IsEmpty()) {
    GetHead()->Free();
  }
}

// TView slot 0x00 override: return this class's MFC CRuntimeClass descriptor.

IMPLEMENT_DYNCREATE(TView, TEventHandler)

// FUNCTION: IMPERIALISM 0x0048a8e0
TView::TView()
    : TEventHandler(), ownerContext(0), absoluteX(0), absoluteY(0), controlValue(0), childList(0),
      stylePayload(0), inputGateFlag(1), childHitTestFlag(1), cursorId(0xffff), nativeWindow(0),
      helpState(1), hoverHelpText(), hoverHelpEnabled(0) {}

// FUNCTION: IMPERIALISM 0x0048a9d0
TView::~TView() {
  delete childList;
  delete stylePayload;
}

// FUNCTION: IMPERIALISM 0x0048aa60
void TView::InitializeUiResourceEntryFrameAndParent(TView* resourceContext, TView* panel,
                                                    int* offsetLayout, int* sizeLayout,
                                                    int layoutParam6, int layoutParam7,
                                                    int attachFlag) {
  if (panel != 0) {
    nativeWindow = panel->nativeWindow;
  }
  controlTag = kControlTagSpSpSpSp;
  enabled = 1;
  viewEnabled = 1;
  nextHandler = panel;
  ownerLocalX = offsetLayout[0];
  ownerLocalY = offsetLayout[1];
  frameWidth = sizeLayout[0];
  frameHeight = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, attachFlag);
  }
  this->resourceContext = resourceContext;
}
// FUNCTION: IMPERIALISM 0x0048aaf0
void TView::DispatchControlEventToChildrenAndSelf(int eventArg) {
  if (childList != 0) {
    POSITION pos = childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetNext(pos));
      child->DispatchControlEventToChildrenAndSelf(eventArg);
    }
  }
  DoPostCreate(eventArg);
}
// FUNCTION: IMPERIALISM 0x0048ab70
void TView::DoPostCreate(int arg) {}
// FUNCTION: IMPERIALISM 0x0048ab90
void TView::ForwardMapViewVirtualC4IfPresent(RgnHandle region) {
  if (ownerContext != 0) {
    ownerContext->ForwardMapViewVirtualC4IfPresent(region);
  }
}
// FUNCTION: IMPERIALISM 0x0048abc0
void TView::NoOpUiCallback() {}

// FUNCTION: IMPERIALISM 0x0048abe0
void TView::AttachChildControl(class TView* child, int flag) {
  child->ownerContext = this;
  child->nextHandler = this;

  if (childList == NULL) {
    childList = new TViewChildList();
  }

  if (flag != 0) {
    childList->AddTail(child);
  } else {
    childList->AddHead(child);
  }

  child->UpdateCoordinates();
}

// IMPLEMENT_DYNCREATE also emits `TView::CreateObject` (`return new TView;`).

// Inlines CList<TView*,TView*>::RemoveAt (frees the list's block chain once empty).
// FUNCTION: IMPERIALISM 0x0048ae60
void TView::RemoveSubView(class TView* child) {
  TViewChildList* list = childList;
  if (list == 0) {
    child->ownerContext = 0;
    return;
  }

  unsigned int tag = static_cast<unsigned int>(child->controlTag);
  POSITION pos = list->GetHeadPosition();
  int found = 0;
  while (pos != NULL) {
    POSITION cur = pos;
    TView* entry = static_cast<TView*>(list->GetNext(pos));
    if (tag == static_cast<unsigned int>(entry->controlTag)) {
      list->RemoveAt(cur);
      found = 1;
      break;
    }
  }

  if (found == 0 && g_McAppUiFlag_006A1AE0 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x152);
  }

  if (list->IsEmpty()) {
    delete list;
    childList = 0;
  }
  child->ownerContext = 0;
}
// FUNCTION: IMPERIALISM 0x0048af80
void TView::SwitchActiveChildAndNotify(class TView* child) {
  if (childList != 0 && childList->GetTail() != child) {
    RemoveSubView(child);
    AttachChildControl(child, 1);
    child->RefreshControl();
  }
}
// FUNCTION: IMPERIALISM 0x0048afd0
class TView* TView::FindSubView(unsigned int controlTag) {
  if (controlTag == static_cast<unsigned int>(this->controlTag)) {
    return this;
  }
  if (childList == 0) {
    return 0;
  }

  POSITION pos = childList->GetHeadPosition();
  while (pos != NULL) {
    TView* entry = static_cast<TView*>(childList->GetNext(pos));
    if (controlTag == static_cast<unsigned int>(entry->controlTag)) {
      return entry;
    }
  }

  pos = childList->GetHeadPosition();
  while (pos != NULL) {
    TView* child = static_cast<TView*>(childList->GetNext(pos));
    TView* match = child->FindSubView(controlTag);
    if (match != 0) {
      return match;
    }
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048b070
void TView::ViewEnable(int enabled, int refreshNow) {
  SetEnable(enabled);
  if (refreshNow != 0) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0048b0b0
void TView::Free() {
  while (childList != 0) {
    TEventHandler* child = static_cast<TEventHandler*>(childList->GetHead());
    child->Free();
  }
  if (ownerContext != 0) {
    ownerContext->RemoveSubView(this);
    ownerContext = 0;
  }
  if (g_pApplication != 0 &&
      static_cast<TEventHandler*>(g_pApplication) != static_cast<TEventHandler*>(this)) {
    TEventHandler* currentTarget = g_pApplication->GetTarget();
    if (currentTarget == this) {
      TEventHandler* replacement = GetNextHandler();
      if (replacement == 0) {
        g_pApplication->SetTarget(g_pApplication);
      } else {
        g_pApplication->SetTarget(replacement);
      }
    }
  }
  nextHandler = 0;
  if (firstBehavior != 0) {
    firstBehavior->Free();
  }
  firstBehavior = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0048b180
TWindow* TView::GetWindow() {
  if (ownerContext != 0) {
    return ownerContext->GetWindow();
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048b1a0
TView* TView::GetRootView() {
  if (ownerContext != 0) {
    return ownerContext->GetWindow();
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048b1c0
void TView::Show(int show, int refreshNow) {
  if (show != viewEnabled) {
    viewEnabled = show;
    if (refreshNow != 0) {
      RefreshControl();
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048b200
bool TView::IsActionable() {
  return g_McAppUiActiveFlag != 0 && nativeWindow != 0 && viewEnabled != 0 && ownerContext != 0 &&
         ownerContext->IsActionable();
}
// FUNCTION: IMPERIALISM 0x0048b250
void TView::Locate(const CPoint& position, bool refresh) {
  if (refresh && IsActionable()) {
    InvalidateCityDialogRectRegion(0, 1);
  }
  ownerLocalX = position.x;
  ownerLocalY = position.y;
  UpdateCoordinates();
  if (refresh && IsActionable()) {
    InvalidateCityDialogRectRegion(0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048b2d0
void TView::UpdateCoordinates() {
  TView* owner = ownerContext;
  int oldX = absoluteX;
  int oldY = absoluteY;
  int newX = g_McAppUiDefaultPosX;
  int newY = g_McAppUiDefaultPosY;
  if (owner != 0) {
    newX = owner->absoluteX + ownerLocalX;
    newY = owner->absoluteY + ownerLocalY;
  }
  absoluteX = newX;
  absoluteY = newY;
  if (absoluteX != oldX || absoluteY != oldY) {
    if (childList != 0) {
      CSubViewIterator iterator(this);
      TView* child = iterator.FirstSubView();
      while (iterator.MoreSubViews()) {
        child->UpdateCoordinates();
        child = iterator.NextSubView();
      }
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048b3f0
void TView::Resize(const CPoint& size, bool refresh) {
  if (refresh) {
    CRect oldRect;
    GetDrawableQDRect(&oldRect);
    frameWidth = size.x;
    frameHeight = size.y;
    CRect newRect;
    GetDrawableQDRect(&newRect);
    UnionRect(&newRect, &newRect, &oldRect);
    if (g_McAppUiActiveFlag != 0) {
      InvalidateRect(nativeWindow->m_hWnd, &newRect, 0);
    }
  } else {
    frameWidth = size.x;
    frameHeight = size.y;
  }
}

// FUNCTION: IMPERIALISM 0x0048b4b0
void TView::InvalidateRegion(RgnHandle region) {
  if (nativeWindow == 0) {
    return;
  }

  RgnHandle localRegion = NewRgn();
  if (localRegion == 0 || *localRegion == 0) {
    return;
  }

  HRGN sourceRegion = 0;
  if (region != 0) {
    sourceRegion = static_cast<HRGN>((*region)->rgn);
  }
  HRGN destRegion = static_cast<HRGN>((*localRegion)->rgn.m_hObject);
  CombineRgn(destRegion, sourceRegion, NULL, RGN_COPY);

  CPoint cachedPos;
  GetAbsolutePosition(&cachedPos);
  OffsetRgn(destRegion, -cachedPos.x, -cachedPos.y);

  if (g_McAppUiActiveFlag != 0) {
    InvalidateRgn(nativeWindow->m_hWnd, destRegion, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTestDriver::ObserveDeferred(kObserveInvalidationRequested);
#endif
  }

  DisposeRgn(localRegion);
}

// FUNCTION: IMPERIALISM 0x0048b5f0
void TView::InvalidateCityDialogRectRegion(RECT* rect, int flag) {
  if (nativeWindow == 0 || nativeWindow->m_hWnd == 0) {
    return;
  }
  CRect localRect;
  if (rect == 0) {
    GetDrawableQDRect(&localRect);
  } else {
    CopyRect(&localRect, rect);
    TranslateRectToWindow(&localRect);
  }
  if (g_McAppUiActiveFlag != 0) {
    InvalidateRect(nativeWindow->m_hWnd, &localRect, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTestDriver::ObserveDeferred(kObserveInvalidationRequested);
#endif
  }
}

// FUNCTION: IMPERIALISM 0x0048b690
void TView::ValidateVRect(RECT* rect) {
  if (nativeWindow != 0 && g_McAppUiActiveFlag != 0) {
    ValidateRect(nativeWindow->m_hWnd, rect);
  }
}
// FUNCTION: IMPERIALISM 0x0048b6d0
void TView::RefreshControl() {
  if (g_McAppUiActiveFlag != 0 && nativeWindow != 0) {
    InvalidateCityDialogRectRegion(0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x0048b700
void TView::ForceRedraw() {
  if (ownerContext != 0) {
    ownerContext->ForceRedraw();
    return;
  }
  if (g_McAppUiUpdateWindowRecursionGuard == 0) {
    g_McAppUiUpdateWindowRecursionGuard = 1;
    if (nativeWindow != 0 && g_McAppUiActiveFlag != 0) {
      UpdateWindow(nativeWindow->m_hWnd);
    }
    g_McAppUiUpdateWindowRecursionGuard = 0;
  }
}
// FUNCTION: IMPERIALISM 0x0048b770
bool TView::PrepareForDrawing() {
  if (this != g_McAppUiActiveRenderContext) {
    SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));
    g_McAppUiActiveRenderContext = this;
  }
  return true;
}
// FUNCTION: IMPERIALISM 0x0048b7b0
int TView::BindMapQuickDrawDc(CDC* paintDc) {
  return BindScopedMapQuickDrawDcHandle(this, paintDc);
}

// FUNCTION: IMPERIALISM 0x0048b7e0
void TView::ReleaseMapQuickDrawDc(CDC* paintDc) {
  ReleaseScopedMapQuickDrawDcHandle(this, paintDc);
}
// stylePayload is freed in ~TView.
// FUNCTION: IMPERIALISM 0x0048b810
void TView::EnsureStylePayload() {
  if (stylePayload == 0) {
    stylePayload = new TUiStyleBytes();
  }
}
// FUNCTION: IMPERIALISM 0x0048b860
void TView::PaintOrInvalidateControl(CDC* paintDc) {
  if (paintDc != 0) {
    CRect rect;
    GetExtent(&rect);
    PaintVisibleChildrenIntersectingClipRect(&rect, paintDc);
    return;
  }
  InvalidateCityDialogRectRegion(0, 0);
}

// FUNCTION: IMPERIALISM 0x0048b8d0
void TView::PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, CDC* paintDc) {
  if (g_McAppUiActiveFlag == 0 || !IsActionable() || !PrepareForDrawing()) {
    return;
  }

  CRect clippedRect;
  GetExtent(&clippedRect);
  if (IntersectRect(&clippedRect, &clippedRect, clipRect) == 0) {
    return;
  }

  if (BindMapQuickDrawDc(paintDc) != 0) {
    Draw(&clippedRect);
    if (firstBehavior != 0) {
      firstBehavior->Draw(&clippedRect);
    }
    ReleaseMapQuickDrawDc(paintDc);
  }

  TViewChildList* list = childList;
  if (list != 0) {
    POSITION pos = list->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(list->GetNext(pos));
      RECT childClip = clippedRect;
      OffsetRect(&childClip, -child->ownerLocalX, -child->ownerLocalY);
      RECT childPaintRect;
      CopyRect(&childPaintRect, &childClip);
      child->PaintVisibleChildrenIntersectingClipRect(&childPaintRect, paintDc);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048ba40
void TView::TranslatePointToParentChain4E(CPoint* point) {
  point->y += ownerLocalY;
  point->x += ownerLocalX;
  ownerContext->TranslatePointToParentChain4E(point);
}
// FUNCTION: IMPERIALISM 0x0048ba80
void TView::LocalToWindow(CPoint* point) {
  int offY = ownerLocalY;
  point->x += ownerLocalX;
  point->y += offY;
  ownerContext->LocalToWindow(point);
}
// Mirror of LocalToWindow/4E above, but subtracts instead of adding.
// FUNCTION: IMPERIALISM 0x0048bac0
void TView::WindowToLocal(CPoint* point) {
  int offY = ownerLocalY;
  point->x -= ownerLocalX;
  point->y -= offY;
  ownerContext->WindowToLocal(point);
}

// FUNCTION: IMPERIALISM 0x0048bb00
void TView::LocalToSuperVRect(CRect* rect) {
  int offsetX = ownerLocalX;
  int offsetY = ownerLocalY;
  OffsetRect(rect, offsetX, offsetY);
}

// FUNCTION: IMPERIALISM 0x0048bb30
CPoint* TView::GetAbsolutePosition(CPoint* outPoint) {
  int posY = absoluteY;
  outPoint->x = absoluteX;
  outPoint->y = posY;
  return outPoint;
}

// FUNCTION: IMPERIALISM 0x0048bb60
CPoint TView::ViewToQDPt(CPoint* inPoint) {
  CPoint local;
  local.x = inPoint->x;
  local.y = inPoint->y;
  TranslatePointToParentChain4E(&local);
  return local;
}

// FUNCTION: IMPERIALISM 0x0048bbb0
CRect TView::ViewToQDRect(CRect* inRect) {
  int width = inRect->right - inRect->left;
  int height = inRect->bottom - inRect->top;
  CPoint corner;
  corner.x = inRect->left;
  corner.y = inRect->top;
  CPoint mapped = ViewToQDPt(&corner);
  return CRect(mapped.x, mapped.y, mapped.x + width, mapped.y + height);
}
// FUNCTION: IMPERIALISM 0x0048bc30
void TView::AddControlPosToPoint(int x, int y, CPoint* outPoint) {
  x += absoluteX;
  y = absoluteY + y;
  outPoint->x = x;
  outPoint->y = y;
}

// FUNCTION: IMPERIALISM 0x0048bc60
void TView::OffsetRectByCachedPos(CRect* inRect, CRect* outRect) {
  CRect local;
  local.left = inRect->left;
  local.top = inRect->top;
  local.right = inRect->right;
  local.bottom = inRect->bottom;
  OffsetRect(&local, absoluteX, absoluteY);
  outRect->left = local.left;
  outRect->top = local.top;
  outRect->right = local.right;
  outRect->bottom = local.bottom;
}

// FUNCTION: IMPERIALISM 0x0048bce0
CRect* TView::GetQDExtent(CRect* rectOut) {
  int width = frameWidth;
  int height = frameHeight;
  CPoint pos;
  GetAbsolutePosition(&pos);
  rectOut->left = pos.x;
  rectOut->top = pos.y;
  rectOut->right = width + pos.x;
  rectOut->bottom = height + pos.y;
  return rectOut;
}

// FUNCTION: IMPERIALISM 0x0048bd30
TView::TView(const TView& source)
    : TEventHandler(source), ownerContext(0), ownerLocalX(source.ownerLocalX),
      ownerLocalY(source.ownerLocalY), absoluteX(source.absoluteX), absoluteY(source.absoluteY),
      frameWidth(source.frameWidth), frameHeight(source.frameHeight),
      controlValue(source.controlValue), childList(0), stylePayload(0),
      inputGateFlag(source.inputGateFlag), childHitTestFlag(source.childHitTestFlag),
      nativeWindow(source.nativeWindow), helpState(source.helpState), hoverHelpText(),
      hoverHelpEnabled(0) {
  if (source.childList != 0) {
    POSITION position = source.childList->GetHeadPosition();
    while (position != 0) {
      TView* child = source.childList->GetNext(position);
      AttachChildControl(static_cast<TView*>(child->ShallowClone()), 0);
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048bef0
void TView::CopyViewStateFromSource(TView* source) {
  enabled = source->enabled;
  viewEnabled = source->viewEnabled;
  controlTag = source->controlTag;
  nextHandler = source->nextHandler;
  ownerContext = 0;
  nativeWindow = source->nativeWindow;
  childList = 0;
  stylePayload = 0;
  controlValue = source->controlValue;
  helpState = source->helpState;
  ownerLocalX = source->ownerLocalX;
  ownerLocalY = source->ownerLocalY;
  absoluteX = source->absoluteX;
  absoluteY = source->absoluteY;
  frameWidth = source->frameWidth;
  frameHeight = source->frameHeight;
  inputGateFlag = source->inputGateFlag;
  childHitTestFlag = source->childHitTestFlag;
  if (source->childList != 0) {
    POSITION pos = source->childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(source->childList->GetNext(pos));
      TView* childClone = static_cast<TView*>(child->ShallowClone());
      AttachChildControl(childClone, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048bfd0
TObject* TView::ShallowClone() {
  TView* clone = static_cast<TView*>(ShallowFree());
  clone->CopyViewStateFromSource(this);
  return clone;
}

// FUNCTION: IMPERIALISM 0x0048c000
bool TView::EvaluateControlInputGate() {
  if (hoverHelpEnabled == 0) {
    if (static_cast<char>(inputGateFlag) != 0 && IsEnabled() != 0) {
      return true;
    }
    if (!HasRenderableParentAndContent()) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x0048c050
bool TView::HasRenderableParentAndContent() {
  return childHitTestFlag && childList != 0 && !childList->IsEmpty();
}

// FUNCTION: IMPERIALISM 0x0048c080
void TView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point, RgnHandle hitArg) {
  if (HasRenderableParentAndContent()) {
    if (childList != 0) {
      POSITION pos = childList->GetHeadPosition();
      while (pos != NULL) {
        TView* child = static_cast<TView*>(childList->GetNext(pos));

        CPoint childPoint = *point;
        child->SuperToLocal(&childPoint);
        if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
            child->EvaluateControlInputGate()) {
          child->HandleCursorHoverSelectionByChildHitTestAndFallback(&childPoint, hitArg);
          return;
        }
      }
    }
  }

  if (EmptyRgn(hitArg) != 0 && PrepareForDrawing()) {
    DoSetCursor(point, hitArg);
  }
}

// FUNCTION: IMPERIALISM 0x0048c1c0
void TView::HandleHelp(const CPoint* point, RgnHandle helpRegion) {}

// FUNCTION: IMPERIALISM 0x0048c1e0
void TView::GetDrawableRegion(RgnHandle clipRegion) {
  CRect rect;
  GetDrawableQDRect(&rect);
  RectRgn(clipRegion, &rect);
}

// FUNCTION: IMPERIALISM 0x0048c220
void TView::SetHoverHelpText(const CString& sharedString) {
  hoverHelpEnabled = 1;
  hoverHelpText = sharedString;
}

// FUNCTION: IMPERIALISM 0x0048c250
void TView::DoSetCursor(CPoint* point, RgnHandle hitArg) {
  if (hoverHelpEnabled != 0) {
    CRect extentStorage;
    CRect quickDrawExtent(*GetQDExtent(&extentStorage));
    RECT hoverHelpRect;
    CopyRect(&hoverHelpRect, &quickDrawExtent);
    if (g_pCursorControlPanel != NULL) {
      g_pCursorControlPanel->HotText(hoverHelpText, &hoverHelpRect);
    }
  }
  short cursorId = GetCursorID();
  if (cursorId != -1) {
    CPoint transformedPoint = ViewToQDPt(point);
    if (PtInRgn(&transformedPoint, hitArg)) {
      QuickDrawCursorHandle cursorHandle = GetQuickDrawCursor(cursorId);
      SetQuickDrawCursor(*cursorHandle);
      return;
    }
  }
  HCURSOR hCursor = LoadCursorA(NULL, IDC_ARROW);
  SetCursor(hCursor);
}
// FUNCTION: IMPERIALISM 0x0048c380
void TView::SetFrame(CRect* newBounds, bool modeFlag) {
  CRect current;
  GetFrame(&current);
  if (EqualRect(newBounds, &current) == 0) {
    if (modeFlag && IsActionable()) {
      InvalidateCityDialogRectRegion(0, 1);
    }
    ownerLocalX = newBounds->left;
    ownerLocalY = newBounds->top;
    frameWidth = newBounds->right - newBounds->left;
    frameHeight = newBounds->bottom - newBounds->top;
    UpdateCoordinates();
    if (modeFlag && IsActionable()) {
      InvalidateCityDialogRectRegion(0, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048c450
bool TView::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (childList != 0) {
    POSITION pos = childList->GetTailPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetPrev(pos));

      CPoint childPoint = point;
      child->SuperToLocal(&childPoint);
      if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
          child->HandleMouseDown(childPoint, event, origin)) {
        return true;
      }
    }
  }

  if (PrepareForDrawing() && IsEnabled() != 0) {
    CPoint localPoint = point;
    DoMouseCommand(localPoint, event, origin);
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x0048c590
char TView::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (childList != 0) {
    POSITION pos = childList->GetTailPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetPrev(pos));

      CPoint childPoint = point;
      child->SuperToLocal(&childPoint);
      if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
          child->HandleMouseUp(childPoint, event, origin) != 0) {
        return 1;
      }
    }
  }

  if (PrepareForDrawing()) {
    CPoint localPoint = point;
    if (IsEnabled() != 0) {
      HandleMouseCommandToSelf(localPoint, event, origin);
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c6d0
char TView::PointInBoundsAndActionable(CPoint* point) {
  CRect bounds;
  GetExtent(&bounds);
  if (IsActionable()) {
    POINT p;
    p.x = point->x;
    p.y = point->y;
    if (PtInRect(&bounds, p) != 0) {
      return 1;
    }
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048c750
void TView::DrawRectangleInCurrentUiContext(const RECT* rect) {
  if (g_McAppUiDrawGate == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x772);
  }
  CDC* context = GetActiveQuickDrawDc();
  Rectangle(context->m_hDC, rect->left, rect->top, rect->right, rect->bottom);
}
// FUNCTION: IMPERIALISM 0x0048c7a0
void TView::AssertMcAppUiLine1914(int unusedArg) {
  if (g_McAppUiFlag_006A1AFC == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x77a);
  }
}

// FUNCTION: IMPERIALISM 0x0048c7d0
void TView::AssertMcAppUiLine1922() {
  if (g_McAppUiFlag_006A1B00 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x782);
  }
  CRect rectStorage;
  GetDrawableQDRect(&rectStorage);
}

// FUNCTION: IMPERIALISM 0x0048c820
CWnd* TView::Open() {
  if (childList != 0) {
    POSITION pos = childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetNext(pos));
      child->Open();
    }
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048c890
void TView::Close() {
  if (childList != 0) {
    POSITION pos = childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetNext(pos));
      child->Close();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048c900
void TView::PropagateUiResourceContextRecursive(CWnd* nativeWindow) {
  this->nativeWindow = nativeWindow;
  if (childList != 0) {
    POSITION pos = childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetNext(pos));
      child->PropagateUiResourceContextRecursive(nativeWindow);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048c970
unsigned short TView::GetHelpState() {
  return helpState;
}
// FUNCTION: IMPERIALISM 0x0048c990
short TView::ContainsMouse(const CPoint& point) {
  CRect bounds;
  GetExtent(&bounds);
  POINT p;
  p.x = point.x;
  p.y = point.y;
  // Returns 3 (not 1) on hit, unlike PointInBoundsAndActionable's near-identical body above.
  return PtInRect(&bounds, p) ? 3 : 0;
}
// FUNCTION: IMPERIALISM 0x0048c9e0
void TView::GoAwayByUser(const CPoint& point) {}
// FUNCTION: IMPERIALISM 0x0048ca00
void TView::MoveByUser(const CPoint& point) {}
// FUNCTION: IMPERIALISM 0x0048ca20
void TView::ResizeByUser(const CPoint& point) {}
// FUNCTION: IMPERIALISM 0x0048ca40
void TView::ZoomByUser(const CPoint& point, short partCode) {}
