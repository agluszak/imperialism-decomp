#include "game/mfc.h"
#include "game/TApplication.h"
#include "game/TEventHandler.h"
#include "game/TView.h"
#include "game/TBehavior.h"
#include "game/TInfoBarText.h"
#include "game/TDialogBehavior.h"
#include "game/TWindow.h"
#include "game/ui_resource_builder.h"
#include "game/global_data_tables.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_regions.h"

// Shared thunks/hooks whose callers interpret the arguments differently are kept in
// generic repo form (rule 9) with a typed cast at the callsite.

extern "C" CRuntimeClass PTR_s_TView_006495a0;

// UI-resource context helpers 0x426fa0-0x4270e0: original TU is this TView region
// (0x4272xx methods follow); they operate on g_pUiResourceContext from ui_resource_builder.h.
// FUNCTION: IMPERIALISM 0x00426fa0
void __cdecl SetUiResourceContextFlagsAndMetrics(short nField9C, short nStyleType, bool f70,
                                                 bool f6f, bool f6e, bool f6d, bool f6c, bool f71) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->topmostFlag70 = f70;
  window->resourceFlag6f = f6f;
  window->resourceFlag6e = f6e;
  window->useCaptionedFrameFlag6d = f6d;
  window->resourceFlag6c = f6c;
  window->resourceFlag71 = f71;
  window->windowFlags = static_cast<unsigned short>(nField9C);
  window->windowStyleType = nStyleType;
}

// FUNCTION: IMPERIALISM 0x00427010
void __cdecl ApplyUiResourceColorTripletFromContext(unsigned char nFlag0C,
                                                    unsigned char nTripletFlag, int colorA,
                                                    int colorB) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->GetDialogBehavior()->SetEnabled(nFlag0C);
  window->GetDialogBehavior()->SetUiColorDescriptorGoldTriplet(nTripletFlag, colorA, colorB);
}

// Replaces the context widget's stylePayload48 style payload. Note the original writes
// through stylePayload48 without re-checking the fresh allocation for null — faithful.
// FUNCTION: IMPERIALISM 0x00427060
void __cdecl ReplaceUiResourceContextPairBuffer(int styleWord, int packedColor) {
  TView* context = g_pUiResourceContext;
  delete context->stylePayload48;
  context->stylePayload48 = new TUiStyleBytes();
  context->stylePayload48->styleWord = styleWord;
  context->stylePayload48->packedColor = packedColor;
}

// FUNCTION: IMPERIALISM 0x004270e0
TUiStyleRef::TUiStyleRef(int value) {
  this->value = value;
}

// FUNCTION: IMPERIALISM 0x00427200
unsigned short TView::GetCursorID() {
  return cursorId4e;
}
// FUNCTION: IMPERIALISM 0x00427220
void TView::PostRender() {}

// FUNCTION: IMPERIALISM 0x00427240
char TView::HandleMouseCommandToSelf(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)point;
  (void)event;
  (void)origin;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00427260
void TView::QueryContentBounds(CRect* boundsOut) {
  boundsOut->left = 0;
  boundsOut->top = 0;
  boundsOut->right = frameWidth34;
  boundsOut->bottom = frameHeight38;
}
// FUNCTION: IMPERIALISM 0x00427290
void TView::QueryBounds(CRect* boundsOut) {
  int width = frameWidth34;
  int left = ownerLocalX;
  int height = frameHeight38;
  int top = ownerLocalY;
  boundsOut->left = left;
  boundsOut->top = top;
  boundsOut->right = width + left;
  boundsOut->bottom = height + top;
}
// FUNCTION: IMPERIALISM 0x004272d0
void TView::TranslateRectToWindow(CRect* rect) {
  TranslatePointToParentChain4D(&rect->TopLeft());
  TranslatePointToParentChain4D(&rect->BottomRight());
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
void TView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
}

// Base TView slot 0x47: orphan RET 0x10 stub (real capture on TControl 0x48e640).

// FUNCTION: IMPERIALISM 0x00430c10
void TView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)point;
  (void)event;
  (void)origin;
}

// TViewChildList's compiler-emitted CList<TView*,TView*>::Serialize body. The real source is
// the childList44 template type in TView, not a TView method or TEventHandler record pool.
// TEMPLATE: IMPERIALISM 0x00479be0
// ?Serialize@?$CList@PAVTView@@PAV1@@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x00479d50
// ??_G?$CList@PAVTView@@PAV1@@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x00479d80
// ??1?$CList@PAVTView@@PAV1@@@UAE@XZ

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
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x152);
  }
}

// FUNCTION: IMPERIALISM 0x0048a070
void TViewChildList::FreeAll() {
  while (!IsEmpty()) {
    GetHead()->Free();
  }
}
// SYNTHETIC: IMPERIALISM 0x0048a840
// TView::CreateObject

// TView slot 0x00 override: return this class's MFC CRuntimeClass descriptor.
// SYNTHETIC: IMPERIALISM 0x0048a8c0
// TView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TView, TEventHandler)

// FUNCTION: IMPERIALISM 0x0048a8e0
TView::TView()
    : TEventHandler(), ownerContext(0), absoluteX(0), absoluteY(0), controlValue3c(0),
      childList44(0), stylePayload48(0), inputGateFlag4c(1), childHitTestFlag4d(1),
      cursorId4e(0xffff), nativeWindow50(0), helpState54(1), hoverHelpText58(),
      hoverHelpEnabled5c(0) {}

// SYNTHETIC: IMPERIALISM 0x0048a9a0
// TView::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0048a9d0
TView::~TView() {
  delete childList44;
  delete stylePayload48;
}

// FUNCTION: IMPERIALISM 0x0048aa60
void TView::InitializeUiResourceEntryFrameAndParent(TView* resourceContext, TView* panel,
                                                    int* offsetLayout, int* sizeLayout,
                                                    int layoutParam6, int layoutParam7,
                                                    int attachFlag) {
  (void)layoutParam6;
  (void)layoutParam7;
  if (panel != 0) {
    nativeWindow50 = panel->nativeWindow50;
  }
  controlTag = 0x20202020;
  field04 = 1;
  field08 = 1;
  linkedChildHandler = panel;
  ownerLocalX = offsetLayout[0];
  ownerLocalY = offsetLayout[1];
  frameWidth34 = sizeLayout[0];
  frameHeight38 = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, attachFlag);
  }
  this->resourceContext = resourceContext;
}
// FUNCTION: IMPERIALISM 0x0048aaf0
void TView::DispatchControlEventToChildrenAndSelf(int eventArg) {
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->DispatchControlEventToChildrenAndSelf(eventArg);
    }
  }
  DoPostCreate(eventArg);
}
// FUNCTION: IMPERIALISM 0x0048ab70
void TView::DoPostCreate(int arg) {
  (void)arg;
}
// FUNCTION: IMPERIALISM 0x0048ab90
void TView::ForwardMapViewVirtualC4IfPresent(int param) {
  if (ownerContext != 0) {
    ownerContext->ForwardMapViewVirtualC4IfPresent(param);
  }
}
// FUNCTION: IMPERIALISM 0x0048abc0
void TView::NoOpUiCallback() {}

// FUNCTION: IMPERIALISM 0x0048abe0
void TView::AttachChildControl(class TView* child, int flag) {
  child->ownerContext = this;
  child->linkedChildHandler = this;

  if (childList44 == nullptr) {
    childList44 = new TViewChildList();
  }

  if (flag != 0) {
    childList44->AddTail(child);
  } else {
    childList44->AddHead(child);
  }

  child->UpdateCoordinates();
}
// TEMPLATE: IMPERIALISM 0x0048ada0
// ??_G?$CList@PAVTView@@PAV1@@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x0048add0
// ??1?$CList@PAVTView@@PAV1@@@UAE@XZ

// IMPLEMENT_DYNCREATE also emits `TView::CreateObject` (`return new TView;`).

// Inlines CList<TView*,TView*>::RemoveAt (frees the list's block chain once empty).
// FUNCTION: IMPERIALISM 0x0048ae60
void TView::DetachChildFromOwnerList(class TView* child) {
  TViewChildList* list = childList44;
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
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x152);
  }

  if (list->IsEmpty()) {
    delete list;
    childList44 = 0;
  }
  child->ownerContext = 0;
}
// FUNCTION: IMPERIALISM 0x0048af80
void TView::SwitchActiveChildAndNotify(class TView* child) {
  if (childList44 != 0 && childList44->GetTail() != child) {
    DetachChildFromOwnerList(child);
    AttachChildControl(child, 1);
    child->RefreshControl();
  }
}
// Scans the direct child list first, then recurses via slot 0x25. The own-tag case
// short-circuits — callers exclude self, this is purely a descendant search.
// FUNCTION: IMPERIALISM 0x0048afd0
class TView* TView::ResolveControlByTag(unsigned int controlTag) {
  if (controlTag == static_cast<unsigned int>(this->controlTag)) {
    return this;
  }
  if (childList44 == 0) {
    return 0;
  }

  POSITION pos = childList44->GetHeadPosition();
  while (pos != NULL) {
    TView* entry = static_cast<TView*>(childList44->GetNext(pos));
    if (controlTag == static_cast<unsigned int>(entry->controlTag)) {
      return entry;
    }
  }

  pos = childList44->GetHeadPosition();
  while (pos != NULL) {
    TView* child = static_cast<TView*>(childList44->GetNext(pos));
    TView* match = child->ResolveControlByTag(controlTag);
    if (match != 0) {
      return match;
    }
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048b070
void TView::SetState(int state, int refreshFlag) {
  (void)refreshFlag;
  SetEnable(state);
  if (state != 0) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0048b0b0
void TView::Free() {
  while (childList44 != 0) {
    TEventHandler* child = static_cast<TEventHandler*>(childList44->GetHead());
    child->Free();
  }
  if (ownerContext != 0) {
    ownerContext->DetachChildFromOwnerList(this);
    ownerContext = 0;
  }
  if (g_pApplicationUiRootController != 0 &&
      static_cast<TEventHandler*>(g_pApplicationUiRootController) !=
          static_cast<TEventHandler*>(this)) {
    TEventHandler* currentTarget = g_pApplicationUiRootController->GetTarget();
    if (currentTarget == this) {
      TEventHandler* replacement = GetNextHandler();
      if (replacement == 0) {
        g_pApplicationUiRootController->SetTarget(g_pApplicationUiRootController);
      } else {
        g_pApplicationUiRootController->SetTarget(replacement);
      }
    }
  }
  field0c = 0;
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
void TView::SetEnabled(int enabledState, int refreshFlag) {
  if (enabledState != field08) {
    field08 = enabledState;
    if (refreshFlag != 0) {
      RefreshControl();
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048b200
char TView::IsActionable() {
  return g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0 && field08 != 0 &&
         ownerContext != 0 && ownerContext->IsActionable() != 0;
}
// FUNCTION: IMPERIALISM 0x0048b250
void TView::CaptureLayoutF0(int* buffer, int modeFlag) {
  if (modeFlag != 0 && IsActionable() != 0) {
    InvalidateCityDialogRectRegion(0, 1);
  }
  ownerLocalX = buffer[0];
  ownerLocalY = buffer[1];
  UpdateCoordinates();
  if (modeFlag != 0 && IsActionable() != 0) {
    InvalidateCityDialogRectRegion(0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048b2d0
void TView::UpdateCoordinates() {
  TView* owner = ownerContext;
  int oldX = absoluteX;
  int oldY = absoluteY;
  int newX = g_McAppUiDefaultPosX_006A1A60;
  int newY = g_McAppUiDefaultPosY_006A1A64;
  if (owner != 0) {
    newX = owner->absoluteX + ownerLocalX;
    newY = owner->absoluteY + ownerLocalY;
  }
  absoluteX = newX;
  absoluteY = newY;
  if (absoluteX != oldX || absoluteY != oldY) {
    if (childList44 != 0) {
      POSITION pos = childList44->GetHeadPosition();
      while (pos != NULL) {
        TView* child = static_cast<TView*>(childList44->GetNext(pos));
        child->UpdateCoordinates();
      }
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048b3f0
void TView::CaptureLayout(int* buffer, int modeFlag) {
  if (modeFlag != 0) {
    CRect oldRect;
    GetDrawableQDRect(&oldRect);
    frameWidth34 = buffer[0];
    frameHeight38 = buffer[1];
    CRect newRect;
    GetDrawableQDRect(&newRect);
    RECT unionRect;
    UnionRect(&unionRect, &newRect, &oldRect);
    if (g_McAppUiActiveFlag_006950AC != 0) {
      InvalidateRect(nativeWindow50->m_hWnd, &unionRect, 0);
    }
  } else {
    frameWidth34 = buffer[0];
    frameHeight38 = buffer[1];
  }
}

// FUNCTION: IMPERIALISM 0x0048b4b0
void TView::InvalidateOffsetRegionUsingChildClipRect(RgnHandle region) {
  if (nativeWindow50 == 0) {
    return;
  }

  RgnHandle localRegion = NewRgn();
  if (localRegion == 0 || *localRegion == 0) {
    return;
  }

  // CRgn::operator HRGN's this==NULL check absorbs the "nil region" sentinel
  // (a Region* placed so &(*region)->rgn == NULL) some callers store in the handle.
  HRGN sourceRegion = 0;
  if (region != 0) {
    sourceRegion = static_cast<HRGN>((*region)->rgn);
  }
  HRGN destRegion = static_cast<HRGN>((*localRegion)->rgn.m_hObject);
  CombineRgn(destRegion, sourceRegion, nullptr, RGN_COPY);

  CPoint cachedPos;
  GetAbsolutePosition(&cachedPos);
  OffsetRgn(destRegion, -cachedPos.x, -cachedPos.y);

  if (g_McAppUiActiveFlag_006950AC != 0) {
    InvalidateRgn(nativeWindow50->m_hWnd, destRegion, 0);
  }

  DisposeRgn(localRegion);
}

// FUNCTION: IMPERIALISM 0x0048b5f0
void TView::InvalidateCityDialogRectRegion(RECT* rect, int flag) {
  (void)flag;
  if (nativeWindow50 == 0 || nativeWindow50->m_hWnd == 0) {
    return;
  }
  CRect localRect;
  if (rect == 0) {
    GetDrawableQDRect(&localRect);
  } else {
    CopyRect(&localRect, rect);
    TranslateRectToWindow(&localRect);
  }
  if (g_McAppUiActiveFlag_006950AC != 0) {
    InvalidateRect(nativeWindow50->m_hWnd, &localRect, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048b690
void TView::ValidateControlRectIfWindowActive(RECT* rect) {
  if (nativeWindow50 != 0 && g_McAppUiActiveFlag_006950AC != 0) {
    ValidateRect(nativeWindow50->m_hWnd, rect);
  }
}
// FUNCTION: IMPERIALISM 0x0048b6d0
void TView::RefreshControl() {
  if (g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0) {
    InvalidateCityDialogRectRegion(0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x0048b700
void TView::ForceRedraw() {
  if (ownerContext != 0) {
    ownerContext->ForceRedraw();
    return;
  }
  if (g_McAppUiUpdateWindowRecursionGuard_006A1AF0 == 0) {
    g_McAppUiUpdateWindowRecursionGuard_006A1AF0 = 1;
    if (nativeWindow50 != 0 && g_McAppUiActiveFlag_006950AC != 0) {
      UpdateWindow(nativeWindow50->m_hWnd);
    }
    g_McAppUiUpdateWindowRecursionGuard_006A1AF0 = 0;
  }
}
// FUNCTION: IMPERIALISM 0x0048b770
char TView::PrepareForDrawing() {
  if (this != g_McAppUiActiveRenderContext_006A1AF4) {
    SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));
    g_McAppUiActiveRenderContext_006A1AF4 = this;
  }
  return 1;
}
// FUNCTION: IMPERIALISM 0x0048b7b0
int TView::BindMapQuickDrawDc(CDC* paintDc) {
  return BindScopedMapQuickDrawDcHandle(this, paintDc);
}

// FUNCTION: IMPERIALISM 0x0048b7e0
void TView::ReleaseMapQuickDrawDc(CDC* paintDc) {
  ReleaseScopedMapQuickDrawDcHandle(this, paintDc);
}
// stylePayload48 is freed in ~TView.
// FUNCTION: IMPERIALISM 0x0048b810
void TView::EnsureField48Buffer() {
  if (stylePayload48 == 0) {
    stylePayload48 = new TUiStyleBytes();
  }
}
// FUNCTION: IMPERIALISM 0x0048b860
void TView::PaintOrInvalidateControl(CDC* paintDc) {
  if (paintDc != 0) {
    CRect rect;
    QueryContentBounds(&rect);
    PaintVisibleChildrenIntersectingClipRect(&rect, paintDc);
    return;
  }
  InvalidateCityDialogRectRegion(0, 0);
}

// FUNCTION: IMPERIALISM 0x0048b8d0
void TView::PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, CDC* paintDc) {
  if (g_McAppUiActiveFlag_006950AC == 0 || IsActionable() == 0 || PrepareForDrawing() == 0) {
    return;
  }

  CRect clippedRect;
  QueryContentBounds(&clippedRect);
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

  TViewChildList* list = childList44;
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

// Same offset-and-recurse shape as TranslatePointToParentChain4D below (0x4d/0x4e are
// distinct vtable slots; both bottom out here at the root owner).
// FUNCTION: IMPERIALISM 0x0048ba40
void TView::TranslatePointToParentChain4E(CPoint* point) {
  point->y += ownerLocalY;
  point->x += ownerLocalX;
  ownerContext->TranslatePointToParentChain4E(point);
}
// FUNCTION: IMPERIALISM 0x0048ba80
void TView::TranslatePointToParentChain4D(CPoint* point) {
  int offY = ownerLocalY;
  point->x += ownerLocalX;
  point->y += offY;
  ownerContext->TranslatePointToParentChain4D(point);
}
// Mirror of TranslatePointToParentChain4D/4E above, but subtracts instead of adding.
// FUNCTION: IMPERIALISM 0x0048bac0
void TView::WindowToLocal(CPoint* point) {
  int offY = ownerLocalY;
  point->x = point->x - ownerLocalX;
  point->y = point->y - offY;
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
  x = x + absoluteX;
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
  int width = frameWidth34;
  int height = frameHeight38;
  CPoint pos;
  GetAbsolutePosition(&pos);
  rectOut->left = pos.x;
  rectOut->top = pos.y;
  rectOut->right = width + pos.x;
  rectOut->bottom = height + pos.y;
  return rectOut;
}

// Base copy constructor used by the derived view copy constructors at 0x48e5c0,
// 0x48f080, 0x48f9d0, and 0x491540. The source child list is cloned structurally;
// it is not the invented 0x649a50 modal-state class previously assigned here.
// FUNCTION: IMPERIALISM 0x0048bd30
TView::TView(const TView& source)
    : TEventHandler(source), ownerContext(0), ownerLocalX(source.ownerLocalX),
      ownerLocalY(source.ownerLocalY), absoluteX(source.absoluteX), absoluteY(source.absoluteY),
      frameWidth34(source.frameWidth34), frameHeight38(source.frameHeight38),
      controlValue3c(source.controlValue3c), childList44(0), stylePayload48(0),
      inputGateFlag4c(source.inputGateFlag4c), childHitTestFlag4d(source.childHitTestFlag4d),
      nativeWindow50(source.nativeWindow50), helpState54(source.helpState54), hoverHelpText58(),
      hoverHelpEnabled5c(0) {
  if (source.childList44 != 0) {
    POSITION position = source.childList44->GetHeadPosition();
    while (position != 0) {
      TView* child = source.childList44->GetNext(position);
      AttachChildControl(static_cast<TView*>(child->ShallowClone()), 0);
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048bef0
void TView::CopyViewStateFromSource(TView* source) {
  field04 = source->field04;
  field08 = source->field08;
  controlTag = source->controlTag;
  field0c = source->field0c;
  ownerContext = 0;
  nativeWindow50 = source->nativeWindow50;
  childList44 = 0;
  stylePayload48 = 0;
  controlValue3c = source->controlValue3c;
  helpState54 = source->helpState54;
  ownerLocalX = source->ownerLocalX;
  ownerLocalY = source->ownerLocalY;
  absoluteX = source->absoluteX;
  absoluteY = source->absoluteY;
  frameWidth34 = source->frameWidth34;
  frameHeight38 = source->frameHeight38;
  inputGateFlag4c = source->inputGateFlag4c;
  childHitTestFlag4d = source->childHitTestFlag4d;
  if (source->childList44 != 0) {
    POSITION pos = source->childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(source->childList44->GetNext(pos));
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
char TView::EvaluateControlInputGate() {
  if (hoverHelpEnabled5c == 0) {
    if ((char)inputGateFlag4c != 0 && IsEnabled() != 0) {
      return 1;
    }
    if (HasRenderableParentAndContent() == 0) {
      return 0;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0048c050
char TView::HasRenderableParentAndContent() {
  if (childHitTestFlag4d != 0 && childList44 != 0 && !childList44->IsEmpty()) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c080
void TView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point, RgnHandle hitArg) {
  if (HasRenderableParentAndContent() != 0) {
    if (childList44 != 0) {
      POSITION pos = childList44->GetHeadPosition();
      while (pos != NULL) {
        TView* child = static_cast<TView*>(childList44->GetNext(pos));

        CPoint childPoint = *point;
        child->SuperToLocal(&childPoint);
        if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
            child->EvaluateControlInputGate() != 0) {
          child->HandleCursorHoverSelectionByChildHitTestAndFallback(&childPoint, hitArg);
          return;
        }
      }
    }
  }

  if (EmptyRgn(hitArg) != 0 && PrepareForDrawing() != 0) {
    DoSetCursor(point, hitArg);
  }
}

// FUNCTION: IMPERIALISM 0x0048c1c0
void TView::HandleHelp(const CPoint* point, RgnHandle helpRegion) {
  (void)point;
  (void)helpRegion;
}

// FUNCTION: IMPERIALISM 0x0048c1e0
void TView::GetDrawableRegion(RgnHandle clipRegion) {
  CRect rect;
  GetDrawableQDRect(&rect);
  RectRgn(clipRegion, &rect);
}

// FUNCTION: IMPERIALISM 0x0048c220
void TView::SetHoverHelpText(CString sharedString) {
  hoverHelpEnabled5c = 1;
  hoverHelpText58 = sharedString;
}

// FUNCTION: IMPERIALISM 0x0048c250
void TView::DoSetCursor(CPoint* point, RgnHandle hitArg) {
  if (hoverHelpEnabled5c != 0) {
    CRect rect;
    GetQDExtent(&rect);
    RECT parentRect;
    CopyRect(&parentRect, &rect);
    if (g_pCursorControlPanel != nullptr) {
      g_pCursorControlPanel->SetTextAndLayoutRect(hoverHelpText58, &parentRect);
    }
  }
  if (GetCursorID() != 0xffff) {
    CPoint transformedPoint = ViewToQDPt(point);
    if (PtInRgn(&transformedPoint, hitArg)) {
      QuickDrawCursorHandle cursorHandle = GetQuickDrawCursor(static_cast<short>(GetCursorID()));
      SetQuickDrawCursor(*cursorHandle);
      return;
    }
  }
  HCURSOR hCursor = LoadCursorA(nullptr, IDC_ARROW);
  SetCursor(hCursor);
}
// FUNCTION: IMPERIALISM 0x0048c380
void TView::ApplyBounds(CRect* newBounds, int modeFlag) {
  CRect current;
  QueryBounds(&current);
  if (EqualRect(newBounds, &current) == 0) {
    if (modeFlag != 0 && IsActionable() != 0) {
      InvalidateCityDialogRectRegion(0, 1);
    }
    ownerLocalX = newBounds->left;
    ownerLocalY = newBounds->top;
    frameWidth34 = newBounds->right - newBounds->left;
    frameHeight38 = newBounds->bottom - newBounds->top;
    UpdateCoordinates();
    if (modeFlag != 0 && IsActionable() != 0) {
      InvalidateCityDialogRectRegion(0, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048c450
char TView::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (childList44 != 0) {
    POSITION pos = childList44->GetTailPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetPrev(pos));

      CPoint childPoint = point;
      child->SuperToLocal(&childPoint);
      if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
          child->HandleMouseDown(childPoint, event, origin) != 0) {
        return 1;
      }
    }
  }

  if (PrepareForDrawing() != 0 && IsEnabled() != 0) {
    CPoint localPoint = point;
    DoMouseCommand(localPoint, event, origin);
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c590
char TView::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (childList44 != 0) {
    POSITION pos = childList44->GetTailPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetPrev(pos));

      CPoint childPoint = point;
      child->SuperToLocal(&childPoint);
      if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
          child->HandleMouseUp(childPoint, event, origin) != 0) {
        return 1;
      }
    }
  }

  if (PrepareForDrawing() != 0) {
    CPoint localPoint = point;
    if (IsEnabled() != 0) {
      return HandleMouseCommandToSelf(localPoint, event, origin) != 0;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c6d0
char TView::PointInBoundsAndActionable(CPoint* point) {
  CRect bounds;
  QueryContentBounds(&bounds);
  if (IsActionable() != 0) {
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
  if (g_McAppUiDrawGate_006A1AF8 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x772);
  }
  CDC* context = GetActiveQuickDrawDc();
  Rectangle(context->m_hDC, rect->left, rect->top, rect->right, rect->bottom);
}
// FUNCTION: IMPERIALISM 0x0048c7a0
void TView::AssertMcAppUiLine1914(int unusedArg) {
  (void)unusedArg;
  if (g_McAppUiFlag_006A1AFC == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x77a);
  }
}

// FUNCTION: IMPERIALISM 0x0048c7d0
void TView::AssertMcAppUiLine1922() {
  if (g_McAppUiFlag_006A1B00 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x782);
  }
  CRect rectStorage;
  GetDrawableQDRect(&rectStorage);
}

// FUNCTION: IMPERIALISM 0x0048c820
CMcWindow* TView::Open() {
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->Open();
    }
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048c890
void TView::Close() {
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->Close();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048c900
void TView::PropagateUiResourceContextRecursive(CWnd* nativeWindow) {
  nativeWindow50 = nativeWindow;
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->PropagateUiResourceContextRecursive(nativeWindow);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048c970
unsigned short TView::GetHelpState() {
  return helpState54;
}
// FUNCTION: IMPERIALISM 0x0048c990
short TView::ContainsMouse(const CPoint& point) {
  CRect bounds;
  QueryContentBounds(&bounds);
  POINT p;
  p.x = point.x;
  p.y = point.y;
  // Returns 3 (not 1) on hit, unlike PointInBoundsAndActionable's near-identical body above.
  return static_cast<short>(-(PtInRect(&bounds, p) != 0) & 3);
}
// FUNCTION: IMPERIALISM 0x0048c9e0
void TView::GoAwayByUser(const CPoint& point) {
  (void)point;
}
// FUNCTION: IMPERIALISM 0x0048ca00
void TView::MoveByUser(const CPoint& point) {
  (void)point;
}
// FUNCTION: IMPERIALISM 0x0048ca20
void TView::ResizeByUser(const CPoint& point) {
  (void)point;
}
// FUNCTION: IMPERIALISM 0x0048ca40
void TView::ZoomByUser(const CPoint& point, short partCode) {
  (void)point;
  (void)partCode;
}

// MSVC500 emitted a fresh out-of-line copy of the (header-inline) `TView::~TView` in
// every TU that needed it non-inline: 0x0048cb00, 0x0048ec30, 0x0048ee00 are
// byte-identical twins of 0x0048a9d0 (verified instruction-for-instruction). reccmp
// cannot bind two original addresses to one recomp symbol, so the twins stay
// stub-owned; their symbols.csv rows carry the truthful `TView::~TView` label.

// 0x00607318 CWnd::GetStyle and 0x0060a60a CWnd::RunModalLoop were byte-for-byte MFC
// library methods hand-ported onto TView (both matched poorly, 24-40%). Retired to
// // LIBRARY: (see config/msvc500_library_overrides.csv); RunModalLoop's one caller
// (TModalTemplateDialog::FinalizeModalDialogAndRestoreOwnerFocus) now calls the real
// CWnd::RunModalLoop on the CWnd base. GetStyle's only caller was RunModalLoop itself.
