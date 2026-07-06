#include "game/mfc.h"
#include "game/TApplication.h"
#include "game/TEventHandler.h"
#include "game/TView.h"
#include "game/TBehavior.h"
#include "game/TCursorControlPanel.h"
#include "game/TDialogBehavior.h"
#include "game/TWindow.h"
#include "game/ui_resource_pool.h"
#include "game/global_data_tables.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_regions.h"

// Shared thunks/hooks whose callers interpret the arguments differently are kept in
// generic repo form (rule 9) with a typed cast at the callsite.

extern "C" CRuntimeClass PTR_s_TView_006495a0;

// UI-resource context helpers 0x426fa0-0x4270e0: original TU is this TView region
// (0x4272xx methods follow); they operate on g_pUiResourceContext from ui_resource_pool.h.
// FUNCTION: IMPERIALISM 0x00426fa0
void __cdecl SetUiResourceContextFlagsAndMetrics(short nField9C, short nStyleType,
                                                 unsigned char f70, unsigned char f6f,
                                                 unsigned char f6e, unsigned char f6d,
                                                 unsigned char f6c, unsigned char f71) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->field70 = f70;
  window->flag6f = f6f;
  window->flag6e = f6e;
  window->field6d = f6d;
  window->flag6c = f6c;
  window->flag71 = f71;
  window->field9c = static_cast<unsigned short>(nField9C);
  window->windowStyleType = nStyleType;
}

// FUNCTION: IMPERIALISM 0x00427010
void __cdecl ApplyUiResourceColorTripletFromContext(unsigned char nFlag0C,
                                                    unsigned char nTripletFlag, int colorA,
                                                    int colorB) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->GetEmbeddedDialogBehavior()->SetFlag0C(nFlag0C);
  window->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(nTripletFlag, colorA,
                                                                       colorB);
}

// Replaces the context widget's field48 style payload. Note the original writes
// through field48 without re-checking the fresh allocation for null — faithful.
// FUNCTION: IMPERIALISM 0x00427060
void __cdecl ReplaceUiResourceContextPairBuffer(int styleWord, int packedColor) {
  TView* context = g_pUiResourceContext;
  delete context->field48;
  context->field48 = new TUiStyleBytes();
  context->field48->styleWord = styleWord;
  context->field48->packedColor = packedColor;
}

// FUNCTION: IMPERIALISM 0x004270e0
TUiStyleRef::TUiStyleRef(int value) {
  this->value = value;
}

// FUNCTION: IMPERIALISM 0x00427200
unsigned short TView::GetField4E() {
  return field4e;
}
extern "C" {
void* AssertQuickDrawFlag6A1DCCNonZero(int index);
void AssertQuickDrawFlag6A1DC8NonZero(void* ptr);
}

// FUNCTION: IMPERIALISM 0x00427220
void TView::PostRenderSlotFC() {}

// FUNCTION: IMPERIALISM 0x00427240
char TView::HandleMouseCommandToSelf(CPoint* point, int arg2, int arg3, int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00427260
void TView::QueryContentBounds(RECT* boundsOut) {
  boundsOut->left = 0;
  boundsOut->top = 0;
  boundsOut->right = field34;
  boundsOut->bottom = field38;
}
// FUNCTION: IMPERIALISM 0x00427290
void TView::QueryBounds(RECT* boundsOut) {
  int width = field34;
  int left = ownerOffsetX;
  int height = field38;
  int top = ownerOffsetY;
  boundsOut->left = left;
  boundsOut->top = top;
  boundsOut->right = width + left;
  boundsOut->bottom = height + top;
}
// FUNCTION: IMPERIALISM 0x004272d0
void TView::DispatchVslot134WithRectAndRectPlus8_Impl(RECT* rect) {
  // RECT's four LONGs are two adjacent POINTs (left,top) and (right,bottom) — the
  // standard MFC/Win32 idiom for treating a RECT as a pair of POINTs in place.
  TranslatePointToParentChain4D(reinterpret_cast<CPoint*>(&rect->left));
  TranslatePointToParentChain4D(reinterpret_cast<CPoint*>(&rect->right));
}

// FUNCTION: IMPERIALISM 0x00427330
void TView::UpdateAfterBitmapChange(CPoint* point) {
  point->x -= ownerOffsetX;
  point->y -= ownerOffsetY;
}

// FUNCTION: IMPERIALISM 0x00429410
void TView::CopyRectFromBuildRectFromSlot158(RECT* rectOut) {
  BuildRectFromSlot158(rectOut);
}
// FUNCTION: IMPERIALISM 0x00430bd0
int TView::QuerySelectedIndexSlotBC() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00430bf0
void TView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
}

// Base TView slot 0x47: orphan RET 0x10 stub (real capture on TControl 0x48e640).

// FUNCTION: IMPERIALISM 0x00430c10
void TView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3, int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
}

// TViewChildList's compiler-emitted CList<TView*,TView*>::Serialize body. The real source is
// the childList44 template type in TView, not a TView method or TEventHandler record pool.
// TEMPLATE: IMPERIALISM 0x00479be0
// ?Serialize@?$CList@PAVTView@@PAV1@@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x00479d50
// ??_G?$CList@PAVTView@@PAV1@@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x00479d80
// ??1?$CList@PAVTView@@PAV1@@@UAE@XZ

// TEMPLATE: IMPERIALISM 0x0048ada0
// ??_G?$CList@PAVTView@@PAV1@@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x0048add0
// ??1?$CList@PAVTView@@PAV1@@@UAE@XZ

// IMPLEMENT_DYNCREATE also emits `TView::CreateObject` (`return new TView;`).
// SYNTHETIC: IMPERIALISM 0x0048a840
// TView::CreateObject

// TView slot 0x00 override: return this class's MFC CRuntimeClass descriptor.
// SYNTHETIC: IMPERIALISM 0x0048a8c0
// TView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TView, TEventHandler)

// FUNCTION: IMPERIALISM 0x0048a8e0
TView::TView()
    : TEventHandler(), ownerContext(0), field2c(0), field30(0), field3c(0), childList44(0),
      field48(0), flag4c(1), flag4d(1), field4e(0xffff), nativeWindow50(0), field54(1),
      sharedStringRef(), field5c(0) {}

// SYNTHETIC: IMPERIALISM 0x0048a9a0
// TView::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0048a9d0
TView::~TView() {
  delete childList44;
  delete field48;
}

// FUNCTION: IMPERIALISM 0x0048aa60
void TView::InitializeUiResourceEntryFrameAndParent(TView* uiResourceContext, TView* panel,
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
  ownerOffsetX = offsetLayout[0];
  ownerOffsetY = offsetLayout[1];
  field34 = sizeLayout[0];
  field38 = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, attachFlag);
  }
  uiResourceContext40 = uiResourceContext;
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
  NoOpUiLifecycleHook(eventArg);
}
// FUNCTION: IMPERIALISM 0x0048ab70
void TView::NoOpUiLifecycleHook(int arg) {
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

  child->RecomputeAbsolutePositionRecursive();
}

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
  SetControlValue(state);
  if (state != 0) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0048b0b0
void TView::Free() {
  // RECOMP SAFETY GUARD (not in the original binary; remove once the root cause is
  // fixed): disarm the global mouse capture if it still points at this view. In the
  // recomp, a title-screen click arms the capture (TControl::
  // BeginMouseCaptureAndStartRepeatTimer via the slot-0x46 dispatch) on a control that
  // the posted 0x2420 turn-event rebuild then frees before WM_LBUTTONUP arrives, so
  // EndMouseCaptureAndStopRepeatTimer dispatches slots 0x67/0x68 through a freed object
  // (verified winedbg backtrace; page fault / jump to scribbled vtable). The original
  // binary does not crash here under the same Wine, so some not-yet-ported piece
  // (likely a stubbed slot-0x3e/0x0a override on the title-screen classes, or a
  // teardown path that disarms the capture) prevents this situation in the original;
  // this guard only keeps the recomp alive until that divergence is found.
  if (static_cast<void*>(g_McAppMouseCaptureState.capturedControl) == static_cast<void*>(this)) {
    if (g_McAppUiMouseCaptureTimerId_006A1ADC != 0 && nativeWindow50 != 0) {
      ::KillTimer(nativeWindow50->m_hWnd, g_McAppUiMouseCaptureTimerId_006A1ADC);
      g_McAppUiMouseCaptureTimerId_006A1ADC = 0;
    }
    ::ReleaseCapture();
    g_McAppMouseCaptureState.capturedControl = 0;
  }
  while (childList44 != 0) {
    TEventHandler* child = static_cast<TEventHandler*>(childList44->GetTail());
    child->Free();
  }
  if (ownerContext != 0) {
    ownerContext->DetachChildFromOwnerList(this);
    ownerContext = 0;
  }
  if (g_pApplicationUiRootController != 0 &&
      static_cast<TEventHandler*>(g_pApplicationUiRootController) !=
          static_cast<TEventHandler*>(this)) {
    TEventHandler* activeView = g_pApplicationUiRootController->GetActiveView();
    if (activeView == this) {
      TEventHandler* replacement = QueryStepValue();
      if (replacement == 0) {
        g_pApplicationUiRootController->SetActiveView(g_pApplicationUiRootController);
      } else {
        g_pApplicationUiRootController->SetActiveView(replacement);
      }
    }
  }
  field0c = 0;
  if (linkedResourceOwner != 0) {
    linkedResourceOwner->Free();
  }
  linkedResourceOwner = 0;
  delete this;
}

// Recurses to the root owner. QueryOwnerContextPanel below looks almost identical but
// only hops one level (via this method) instead of recursing.
// FUNCTION: IMPERIALISM 0x0048b180
TView* TView::OwnerPanel() {
  if (ownerContext == 0) {
    return 0;
  }
  return ownerContext->OwnerPanel();
}
// FUNCTION: IMPERIALISM 0x0048b1a0
TView* TView::QueryOwnerContextPanel() {
  if (ownerContext == 0) {
    return 0;
  }
  return ownerContext->OwnerPanel();
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
  ownerOffsetX = buffer[0];
  ownerOffsetY = buffer[1];
  RecomputeAbsolutePositionRecursive();
  if (modeFlag != 0 && IsActionable() != 0) {
    InvalidateCityDialogRectRegion(0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048b2d0
void TView::RecomputeAbsolutePositionRecursive() {
  TView* owner = ownerContext;
  int oldX = field2c;
  int oldY = field30;
  int newX = g_McAppUiDefaultPosX_006A1A60;
  int newY = g_McAppUiDefaultPosY_006A1A64;
  if (owner != 0) {
    newX = owner->field2c + ownerOffsetX;
    newY = owner->field30 + ownerOffsetY;
  }
  field2c = newX;
  field30 = newY;
  if (field2c != oldX || field30 != oldY) {
    if (childList44 != 0) {
      POSITION pos = childList44->GetHeadPosition();
      while (pos != NULL) {
        TView* child = static_cast<TView*>(childList44->GetNext(pos));
        child->RecomputeAbsolutePositionRecursive();
      }
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048b3f0
void TView::CaptureLayout(int* buffer, int modeFlag) {
  if (modeFlag != 0) {
    RECT oldRect;
    CopyRectFromBuildRectFromSlot158(&oldRect);
    field34 = buffer[0];
    field38 = buffer[1];
    RECT newRect;
    CopyRectFromBuildRectFromSlot158(&newRect);
    RECT unionRect;
    UnionRect(&unionRect, &newRect, &oldRect);
    if (g_McAppUiActiveFlag_006950AC != 0) {
      InvalidateRect(nativeWindow50->m_hWnd, &unionRect, 0);
    }
  } else {
    field34 = buffer[0];
    field38 = buffer[1];
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
    sourceRegion = (HRGN)(*region)->rgn;
  }
  HRGN destRegion = static_cast<HRGN>((*localRegion)->rgn.m_hObject);
  CombineRgn(destRegion, sourceRegion, nullptr, RGN_COPY);

  CPoint cachedPos;
  GetCachedPosPoint(&cachedPos);
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
  RECT localRect;
  if (rect == 0) {
    CopyRectFromBuildRectFromSlot158(&localRect);
  } else {
    CopyRect(&localRect, rect);
    DispatchVslot134WithRectAndRectPlus8_Impl(&localRect);
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
void TView::InvokeSlot13C() {
  if (ownerContext != 0) {
    ownerContext->InvokeSlot13C();
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
char TView::Refresh() {
  if (this != g_McAppUiActiveRenderContext_006A1AF4) {
    SetGlobalQuickDrawOrigin(static_cast<short>(field2c), static_cast<short>(field30));
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
// field48 is freed in ~TView.
// FUNCTION: IMPERIALISM 0x0048b810
void TView::EnsureField48Buffer() {
  if (field48 == 0) {
    field48 = new TUiStyleBytes();
  }
}
// FUNCTION: IMPERIALISM 0x0048b860
void TView::PaintOrInvalidateControl(CDC* paintDc) {
  if (paintDc != 0) {
    RECT rect;
    QueryContentBounds(&rect);
    PaintVisibleChildrenIntersectingClipRect(&rect, paintDc);
    return;
  }
  InvalidateCityDialogRectRegion(0, 0);
}

// FUNCTION: IMPERIALISM 0x0048b8d0
void TView::PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, CDC* paintDc) {
  if (g_McAppUiActiveFlag_006950AC == 0 || IsActionable() == 0 || Refresh() == 0) {
    return;
  }

  RECT clippedRect;
  QueryContentBounds(&clippedRect);
  if (IntersectRect(&clippedRect, &clippedRect, clipRect) == 0) {
    return;
  }

  if (BindMapQuickDrawDc(paintDc) != 0) {
    ApplyRectSlot110(&clippedRect);
    if (linkedResourceOwner != 0) {
      linkedResourceOwner->DispatchQueuedUiCommandAndRelease(&clippedRect);
    }
    ReleaseMapQuickDrawDc(paintDc);
  }

  TViewChildList* list = childList44;
  if (list != 0) {
    POSITION pos = list->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(list->GetNext(pos));
      RECT childClip = clippedRect;
      OffsetRect(&childClip, -child->ownerOffsetX, -child->ownerOffsetY);
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
  point->y += ownerOffsetY;
  point->x += ownerOffsetX;
  ownerContext->TranslatePointToParentChain4E(point);
}
// FUNCTION: IMPERIALISM 0x0048ba80
void TView::TranslatePointToParentChain4D(CPoint* point) {
  int offY = ownerOffsetY;
  point->x += ownerOffsetX;
  point->y += offY;
  ownerContext->TranslatePointToParentChain4D(point);
}
// Mirror of TranslatePointToParentChain4D/4E above, but subtracts instead of adding.
// FUNCTION: IMPERIALISM 0x0048bac0
void TView::SubtractPosAndDispatchToOwnerSlot19C(CPoint* point) {
  int offY = ownerOffsetY;
  point->x = point->x - ownerOffsetX;
  point->y = point->y - offY;
  ownerContext->SubtractPosAndDispatchToOwnerSlot19C(point);
}

// FUNCTION: IMPERIALISM 0x0048bb00
void TView::OffsetRectByControlPosition(RECT* rect) {
  OffsetRect(rect, ownerOffsetX, ownerOffsetY);
}

// FUNCTION: IMPERIALISM 0x0048bb30
CPoint* TView::GetCachedPosPoint(CPoint* outPoint) {
  int posY = field30;
  outPoint->x = field2c;
  outPoint->y = posY;
  return outPoint;
}

// FUNCTION: IMPERIALISM 0x0048bb60
CPoint TView::TransformPointViaSlot138(CPoint* inPoint) {
  CPoint local;
  local.x = inPoint->x;
  local.y = inPoint->y;
  TranslatePointToParentChain4E(&local);
  return local;
}

// FUNCTION: IMPERIALISM 0x0048bbb0
RECT TView::TransformRectViaSlot148(RECT* inRect) {
  int width = inRect->right - inRect->left;
  int height = inRect->bottom - inRect->top;
  CPoint corner;
  corner.x = inRect->left;
  corner.y = inRect->top;
  CPoint mapped = TransformPointViaSlot138(&corner);
  RECT result;
  result.left = mapped.x;
  result.top = mapped.y;
  result.right = mapped.x + width;
  result.bottom = mapped.y + height;
  return result;
}
// FUNCTION: IMPERIALISM 0x0048bc30
void TView::AddControlPosToPoint(int x, int y, int* outPoint) {
  x = x + field2c;
  y = field30 + y;
  outPoint[0] = x;
  outPoint[1] = y;
}

// FUNCTION: IMPERIALISM 0x0048bc60
void TView::OffsetRectByCachedPos(RECT* inRect, RECT* outRect) {
  RECT local;
  local.left = inRect->left;
  local.top = inRect->top;
  local.right = inRect->right;
  local.bottom = inRect->bottom;
  OffsetRect(&local, field2c, field30);
  outRect->left = local.left;
  outRect->top = local.top;
  outRect->right = local.right;
  outRect->bottom = local.bottom;
}

// FUNCTION: IMPERIALISM 0x0048bce0
RECT* TView::BuildRectFromSlot158(RECT* rectOut) {
  int width = field34;
  int height = field38;
  CPoint pos;
  GetCachedPosPoint(&pos);
  rectOut->left = pos.x;
  rectOut->top = pos.y;
  rectOut->right = width + pos.x;
  rectOut->bottom = height + pos.y;
  return rectOut;
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
  field48 = 0;
  field3c = source->field3c;
  field54 = source->field54;
  ownerOffsetX = source->ownerOffsetX;
  ownerOffsetY = source->ownerOffsetY;
  field2c = source->field2c;
  field30 = source->field30;
  field34 = source->field34;
  field38 = source->field38;
  flag4c = source->flag4c;
  flag4d = source->flag4d;
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
  if (field5c == 0) {
    if ((char)flag4c != 0 && GetBoolSlot28() != 0) {
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
  if (flag4d != 0 && childList44 != 0 && !childList44->IsEmpty()) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c080
void TView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point, int hitArg) {
  if (HasRenderableParentAndContent() != 0) {
    if (childList44 != 0) {
      POSITION pos = childList44->GetHeadPosition();
      while (pos != NULL) {
        TView* child = static_cast<TView*>(childList44->GetNext(pos));

        CPoint childPoint = *point;
        child->UpdateAfterBitmapChange(&childPoint);
        if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
            child->EvaluateControlInputGate() != 0) {
          child->HandleCursorHoverSelectionByChildHitTestAndFallback(&childPoint, hitArg);
          return;
        }
      }
    }
  }

  // TODO(typing): hitArg is really a RgnHandle threaded through the whole
  // slot-0x2c/0x35 hover family (200+ files); retype the family in one pass.
  if (EmptyRgn(reinterpret_cast<RgnHandle>(hitArg)) != 0 && Refresh() != 0) {
    HandleCursorHoverFallback(point, hitArg);
  }
}

// FUNCTION: IMPERIALISM 0x0048c1c0
void TView::NoOpClipRegionSlot2D(int arg1, int arg2) {}

// FUNCTION: IMPERIALISM 0x0048c1e0
void TView::RefreshCityProductionViewStateFromContext(RgnHandle clipRegion) {
  RECT rect;
  CopyRectFromBuildRectFromSlot158(&rect);
  RectRgn(clipRegion, &rect);
}

// FUNCTION: IMPERIALISM 0x0048c220
void TView::EnableAndProcessFlag(CString sharedString) {
  field5c = 1;
  sharedStringRef = sharedString;
}

// FUNCTION: IMPERIALISM 0x0048c250
void TView::HandleCursorHoverFallback(CPoint* point, int hitArg) {
  if (field5c != 0) {
    RECT rect;
    BuildRectFromSlot158(&rect);
    RECT parentRect;
    CopyRect(&parentRect, &rect);
    if (g_pCursorControlPanel != nullptr) {
      g_pCursorControlPanel->SetTextAndLayoutRect(sharedStringRef, &parentRect);
    }
  }
  if (GetField4E() != 0xffff) {
    CPoint transformedPoint = TransformPointViaSlot138(point);
    if (PtInRgn(&transformedPoint, reinterpret_cast<RgnHandle>(hitArg))) {
      void* ptr = AssertQuickDrawFlag6A1DCCNonZero(GetField4E());
      AssertQuickDrawFlag6A1DC8NonZero(*reinterpret_cast<void**>(ptr));
      return;
    }
  }
  HCURSOR hCursor = LoadCursorA(nullptr, IDC_ARROW);
  SetCursor(hCursor);
}
// FUNCTION: IMPERIALISM 0x0048c380
void TView::ApplyBounds(RECT* newBounds, int modeFlag) {
  RECT current;
  QueryBounds(&current);
  if (EqualRect(newBounds, &current) == 0) {
    if (modeFlag != 0 && IsActionable() != 0) {
      InvalidateCityDialogRectRegion(0, 1);
    }
    ownerOffsetX = newBounds->left;
    ownerOffsetY = newBounds->top;
    field34 = newBounds->right - newBounds->left;
    field38 = newBounds->bottom - newBounds->top;
    RecomputeAbsolutePositionRecursive();
    if (modeFlag != 0 && IsActionable() != 0) {
      InvalidateCityDialogRectRegion(0, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048c450
char TView::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  if (childList44 != 0) {
    POSITION pos = childList44->GetTailPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetPrev(pos));

      CPoint childPoint = *point;
      child->UpdateAfterBitmapChange(&childPoint);
      if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
          child->DispatchUiMouseMoveToChildren(&childPoint, arg2, arg3, arg4) != 0) {
        return 1;
      }
    }
  }

  if (Refresh() != 0 && GetBoolSlot28() != 0) {
    CPoint localPoint = *point;
    BeginMouseCaptureAndStartRepeatTimer(&localPoint, arg2, arg3, arg4);
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c590
char TView::DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3, int arg4) {
  if (childList44 != 0) {
    POSITION pos = childList44->GetTailPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetPrev(pos));

      CPoint childPoint = *point;
      child->UpdateAfterBitmapChange(&childPoint);
      if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
          child->DispatchUiMouseEventToChildrenOrSelf_Impl(&childPoint, arg2, arg3, arg4) != 0) {
        return 1;
      }
    }
  }

  if (Refresh() != 0) {
    CPoint localPoint = *point;
    if (GetBoolSlot28() != 0) {
      return HandleMouseCommandToSelf(&localPoint, arg2, arg3, arg4) != 0;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c6d0
char TView::PointInBoundsAndActionable(CPoint* point) {
  RECT bounds;
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
void TView::DrawRectangleInCurrentUiContext(int* rect) {
  if (g_McAppUiDrawGate_006A1AF8 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x772);
  }
  CDC* context = GetActiveQuickDrawDc();
  Rectangle(context->m_hDC, rect[0], rect[1], rect[2], rect[3]);
}
// FUNCTION: IMPERIALISM 0x0048c7a0
void TView::AssertMcAppUiLine1914() {
  if (g_McAppUiFlag_006A1AFC == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x77a);
  }
}

// FUNCTION: IMPERIALISM 0x0048c7d0
void TView::AssertMcAppUiLine1922() {
  if (g_McAppUiFlag_006A1B00 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x782);
  }
  RECT rectStorage;
  CopyRectFromBuildRectFromSlot158(&rectStorage);
}

// FUNCTION: IMPERIALISM 0x0048c820
void TView::DispatchSlot9CToLinkedChildren() {
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->DispatchSlot9CToLinkedChildren();
    }
  }
}
// FUNCTION: IMPERIALISM 0x0048c890
void TView::CallVoidSlotA0() {
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->CallVoidSlotA0();
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
unsigned short TView::GetField54() {
  return field54;
}
// FUNCTION: IMPERIALISM 0x0048c990
char TView::TestPointInBounds(CPoint* point) {
  RECT bounds;
  QueryContentBounds(&bounds);
  POINT p;
  p.x = point->x;
  p.y = point->y;
  // Returns 3 (not 1) on hit, unlike PointInBoundsAndActionable's near-identical body above.
  return -(PtInRect(&bounds, p) != 0) & 3;
}
// FUNCTION: IMPERIALISM 0x0048c9e0
void TView::ReturnFromUiSlot60(int arg) {
  (void)arg;
}
// FUNCTION: IMPERIALISM 0x0048ca00
void TView::ReturnFromUiSlot61(int arg) {
  (void)arg;
}
// FUNCTION: IMPERIALISM 0x0048ca20
void TView::ReturnFromUiSlot62(int arg) {
  (void)arg;
}
// FUNCTION: IMPERIALISM 0x0048ca40
void TView::ReturnFromUiSlot63(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// MSVC500 emitted a fresh out-of-line copy of the (header-inline) `TView::~TView` in
// every TU that needed it non-inline: 0x0048cb00, 0x0048ec30, 0x0048ee00 are
// byte-identical twins of 0x0048a9d0 (verified instruction-for-instruction). reccmp
// cannot bind two original addresses to one recomp symbol, so the twins stay
// stub-owned; their symbols.csv rows carry the truthful `TView::~TView` label.

// FUNCTION: IMPERIALISM 0x00607318
UINT TView::GetStyle() {
  if (field38 != 0) {
    // TODO(class-recovery): field38, when non-null, is some other polymorphic object
    // whose own vtable slot 0x1e is tail-called here for the style value; that class
    // isn't recovered yet. Falls back to the window-handle path below in the meantime
    // (identical to the field38 == 0 case). Dead for TView::RunModalLoop's movie path
    // (loopKind == 0 never reaches here).
  }
  return GetWindowLong(reinterpret_cast<HWND>(controlTag), GWL_STYLE);
}

// MFC-private message sent by RunModalLoop to itself each idle cycle (afxpriv.h
// WM_KICKIDLE, not vendored here).
namespace {
const UINT kMsgKickIdle = 0x036a;
}

// FUNCTION: IMPERIALISM 0x0060a60a
int TView::RunModalLoop(unsigned char loopKind) {
  bool idleModeActive = true;
  int idleMessageCount = 0;
  bool showOnFirstNonInputMessage = false;
  if ((loopKind & 4) != 0) {
    showOnFirstNonInputMessage = (GetStyle() & WS_VISIBLE) == 0;
  }

  HWND parentHwnd = GetParent(reinterpret_cast<HWND>(controlTag));
  ownerOffsetX |= 0x18;

  CWinThread* thread = AfxGetThread();
  LPMSG msg = &thread->m_msgCur;

  for (;;) {
    while (!idleModeActive || PeekMessageA(msg, nullptr, 0, 0, PM_NOREMOVE) != 0) {
      if (!thread->PumpMessage()) {
        AfxPostQuitMessage(0);
        return -1;
      }

      if (showOnFirstNonInputMessage && (msg->message == 0x118 || msg->message == WM_SYSKEYDOWN)) {
        // Original calls CWnd::ShowWindow/UpdateWindow directly on `this`; modeled here
        // against the hosted native window until TView's relationship to that call is
        // understood (dead for loopKind == 0, the movie path).
        if (nativeWindow50 != 0) {
          nativeWindow50->ShowWindow(SW_SHOWNORMAL);
        }
        UpdateWindow(reinterpret_cast<HWND>(controlTag));
        showOnFirstNonInputMessage = false;
      }

      if (!ContinueModal()) {
        ownerOffsetX &= ~0x18;
        return field2c;
      }

      if (thread->IsIdleMessage(msg)) {
        idleModeActive = true;
        idleMessageCount = 0;
      }
    }

    if (showOnFirstNonInputMessage) {
      if (nativeWindow50 != 0) {
        nativeWindow50->ShowWindow(SW_SHOWNORMAL);
      }
      UpdateWindow(reinterpret_cast<HWND>(controlTag));
      showOnFirstNonInputMessage = false;
    }

    if ((loopKind & 1) == 0 && parentHwnd != 0 && idleMessageCount == 0) {
      SendMessageA(parentHwnd, WM_ENTERIDLE, 0, static_cast<LPARAM>(controlTag));
    }

    if ((loopKind & 2) == 0) {
      const int currentIdleCount = idleMessageCount++;
      if (SendMessageA(reinterpret_cast<HWND>(controlTag), kMsgKickIdle, 0, currentIdleCount) !=
          0) {
        continue;
      }
    }
    idleModeActive = false;
  }
}
