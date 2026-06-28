// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#pragma optimize("y", on)
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include <new>

#include "game/TApplication.h"
#include "game/TEventHandler.h"
#include "game/TView.h"
#include "game/TControl.h"
#include "game/TCursorControlPanel.h"
#include "game/mcappui_globals.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/quickdraw_globals.h"
#include "game/ui_invalidation_guard.h"

// Shared thunks/hooks whose callers interpret the arguments differently are kept in
// generic repo form (rule 9) with a typed cast at the callsite.
undefined4 NoOpQuickDrawContextSelectionHook(void);
undefined4 ReplaceClipStateRegionHandleFromRect(void);
#include "game/ClipStateRegion.h"
undefined4 GetRegionBoxToRectIfPresent(void);

// TView::childList44 is an MFC CPtrList of child-control TView* pointers (node->data).

extern "C" CRuntimeClass PTR_s_TView_006495a0;

// FUNCTION: IMPERIALISM 0x00427200
unsigned short TView::GetField4E() {
  return field4e;
}
extern "C" TCursorControlPanel* g_pCursorControlPanel;
extern "C" {
void* AssertQuickDrawFlag6A1DCCNonZero(int index);
void AssertQuickDrawFlag6A1DC8NonZero(void* ptr);
int IsPointInsideHitRegion(CPoint* point, int hitArg);
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
  TranslatePointToParentChain4D(reinterpret_cast<int*>(&rect->left));
  TranslatePointToParentChain4D(reinterpret_cast<int*>(&rect->right));
}

// FUNCTION: IMPERIALISM 0x00427330
void TView::UpdateAfterBitmapChange(int unknownFlag) {
  CPoint* point = reinterpret_cast<CPoint*>(unknownFlag);
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

// Serialize the field04/field08 intrusive list hanging off TEventHandler (+0x04 head,
// +0x08 tail, +0x0c count, +0x10 free-list, +0x14/+0x18 block pool).
// FUNCTION: IMPERIALISM 0x00479be0
void TView::SerializeRecordList_0x0C_WithBlockPool_A(CArchive* archive) {
  if (archive->IsLoading()) {
    for (int count = archive->ReadCount(); count != 0; count = count - 1) {
      CArchive* value = 0;
      archive->Read(&value, sizeof(value));
      int tail = field08;
      if (field10 == 0) {
        int blockBase = AllocateAndLinkBlockHead(&field14, resourceOwner, 0xc);
        int blockCount = resourceOwner;
        int* node = reinterpret_cast<int*>(blockBase + -8 + blockCount * 0xc);
        if (-1 < blockCount - 1) {
          do {
            *node = field10;
            field10 = reinterpret_cast<int>(node);
            node = node - 3;
            blockCount = blockCount - 1;
          } while (blockCount != 0);
        }
      }
      int* node = reinterpret_cast<int*>(field10);
      field10 = *node;
      node[1] = tail;
      node[0] = 0;
      field0c = field0c + 1;
      node[2] = 0;
      node[2] = reinterpret_cast<int>(value);
      if (field08 == 0) {
        field04 = reinterpret_cast<int>(node);
      } else {
        *reinterpret_cast<int**>(field08) = node;
      }
      field08 = reinterpret_cast<int>(node);
    }
  } else {
    archive->WriteCount(field0c);
    int* node = reinterpret_cast<int*>(field04);
    if (node != 0) {
      do {
        archive->Write(node + 2, sizeof(CArchive*));
        node = reinterpret_cast<int*>(*node);
      } while (node != 0);
    }
  }
}

// TView slot 0x00 override: return this class's MFC CRuntimeClass descriptor.
IMPLEMENT_DYNCREATE(TView, TEventHandler)

// Real ctor. The TEventHandler base ctor (inlined) writes the base vptr (0x006497a0)
// and the base scalar fields (field0c/field10/field14/resourceOwner); MSVC then writes this
// class's vptr (0x00649858) and constructs TView's own members in declaration order.
// The scalar fields are member-initializers (not body assignments) so they are emitted
// before the CString member sharedStringRef is constructed (-> 0x00605797). No manual
// vtable writes — the // VTABLE: annotation owns it.
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
  delete[] field48;
}

// FUNCTION: IMPERIALISM 0x0048aa60
void TView::InitializeUiResourceEntryFrameAndParent(int ownerContext, TControl* panel,
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
  field0c = reinterpret_cast<int>(panel);
  ownerOffsetX = offsetLayout[0];
  ownerOffsetY = offsetLayout[1];
  field34 = sizeLayout[0];
  field38 = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, attachFlag);
  }
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x40) = ownerContext;
}
// Recursively dispatch a control event: walk the field44 child list, forward to each
// child's slot-0x36, then invoke this view's own slot-0x37 handler.
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
// Forward a map-view notification (slot 0x31) up to the owning view, if any.
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
  child->field0c = reinterpret_cast<int>(this);

  if (childList44 == nullptr) {
    childList44 = new CPtrList();
  }

  if (flag != 0) {
    childList44->AddTail(child);
  } else {
    childList44->AddHead(child);
  }

  child->RecomputeAbsolutePositionRecursive();
}

// Find the child whose controlTag matches, unlink it from childList44 (inlined
// CPtrList::RemoveAt; when the list empties, free its block chain), delete the now-empty
// list, and clear the child's back-reference to this owner.
// FUNCTION: IMPERIALISM 0x0048ae60
void TView::DetachChildFromOwnerList(class TView* child) {
  CPtrList* list = childList44;
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
    reinterpret_cast<void(__cdecl*)(const char*, int)>(reinterpret_cast<void (*)()>(
        TemporarilyClearAndRestoreUiInvalidationFlag))(g_szMcAppUiSourcePath_006950B0, 0x152);
  }

  if (list->IsEmpty()) {
    delete list;
    childList44 = 0;
  }
  child->ownerContext = 0;
}
// If the child list's tail element is not already the given child, notify the old/new
// selection (slots 0x5d/0x5c) and refresh the newly active child.
// FUNCTION: IMPERIALISM 0x0048af80
void TView::SwitchActiveChildAndNotify(class TView* child) {
  if (childList44 != 0 && childList44->GetTail() != child) {
    DetachChildFromOwnerList(child);
    AttachChildControl(child, 1);
    child->RefreshControl();
  }
}
// Find the descendant control whose controlTag matches: scan the direct child list
// first, then recurse into each child via slot 0x25 (ResolveControlByTag). Returns the
// matching control, or null. The own-tag case short-circuits (callers exclude self).
// FUNCTION: IMPERIALISM 0x0048afd0
class TControl* TView::ResolveControlByTag(unsigned int controlTag) {
  if (controlTag == static_cast<unsigned int>(this->controlTag)) {
    return reinterpret_cast<class TControl*>(this);
  }
  if (childList44 == 0) {
    return 0;
  }

  POSITION pos = childList44->GetHeadPosition();
  while (pos != NULL) {
    TView* entry = static_cast<TView*>(childList44->GetNext(pos));
    if (controlTag == static_cast<unsigned int>(entry->controlTag)) {
      return reinterpret_cast<class TControl*>(entry);
    }
  }

  pos = childList44->GetHeadPosition();
  while (pos != NULL) {
    TView* child = static_cast<TView*>(childList44->GetNext(pos));
    TControl* match = child->ResolveControlByTag(controlTag);
    if (match != 0) {
      return match;
    }
  }
  return 0;
}
// Push the control value through slot 0x0b, then refresh when it is non-zero.
// FUNCTION: IMPERIALISM 0x0048b070
void TView::SetState(int state, int refreshFlag) {
  (void)refreshFlag;
  SetControlValue(state);
  if (state != 0) {
    RefreshControl();
  }
}

// Base-slot overrides (slots 0x07/0x08). Bodies differ from TEventHandler's; still
// unported stubs.
// FUNCTION: IMPERIALISM 0x0048b0b0
void TView::Free() {
  while (childList44 != 0) {
    int* listWords = reinterpret_cast<int*>(childList44);
    TEventHandler* child = *reinterpret_cast<TEventHandler**>(
        reinterpret_cast<char*>(*reinterpret_cast<int*>(reinterpret_cast<char*>(listWords) + 4)) +
        8);
    child->Free();
  }
  if (ownerContext != 0) {
    ownerContext->DetachChildFromOwnerList(this);
    ownerContext = 0;
  }
  if (g_pApplicationUiRootController != 0 &&
      g_pApplicationUiRootController != reinterpret_cast<TApplication*>(this)) {
    TView* activeView = g_pApplicationUiRootController->GetActiveView();
    if (activeView == this) {
      TEventHandler* replacement = reinterpret_cast<TEventHandler*>(QueryStepValue());
      if (replacement == 0) {
        g_pApplicationUiRootController->SetActiveView(
            reinterpret_cast<TView*>(g_pApplicationUiRootController));
      } else {
        g_pApplicationUiRootController->SetActiveView(reinterpret_cast<TView*>(replacement));
      }
    }
  }
  field0c = 0;
  if (resourceOwner != 0) {
    reinterpret_cast<TEventHandler*>(resourceOwner)->Free();
  }
  resourceOwner = 0;
  delete this;
}

// Walk up the owner chain: forward to the owner context's own slot-0x16 query, or 0
// at the root. (One level above QueryOwnerContextPanel, which only hops once.) Slot 0x16
// override (TEventHandler's base body differs).
// FUNCTION: IMPERIALISM 0x0048b180
TView* TView::OwnerPanel() {
  if (ownerContext == 0) {
    return 0;
  }
  return ownerContext->OwnerPanel();
}
// Forward to the owner context's panel query (slot 0x16), or 0 if no owner.
// FUNCTION: IMPERIALISM 0x0048b1a0
TView* TView::QueryOwnerContextPanel() {
  if (ownerContext == 0) {
    return 0;
  }
  return ownerContext->OwnerPanel();
}
// If the enabled-state field (field08) changes, store it and optionally refresh.
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
int TView::IsActionable() {
  if (g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0 && field08 != 0 &&
      ownerContext != 0) {
    if (ownerContext->IsActionable() != 0) {
      return 1;
    }
  }
  return 0;
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

// Recompute this control's absolute position (field2c/field30) from the owner's absolute
// position plus this control's owner offset (default position when no owner). If it
// moved, propagate the recompute to every child via slot 0x59.
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
// Update the cached position (field34/field38) to buffer's point. When modeFlag is set,
// capture the control rect before and after the move and invalidate their union.
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
      InvalidateRect(reinterpret_cast<HWND>(nativeWindow50->m_hWnd), &unionRect, 0);
    }
  } else {
    field34 = buffer[0];
    field38 = buffer[1];
  }
}

// FUNCTION: IMPERIALISM 0x0048b4b0
void TView::InvalidateOffsetRegionUsingChildClipRect(int* regionWrapper) {
  if (nativeWindow50 == 0) {
    return;
  }

  ClipStateRegionWrapper* localRegion = CreateClipStateRegionWrapperObject();
  if (localRegion == 0 || localRegion->inner == 0) {
    return;
  }

  void* sourceRegion = 0;
  if (regionWrapper != 0 && *regionWrapper != -0x14) {
    ClipStateRegionWrapper* childWrapper =
        reinterpret_cast<ClipStateRegionWrapper*>(*regionWrapper);
    if (childWrapper != 0 && childWrapper->inner != 0) {
      sourceRegion = *reinterpret_cast<void**>(reinterpret_cast<char*>(childWrapper->inner) + 0x18);
    }
  }
  void* destRegion = *reinterpret_cast<void**>(reinterpret_cast<char*>(localRegion->inner) + 0x18);
  CombineRgn(reinterpret_cast<HRGN>(destRegion), reinterpret_cast<HRGN>(sourceRegion), nullptr, 5);

  CPoint cachedPos;
  CPoint* pos = reinterpret_cast<CPoint*>(GetCachedPosPoint(reinterpret_cast<int*>(&cachedPos)));
  OffsetRgn(reinterpret_cast<HRGN>(destRegion), -pos->x, -pos->y);

  if (g_McAppUiActiveFlag_006950AC != 0) {
    InvalidateRgn(reinterpret_cast<HWND>(nativeWindow50->m_hWnd),
                  reinterpret_cast<HRGN>(destRegion), 0);
  }

  DestroyClipStateRegionWrapperObject(localRegion);
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
    InvalidateRect(reinterpret_cast<HWND>(nativeWindow50->m_hWnd), &localRect, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048b690
void TView::ValidateControlRectIfWindowActive(RECT* rect) {
  if (nativeWindow50 != 0 && g_McAppUiActiveFlag_006950AC != 0) {
    ValidateRect(reinterpret_cast<HWND>(nativeWindow50->m_hWnd), rect);
  }
}
// FUNCTION: IMPERIALISM 0x0048b6d0
void TView::RefreshControl() {
  if (g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0) {
    InvalidateCityDialogRectRegion(0, 1);
  }
}

// Forward slot 0x4f to the owner when present; roots force a guarded UpdateWindow pass.
// FUNCTION: IMPERIALISM 0x0048b700
void TView::InvokeSlot13C() {
  if (ownerContext != 0) {
    ownerContext->InvokeSlot13C();
    return;
  }
  if (g_McAppUiUpdateWindowRecursionGuard_006A1AF0 == 0) {
    g_McAppUiUpdateWindowRecursionGuard_006A1AF0 = 1;
    if (nativeWindow50 != 0 && g_McAppUiActiveFlag_006950AC != 0) {
      UpdateWindow(reinterpret_cast<HWND>(nativeWindow50->m_hWnd));
    }
    g_McAppUiUpdateWindowRecursionGuard_006A1AF0 = 0;
  }
}
// Select this view as the active QuickDraw origin and return success.
// FUNCTION: IMPERIALISM 0x0048b770
char TView::Refresh() {
  if (this != g_McAppUiActiveRenderContext_006A1AF4) {
    SetGlobalQuickDrawOrigin(static_cast<short>(field2c), static_cast<short>(field30));
    g_McAppUiActiveRenderContext_006A1AF4 = this;
  }
  return 1;
}
// FUNCTION: IMPERIALISM 0x0048b7b0
int TView::BindMapQuickDrawDc(int arg) {
  return BindScopedMapQuickDrawDcHandle(this, arg);
}

// FUNCTION: IMPERIALISM 0x0048b7e0
void TView::ReleaseMapQuickDrawDc(int arg) {
  ReleaseScopedMapQuickDrawDcHandle(this, arg);
}
// Lazily allocate the 8-byte auxiliary buffer stored at field48 (freed in the dtor).
// FUNCTION: IMPERIALISM 0x0048b810
void TView::EnsureField48Buffer() {
  if (field48 == 0) {
    field48 = new int[2];
    if (field48 != 0) {
      field48[0] = 0;
      field48[1] = 0;
      return;
    }
    field48 = 0;
  }
}
// FUNCTION: IMPERIALISM 0x0048b860
void TView::PaintOrInvalidateControl(int arg) {
  if (arg != 0) {
    RECT rect;
    QueryContentBounds(&rect);
    PaintVisibleChildrenIntersectingClipRect(&rect, arg);
    return;
  }
  InvalidateCityDialogRectRegion(0, 0);
}

// FUNCTION: IMPERIALISM 0x0048b8d0
void TView::PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, int bindArg) {
  if (g_McAppUiActiveFlag_006950AC == 0 || IsActionable() == 0 || Refresh() == 0) {
    return;
  }

  RECT clippedRect;
  QueryContentBounds(&clippedRect);
  if (IntersectRect(&clippedRect, &clippedRect, clipRect) == 0) {
    return;
  }

  if (BindMapQuickDrawDc(bindArg) != 0) {
    ApplyRectSlot110(&clippedRect);
    if (resourceOwner != 0) {
      reinterpret_cast<TEventHandler*>(resourceOwner)
          ->DispatchQueuedUiCommandAndRelease(&clippedRect);
    }
    ReleaseMapQuickDrawDc(bindArg);
  }

  CPtrList* list = childList44;
  if (list != 0) {
    POSITION pos = list->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(list->GetNext(pos));
      RECT childClip = clippedRect;
      OffsetRect(&childClip, -child->ownerOffsetX, -child->ownerOffsetY);
      RECT childPaintRect;
      CopyRect(&childPaintRect, &childClip);
      child->PaintVisibleChildrenIntersectingClipRect(&childPaintRect, bindArg);
    }
  }
}

// Translate a point into the owner's space (add this view's owner offset) and forward up
// the owner chain via slot 0x4e. Mirror of SubtractPosAndDispatchToOwnerSlot19C (which
// subtracts); recurses until the root owner.
// FUNCTION: IMPERIALISM 0x0048ba40
void TView::TranslatePointToParentChain4E(int* point) {
  point[1] += ownerOffsetY;
  point[0] += ownerOffsetX;
  ownerContext->TranslatePointToParentChain4E(point);
}
// Translate a point into the owner's space (add this view's owner offset) and forward up
// the owner chain via slot 0x4d. Mirror of TranslatePointToParentChain4E (slot 0x4e) but
// on this slot.
// FUNCTION: IMPERIALISM 0x0048ba80
void TView::TranslatePointToParentChain4D(int* point) {
  int offY = ownerOffsetY;
  point[0] += ownerOffsetX;
  point[1] += offY;
  ownerContext->TranslatePointToParentChain4D(point);
}
// Translate a point out of this view's local space and forward it to the owner's
// matching slot (recurses up the owner chain).
// FUNCTION: IMPERIALISM 0x0048bac0
void TView::SubtractPosAndDispatchToOwnerSlot19C(int* point) {
  int offY = ownerOffsetY;
  point[0] = point[0] - ownerOffsetX;
  point[1] = point[1] - offY;
  ownerContext->SubtractPosAndDispatchToOwnerSlot19C(point);
}

// KNOWN ILT (retired): 0x004064e2 is a 5-byte `jmp TView::TView` linker stub — not ported.
// Real ctor: TView::TView @ 0x0048a8e0.
// Offset a rect by this control's owner offset (its position within the owner).
// FUNCTION: IMPERIALISM 0x0048bb00
void TView::OffsetRectByControlPosition(RECT* rect) {
  OffsetRect(rect, ownerOffsetX, ownerOffsetY);
}

// FUNCTION: IMPERIALISM 0x0048bb30
int* TView::GetCachedPosPoint(int* outPoint) {
  int posY = field30;
  outPoint[0] = field2c;
  outPoint[1] = posY;
  return outPoint;
}

// Copy a point, transform it in place through slot 0x4e, and return the result by value.
// FUNCTION: IMPERIALISM 0x0048bb60
CPoint TView::TransformPointViaSlot138(CPoint* inPoint) {
  CPoint local;
  local.x = inPoint->x;
  local.y = inPoint->y;
  TranslatePointToParentChain4E(reinterpret_cast<int*>(&local));
  return local;
}

// Transform a rect: carry its width/height, map its top-left corner through slot 0x52,
// and rebuild the rect at the transformed origin.
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

// Build a rect from the slot-0x56 cached position (top-left) plus the cached size held
// in field34/field38.
// FUNCTION: IMPERIALISM 0x0048bce0
RECT* TView::BuildRectFromSlot158(RECT* rectOut) {
  int width = field34;
  int height = field38;
  int pos[2];
  GetCachedPosPoint(pos);
  rectOut->left = pos[0];
  rectOut->top = pos[1];
  rectOut->right = width + pos[0];
  rectOut->bottom = height + pos[1];
  return rectOut;
}
// FUNCTION: IMPERIALISM 0x0048bef0
void TView::CopyCityDialogStateFromSource(TView* source) {
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

// TView slot 0x08 override: allocate via slot 0x09 then copy city-dialog fields.
// FUNCTION: IMPERIALISM 0x0048bfd0
TObject* TView::ShallowClone() {
  TView* clone = static_cast<TView*>(ShallowFree());
  clone->CopyCityDialogStateFromSource(this);
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
        child->UpdateAfterBitmapChange(reinterpret_cast<int>(&childPoint));
        if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
            child->EvaluateControlInputGate() != 0) {
          child->HandleCursorHoverSelectionByChildHitTestAndFallback(&childPoint, hitArg);
          return;
        }
      }
    }
  }

  if (reinterpret_cast<char(__cdecl*)(int)>(GetRegionBoxToRectIfPresent)(hitArg) != 0 &&
      Refresh() != 0) {
    HandleCursorHoverFallback(point, hitArg);
  }
}

// FUNCTION: IMPERIALISM 0x0048c1c0
void TView::NoOpClipRegionSlot2D(int arg1, int arg2) {}

// FUNCTION: IMPERIALISM 0x0048c1e0
void TView::RefreshCityProductionViewStateFromContext(int* clipRegionWrapper) {
  RECT rect;
  CopyRectFromBuildRectFromSlot158(&rect);
  reinterpret_cast<void(__cdecl*)(int*, RECT*)>(
      reinterpret_cast<void (*)()>(ReplaceClipStateRegionHandleFromRect))(clipRegionWrapper, &rect);
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
      g_pCursorControlPanel->sharedStringRef = sharedStringRef;
      g_pCursorControlPanel->UpdateCursorState();
    }
  }
  if (GetField4E() != 0xffff) {
    CPoint transformedPoint = TransformPointViaSlot138(point);
    if (IsPointInsideHitRegion(&transformedPoint, hitArg)) {
      void* ptr = AssertQuickDrawFlag6A1DCCNonZero(GetField4E());
      AssertQuickDrawFlag6A1DC8NonZero(*reinterpret_cast<void**>(ptr));
      return;
    }
  }
  HCURSOR hCursor = LoadCursorA(nullptr, IDC_ARROW);
  SetCursor(hCursor);
}
// Recompute and store this control's bounds (owner offset + cached size) from a new rect;
// if it changed, optionally bracket the layout pass with city-dialog invalidations and
// propagate the absolute-position recompute (slot 0x59).
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
      child->UpdateAfterBitmapChange(reinterpret_cast<int>(&childPoint));
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
      child->UpdateAfterBitmapChange(reinterpret_cast<int>(&childPoint));
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

// True (3) iff this view is actionable and the point falls inside its content bounds.
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
// Draw this control's rect into the current QuickDraw/GDI context.
// FUNCTION: IMPERIALISM 0x0048c750
void TView::DrawRectangleInCurrentUiContext(int* rect) {
  if (g_McAppUiDrawGate_006A1AF8 == 0) {
    typedef void(__cdecl * UiInvalidationFlagThunk)(const char*, int);
    reinterpret_cast<UiInvalidationFlagThunk>(reinterpret_cast<void (*)()>(
        TemporarilyClearAndRestoreUiInvalidationFlag))(g_szMcAppUiSourcePath_006950B0, 0x772);
  }
  int context = NoOpQuickDrawContextSelectionHook();
  Rectangle(reinterpret_cast<HDC>(*reinterpret_cast<void**>(context + 4)), rect[0], rect[1],
            rect[2], rect[3]);
}
// FUNCTION: IMPERIALISM 0x0048c7a0
void TView::AssertMcAppUiLine1914() {
  if (g_McAppUiFlag_006A1AFC == 0) {
    reinterpret_cast<void(__cdecl*)(const char*, int)>(reinterpret_cast<void (*)()>(
        TemporarilyClearAndRestoreUiInvalidationFlag))(g_szMcAppUiSourcePath_006950B0, 0x77a);
  }
}

// FUNCTION: IMPERIALISM 0x0048c7d0
void TView::AssertMcAppUiLine1922() {
  if (g_McAppUiFlag_006A1B00 == 0) {
    reinterpret_cast<void(__cdecl*)(const char*, int)>(reinterpret_cast<void (*)()>(
        TemporarilyClearAndRestoreUiInvalidationFlag))(g_szMcAppUiSourcePath_006950B0, 0x782);
  }
  RECT rectStorage;
  CopyRectFromBuildRectFromSlot158(&rectStorage);
}

// Walk the field44 child list and forward slot-0x27 to each linked child.
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
// Walk the field44 child list and forward slot-0x28 (CallVoidSlotA0) to each child.
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

// Propagate the native-window/resource context through this subtree.
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
// True (3) iff the point falls inside this view's content bounds.
// FUNCTION: IMPERIALISM 0x0048c990
char TView::TestPointInBounds(CPoint* point) {
  RECT bounds;
  QueryContentBounds(&bounds);
  POINT p;
  p.x = point->x;
  p.y = point->y;
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
