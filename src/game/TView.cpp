// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#pragma optimize("y", on)
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>

#include "game/ApplicationUiRootController.h"
#include "game/TView.h"
#include "game/mcappui_globals.h"
#include "game/generated/vcall_facades.h"

extern "C" int __stdcall ValidateRect(void* hWnd, const struct RECT* rect);
extern "C" int __stdcall Rectangle(void* hdc, int left, int top, int right, int bottom);
extern "C" __declspec(dllimport) int __stdcall PtInRect(const struct RECT* rect, Point32 pt);
extern "C" __declspec(dllimport) int __stdcall UnionRect(struct RECT* dest, const struct RECT* src1,
                                                         const struct RECT* src2);
extern "C" __declspec(dllimport) int __stdcall InvalidateRect(void* hWnd, const struct RECT* rect,
                                                              int erase);

// Generic thunk/hook decls kept in repo form (rule 9): typed function-pointer casts at
// the callsite rather than changing the thunk declaration signature.
undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);
undefined4 NoOpQuickDrawContextSelectionHook(void);
undefined4 thunk_InvalidateCityDialogRectRegion(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 BindScopedMapQuickDrawDcHandle(void);
undefined4 ReleaseScopedMapQuickDrawDcHandle(void);

// TView::childList44 is an MFC CPtrList of child-control TView* pointers (node->data).

// Real ctor. The scalar fields are member-initializers (not body assignments) so
// they are emitted in declaration order *before* the CString member sharedStringRef
// is constructed (-> 0x00605797), matching the original phase split. The inlined
// TEventHandler base ctor writes the base vptr (0x006497a0) + field0c; MSVC writes
// this class's vptr (0x00649858) last. No manual vtable writes — the // VTABLE:
// annotation owns it.
// FUNCTION: IMPERIALISM 0x0048a8e0
TView::TView()
    : field10(0x7fffffff), field14(0), field18(0), ownerContext(0), field2c(0), field30(0),
      field3c(0), childList44(0), field48(0), flag4c(1), flag4d(1), field4e(0xffff), nativeWindow50(0),
      field54(1), sharedStringRef(), field5c(0) {}

// FUNCTION: IMPERIALISM 0x0048a9d0
TView::~TView() {
  delete childList44;
  FreeHeapBufferIfNotNull(field48);
}

// SYNTHETIC: IMPERIALISM 0x0048a9a0
// TView::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00406ba9
void TView::thunk_NoOpUiLifecycleHook(int passthroughArg) {
  (void)passthroughArg;
}

// Dummy methods
void TView::vmethod_0002() {}
void TView::vmethod_0003() {}
void TView::vmethod_0004() {}
void TView::vmethod_0005() {}
void TView::vmethod_0006() {}
void TView::CallVoidSlot1C() {}
void TView::vmethod_0008() {}
void TView::vmethod_0009() {}
// FUNCTION: IMPERIALISM 0x0048a240
char TView::GetBoolSlot28() {
  return (char)field04;
}

// FUNCTION: IMPERIALISM 0x0048a260
void TView::SetControlValue(int value) {
  field04 = (signed char)value;
}

// FUNCTION: IMPERIALISM 0x0048a2c0
int TView::QueryStepValue() {
  return field0c;
}
// Dispatch a queued command record: the command's stored handler (cmd+0x10) receives the
// command's payload words (cmd+0x08, cmd+0x0c) plus the command itself, then the command
// is released via slot 0x07.
// FUNCTION: IMPERIALISM 0x0048a3b0
void TView::vmethod_0013(int* cmd) {
  reinterpret_cast<TView*>(cmd[4])->DispatchEvent(cmd[2], reinterpret_cast<void*>(cmd[3]),
                                                  reinterpret_cast<int>(cmd));
  if (cmd != 0) {
    reinterpret_cast<TView*>(cmd)->CallVoidSlot1C();
  }
}
// FUNCTION: IMPERIALISM 0x0048a3f0
void TView::vmethod_0014(int command) {
  vmethod_0013(reinterpret_cast<int*>(command));
}
// Forward an event triplet to the child object returned by slot 0x0c (QueryStepValue),
// if any. Derived classes override slot 0x0c to return the active child control.
// FUNCTION: IMPERIALISM 0x0048a280
void TView::vmethod_0015(int arg1, void* arg2, int arg3) {
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->DispatchEvent(arg1, arg2, arg3);
  }
}
// FUNCTION: IMPERIALISM 0x0048a2e0
void TView::DispatchEvent(int arg1, void* arg2, int arg3) {
  vmethod_0015(arg1, arg2, arg3);
}
// FUNCTION: IMPERIALISM 0x0048a310
void TView::vmethod_0017(int param) {
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->vmethod_0017(param);
  }
}
// FUNCTION: IMPERIALISM 0x0048a380
void TView::ForwardParam(int param) {
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->ForwardParam(param);
  }
}
// FUNCTION: IMPERIALISM 0x0048a480
char TView::vmethod_0019() {
  return 0;
}
void TView::vmethod_0020() {}
void TView::vmethod_0021() {}
// Walk up the owner chain: forward to the owner context's own slot-0x16 query, or 0
// at the root. (One level above QueryOwnerContextPanel, which only hops once.)
// FUNCTION: IMPERIALISM 0x0048b180
TView* TView::OwnerPanel() {
  if (ownerContext == 0) {
    return 0;
  }
  return ownerContext->OwnerPanel();
}
// FUNCTION: IMPERIALISM 0x0048a530
char TView::vmethod_0023() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048a550
char TView::vmethod_0024() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048a690
void TView::vmethod_0025() {}
// FUNCTION: IMPERIALISM 0x0048a6b0
void TView::vmethod_0026(int gate) {
  (void)gate;
}
void TView::vmethod_0027() {}
void TView::vmethod_0028() {}
void TView::vmethod_0029() {}
void TView::vmethod_0030() {}
// Make this view the active view if allowed: already-active short-circuits to true;
// otherwise the current active view must agree (slot 0x20) before we take over.
// FUNCTION: IMPERIALISM 0x0048a570
char TView::vmethod_0031() {
  TView* active = g_pApplicationUiRootController->GetActiveView();
  if (this == active) {
    return 1;
  }
  if (active != 0 && active->vmethod_0080() != 0) {
    g_pApplicationUiRootController->SetActiveView(this);
    return 1;
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048a5e0
char TView::vmethod_0080() {
  if (g_pApplicationUiRootController == 0) {
    return 0;
  }
  TView* activeView = g_pApplicationUiRootController->GetActiveView();
  if (activeView == 0) {
    return 0;
  }
  char gate = activeView->vmethod_0024();
  if (gate == 0) {
    activeView->vmethod_0025();
    g_pApplicationUiRootController->SetActiveView(
        reinterpret_cast<TView*>(g_pApplicationUiRootController));
    return 1;
  }
  activeView->vmethod_0026(gate);
  return 0;
}
// FUNCTION: IMPERIALISM 0x0048a710
void TView::vmethod_0081() {}
// True iff this view is the root controller's current active view.
// FUNCTION: IMPERIALISM 0x0048a500
char TView::vmethod_0032() {
  return this == g_pApplicationUiRootController->GetActiveView();
}
// If the given object is our currently-linked field18 target, detach it both ways.
// FUNCTION: IMPERIALISM 0x0048a4a0
void TView::vmethod_0033(int arg) {
  if (field18 != 0 && field18 == arg) {
    field18 = 0;
    *reinterpret_cast<int*>(arg + 8) = 0;
  }
}
void TView::vmethod_0034() {}
void TView::vmethod_0035() {}
// Link this view to a resource-owner object and set the owner's back-pointer to this.
// FUNCTION: IMPERIALISM 0x0048a4d0
void TView::SetUiResourceOwner(int owner) {
  if (owner != 0) {
    field18 = owner;
    *reinterpret_cast<int*>(owner + 8) = reinterpret_cast<int>(this);
  }
}
class TControl* TView::ResolveControlByTag(unsigned int controlTag) {
  return 0;
}
// If the child list's tail element is not already the given child, notify the old/new
// selection (slots 0x5d/0x5c) and refresh the newly active child.
// FUNCTION: IMPERIALISM 0x0048af80
void TView::SwitchActiveChildAndNotify(class TView* child) {
  if (childList44 != 0 && childList44->tailNode->data != child) {
    vmethod_0093(child);
    vmethod_0092(child, 1);
    child->RefreshControl();
  }
}

// Walk the field44 child list and forward slot-0x27 to each linked child.
// FUNCTION: IMPERIALISM 0x0048c820
void TView::DispatchSlot9CToLinkedChildren() {
  CPtrListNode* node;
  if (childList44 == 0) {
    node = 0;
  } else {
    node = childList44->headNode;
  }
  TView* child;
  if (node == 0) {
    child = 0;
    node = 0;
  } else {
    child = reinterpret_cast<TView*>(node->data);
    node = node->next;
  }
  while (child != 0) {
    child->DispatchSlot9CToLinkedChildren();
    if (node == 0) {
      child = 0;
      node = 0;
    } else {
      child = reinterpret_cast<TView*>(node->data);
      node = node->next;
    }
  }
}
// Walk the field44 child list and forward slot-0x28 (CallVoidSlotA0) to each child.
// FUNCTION: IMPERIALISM 0x0048c890
void TView::CallVoidSlotA0() {
  CPtrListNode* node;
  if (childList44 == 0) {
    node = 0;
  } else {
    node = childList44->headNode;
  }
  TView* child;
  if (node == 0) {
    child = 0;
    node = 0;
  } else {
    child = reinterpret_cast<TView*>(node->data);
    node = node->next;
  }
  while (child != 0) {
    child->CallVoidSlotA0();
    if (node == 0) {
      child = 0;
      node = 0;
    } else {
      child = reinterpret_cast<TView*>(node->data);
      node = node->next;
    }
  }
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
// Push the control value through slot 0x0b, then refresh when it is non-zero.
// FUNCTION: IMPERIALISM 0x0048b070
void TView::SetState(int state, int refreshFlag) {
  (void)refreshFlag;
  SetControlValue(state);
  if (state != 0) {
    RefreshControl();
  }
}
void TView::vmethod_0043() {}
void TView::vmethod_0044() {}
void TView::vmethod_0045() {}
void TView::vmethod_0046() {}
int TView::QuerySelectedIndexSlotBC() {
  return 0;
}
void TView::vmethod_0048() {}
// Forward a map-view notification (slot 0x31) up to the owning view, if any.
// FUNCTION: IMPERIALISM 0x0048ab90
void TView::ForwardMapViewVirtualC4IfPresent(int param) {
  if (ownerContext != 0) {
    ownerContext->ForwardMapViewVirtualC4IfPresent(param);
  }
}

// FUNCTION: IMPERIALISM 0x0048b690
void TView::ValidateControlRectIfWindowActive(struct RECT* rect) {
  if (nativeWindow50 != 0 && g_McAppUiActiveFlag_006950AC != 0) {
    ValidateRect(nativeWindow50->hwnd, rect);
  }
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
  if (flag4d != 0 && childList44 != 0 && childList44->nodeCount != 0) {
    return 1;
  }
  return 0;
}
void TView::vmethod_0053() {}
// Recursively dispatch a control event: walk the field44 child list, forward to each
// child's slot-0x36, then invoke this view's own slot-0x37 handler.
// FUNCTION: IMPERIALISM 0x0048aaf0
void TView::DispatchControlEventToChildrenAndSelf(int eventArg) {
  CPtrListNode* node;
  if (childList44 == 0) {
    node = 0;
  } else {
    node = childList44->headNode;
  }
  TView* child;
  if (node == 0) {
    child = 0;
    node = 0;
  } else {
    child = reinterpret_cast<TView*>(node->data);
    node = node->next;
  }
  while (child != 0) {
    child->DispatchControlEventToChildrenAndSelf(eventArg);
    if (node == 0) {
      child = 0;
      node = 0;
    } else {
      child = reinterpret_cast<TView*>(node->data);
      node = node->next;
    }
  }
  vmethod_0055(eventArg);
}
void TView::vmethod_0055(unsigned int styleSeed) {
  (void)styleSeed;
}
// FUNCTION: IMPERIALISM 0x0048abc0
void TView::NoOpUiCallback() {}
// FUNCTION: IMPERIALISM 0x0048b6d0
void TView::RefreshControl() {
  if (g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0) {
    reinterpret_cast<void(__stdcall*)(struct RECT*, int)>(thunk_InvalidateCityDialogRectRegion)(0, 1);
  }
}
// Forward to the owner context's panel query (slot 0x16), or 0 if no owner.
// FUNCTION: IMPERIALISM 0x0048b1a0
TView* TView::QueryOwnerContextPanel() {
  if (ownerContext == 0) {
    return 0;
  }
  return ownerContext->OwnerPanel();
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
    reinterpret_cast<void(__stdcall*)(struct RECT*, int)>(thunk_InvalidateCityDialogRectRegion)(0, 1);
  }
  ownerOffsetX = buffer[0];
  ownerOffsetY = buffer[1];
  vmethod_0089();
  if (modeFlag != 0 && IsActionable() != 0) {
    reinterpret_cast<void(__stdcall*)(struct RECT*, int)>(thunk_InvalidateCityDialogRectRegion)(0, 0);
  }
}
// Update the cached position (field34/field38) to buffer's point. When modeFlag is set,
// capture the control rect before and after the move and invalidate their union.
// FUNCTION: IMPERIALISM 0x0048b3f0
void TView::CaptureLayout(int* buffer, int modeFlag) {
  if (modeFlag != 0) {
    RECT oldRect;
    vmethod_0087(reinterpret_cast<int*>(&oldRect));
    field34 = buffer[0];
    field38 = buffer[1];
    RECT newRect;
    vmethod_0087(reinterpret_cast<int*>(&newRect));
    RECT unionRect;
    UnionRect(&unionRect, &newRect, &oldRect);
    if (g_McAppUiActiveFlag_006950AC != 0) {
      InvalidateRect(nativeWindow50->hwnd, &unionRect, 0);
    }
  } else {
    field34 = buffer[0];
    field38 = buffer[1];
  }
}
char TView::Refresh() {
  return 0;
}
void TView::PostRenderSlotFC() {}
// FUNCTION: IMPERIALISM 0x0048b7b0
void TView::BindMapQuickDrawDc(int arg) {
  reinterpret_cast<void(__cdecl*)(TView*, int)>(BindScopedMapQuickDrawDcHandle)(this, arg);
}

// FUNCTION: IMPERIALISM 0x0048b7e0
void TView::ReleaseMapQuickDrawDc(int arg) {
  reinterpret_cast<void(__cdecl*)(TView*, int)>(ReleaseScopedMapQuickDrawDcHandle)(this, arg);
}
// Lazily allocate the 8-byte auxiliary buffer stored at field48 (freed in the dtor).
// FUNCTION: IMPERIALISM 0x0048b810
void TView::EnsureField48Buffer() {
  if (field48 == 0) {
    int* buffer = reinterpret_cast<int*>(AllocateWithFallbackHandler(8));
    if (buffer != 0) {
      buffer[0] = 0;
      buffer[1] = 0;
      field48 = reinterpret_cast<int>(buffer);
      return;
    }
    field48 = 0;
  }
}
void TView::vmethod_0067() {}
void TView::ApplyRectSlot110(int* rectBuffer) {}
void TView::UpdateAfterBitmapChange(int unknownFlag) {}
void TView::vmethod_0070() {}
void TView::vmethod_0071() {}
void TView::vmethod_0072(int arg1, int arg2, int arg3, int arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
}
// FUNCTION: IMPERIALISM 0x0048c1c0
void TView::vmethod_0073(int arg1, int arg2) {}
void TView::QueryContentBounds(int* boundsBuffer) {}
void TView::QueryBounds(int* boundsBuffer) {}
void TView::vmethod_0076() {}
void TView::vmethod_0077() {}
// Translate a point into the owner's space (add this view's owner offset) and forward up
// the owner chain via slot 0x4e. Mirror of SubtractPosAndDispatchToOwnerSlot19C (which
// subtracts); recurses until the root owner.
// FUNCTION: IMPERIALISM 0x0048ba40
void TView::vmethod_0078(int* point) {
  point[1] += ownerOffsetY;
  point[0] += ownerOffsetX;
  ownerContext->vmethod_0078(point);
}
void TView::InvokeSlot13C() {}

// Copy a point, transform it in place through slot 0x4e, and return the result by value.
// FUNCTION: IMPERIALISM 0x0048bb60
Point32 TView::TransformPointViaSlot138(Point32* inPoint) {
  Point32 local;
  local.x = inPoint->x;
  local.y = inPoint->y;
  vmethod_0078(reinterpret_cast<int*>(&local));
  return local;
}

// Transform a rect: carry its width/height, map its top-left corner through slot 0x52,
// and rebuild the rect at the transformed origin.
// FUNCTION: IMPERIALISM 0x0048bbb0
struct RECT TView::TransformRectViaSlot148(struct RECT* inRect) {
  int width = inRect->right - inRect->left;
  int height = inRect->bottom - inRect->top;
  Point32 corner;
  corner.x = inRect->left;
  corner.y = inRect->top;
  Point32 mapped = TransformPointViaSlot138(&corner);
  RECT result;
  result.left = mapped.x;
  result.top = mapped.y;
  result.right = mapped.x + width;
  result.bottom = mapped.y + height;
  return result;
}
// FUNCTION: IMPERIALISM 0x0048bc30
void TView::AddControlPosToPoint(int x, int y, int* outPoint) {
  int posY = field30;
  outPoint[0] = x + field2c;
  outPoint[1] = posY + y;
}

// FUNCTION: IMPERIALISM 0x0048bc60
void TView::OffsetRectByCachedPos(struct RECT* inRect, struct RECT* outRect) {
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

// FUNCTION: IMPERIALISM 0x0048bb30
int* TView::GetCachedPosPoint(int* outPoint) {
  int posY = field30;
  outPoint[0] = field2c;
  outPoint[1] = posY;
  return outPoint;
}
void TView::vmethod_0087(int* rectOut) {}

// Build a rect from the slot-0x56 cached position (top-left) plus the cached size held
// in field34/field38.
// FUNCTION: IMPERIALISM 0x0048bce0
struct RECT TView::BuildRectFromSlot158() {
  int width = field34;
  int height = field38;
  Point32 origin;
  int* pt = GetCachedPosPoint(reinterpret_cast<int*>(&origin));
  RECT result;
  result.left = pt[0];
  result.top = pt[1];
  result.right = width + pt[0];
  result.bottom = height + pt[1];
  return result;
}

void TView::vmethod_0089() {}
void TView::ApplyBounds(int* boundsBuffer, int modeFlag) {}

// True (3) iff this view is actionable and the point falls inside its content bounds.
// FUNCTION: IMPERIALISM 0x0048c6d0
char TView::PointInBoundsAndActionable(Point32* point) {
  RECT bounds;
  QueryContentBounds(reinterpret_cast<int*>(&bounds));
  if (IsActionable() != 0) {
    Point32 p;
    p.x = point->x;
    p.y = point->y;
    if (PtInRect(&bounds, p) != 0) {
      return 1;
    }
  }
  return 0;
}
void TView::vmethod_0092(class TView* child, int flag) {}
// Find the child whose controlTag matches, unlink it from childList44 (inlined
// CPtrList::RemoveAt; when the list empties, free its block chain), delete the now-empty
// list, and clear the child's back-reference to this owner.
// FUNCTION: IMPERIALISM 0x0048ae60
void TView::vmethod_0093(class TView* child) {
  CPtrList* list = childList44;
  int tag = child->controlTag;
  CPtrListNode* head = list->headNode;
  CPtrListNode* node = head;
  CPtrListNode* cur;
  int newCount;
  while (node != 0) {
    cur = node;
    node = cur->next;
    if (tag == reinterpret_cast<TView*>(cur->data)->controlTag) {
      goto unlink;
    }
  }
  if (g_McAppUiFlag_006A1AE0 == 0) {
    reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(
        g_szMcAppUiSourcePath_006950B0, 0x152);
  }
  goto tail;

unlink:
  if (cur == head) {
    list->headNode = cur->next;
  } else {
    cur->prev->next = cur->next;
  }
  if (cur == list->tailNode) {
    list->tailNode = cur->prev;
  } else {
    cur->next->prev = cur->prev;
  }
  cur->next = list->freeNodeList;
  newCount = list->nodeCount - 1;
  list->freeNodeList = cur;
  list->nodeCount = newCount;
  if (newCount == 0) {
    for (CPtrListNode* p = list->headNode; p != 0; p = p->next) {
    }
    void* chain = list->blockChain;
    list->nodeCount = 0;
    list->freeNodeList = 0;
    list->tailNode = 0;
    list->headNode = 0;
    FreeLinkedBlockChain(chain);
    list->blockChain = 0;
  }

tail:
  if (childList44->nodeCount == 0) {
    delete childList44;
    childList44 = 0;
  }
  child->ownerContext = 0;
}
// FUNCTION: IMPERIALISM 0x0048c970
unsigned short TView::GetField54() {
  return field54;
}
// True (3) iff the point falls inside this view's content bounds.
// FUNCTION: IMPERIALISM 0x0048c990
char TView::TestPointInBounds(Point32* point) {
  RECT bounds;
  QueryContentBounds(reinterpret_cast<int*>(&bounds));
  Point32 p;
  p.x = point->x;
  p.y = point->y;
  return -(PtInRect(&bounds, p) != 0) & 3;
}
// FUNCTION: IMPERIALISM 0x0048c9e0
void TView::vmethod_0096(int arg) {}
// FUNCTION: IMPERIALISM 0x0048ca00
void TView::vmethod_0097(int arg) {}
// FUNCTION: IMPERIALISM 0x0048ca20
void TView::vmethod_0098(int arg) {}
// FUNCTION: IMPERIALISM 0x0048ca40
void TView::vmethod_0099(int arg1, int arg2) {}
// Draw this control's rect into the current QuickDraw/GDI context.
// FUNCTION: IMPERIALISM 0x0048c750
void TView::DrawRectangleInCurrentUiContext(int* rect) {
  if (g_McAppUiDrawGate_006A1AF8 == 0) {
    typedef void(__cdecl* UiInvalidationFlagThunk)(const char*, int);
    reinterpret_cast<UiInvalidationFlagThunk>(thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(
        g_szMcAppUiSourcePath_006950B0, 0x772);
  }
  int context = NoOpQuickDrawContextSelectionHook();
  Rectangle(*reinterpret_cast<void**>(context + 4), rect[0], rect[1], rect[2], rect[3]);
}
// FUNCTION: IMPERIALISM 0x0048c7a0
void TView::AssertMcAppUiLine1914() {
  if (g_McAppUiFlag_006A1AFC == 0) {
    reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(
        g_szMcAppUiSourcePath_006950B0, 0x77a);
  }
}

// FUNCTION: IMPERIALISM 0x0048c7d0
void TView::AssertMcAppUiLine1922() {
  if (g_McAppUiFlag_006A1B00 == 0) {
    reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(
        g_szMcAppUiSourcePath_006950B0, 0x782);
  }
  int rect[4];
  vmethod_0087(rect);
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

// KNOWN LINKER ARTIFACT: 0x004064e2 is `jmp TView::TView`.
// FUNCTION: IMPERIALISM 0x004064e2
void __fastcall ConstructTViewBaseStateThunk(TView* self) {
  new (self) TView();
}
