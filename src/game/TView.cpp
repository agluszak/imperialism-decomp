// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#pragma optimize("y", on)
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>

#include "game/TView.h"
#include "game/CString.h"
#include "game/mcappui_globals.h"
#include "game/generated/vcall_facades.h"

extern "C" int __stdcall ValidateRect(void* hWnd, const struct RECT* rect);
extern "C" int __stdcall Rectangle(void* hdc, int left, int top, int right, int bottom);

// Generic thunk/hook decls kept in repo form (rule 9): typed function-pointer casts at
// the callsite rather than changing the thunk declaration signature.
undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);
undefined4 NoOpQuickDrawContextSelectionHook(void);
undefined4 thunk_InvalidateCityDialogRectRegion(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);

namespace {

// TView::field44 holds a CObList-style child-control container: a vtable-bearing list
// object whose head/tail node pointers thread the child TView elements. Typed view so
// the child-walk reads as real field accesses instead of cast-helper indirection.
struct TChildListNode {
  TChildListNode* next;     // +0x00
  TChildListNode* prev;     // +0x04
  TView* element;           // +0x08
};

struct TChildList {
  void* vftable;            // +0x00
  TChildListNode* head;     // +0x04
  TChildListNode* tail;     // +0x08
  int count;                // +0x0c
  TChildListNode* freeList; // +0x10
  int field14;              // +0x14
};

} // namespace

// Real ctor. The scalar fields are member-initializers (not body assignments) so
// they are emitted in declaration order *before* the CString member sharedStringRef
// is constructed (-> 0x00605797), matching the original phase split. The inlined
// TEventHandler base ctor writes the base vptr (0x006497a0) + field0c; MSVC writes
// this class's vptr (0x00649858) last. No manual vtable writes — the // VTABLE:
// annotation owns it.
// FUNCTION: IMPERIALISM 0x0048a8e0
TView::TView()
    : field10(0x7fffffff), field14(0), field18(0), ownerContext(0), field2c(0), field30(0),
      field3c(0), field44(0), field48(0), flag4c(1), flag4d(1), field4e(0xffff), nativeWindow50(0),
      field54(1), sharedStringRef(), field5c(0) {}

// FUNCTION: IMPERIALISM 0x0048a9d0
TView::~TView() {
  delete reinterpret_cast<TView*>(field44);
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
void TView::vmethod_0013() {}
void TView::vmethod_0014() {}
void TView::vmethod_0015() {}
void TView::DispatchEvent(int arg1, void* arg2, int arg3) {}
void TView::vmethod_0017() {}
void TView::ForwardParam(int param) {}
void TView::vmethod_0019() {}
void TView::vmethod_0020() {}
void TView::vmethod_0021() {}
TView* TView::OwnerPanel() {
  return 0;
}
void TView::vmethod_0023() {}
void TView::vmethod_0024() {}
void TView::vmethod_0025() {}
void TView::vmethod_0026() {}
void TView::vmethod_0027() {}
void TView::vmethod_0028() {}
void TView::vmethod_0029() {}
void TView::vmethod_0030() {}
void TView::vmethod_0031() {}
void TView::vmethod_0032() {}
// FUNCTION: IMPERIALISM 0x0048a710
void TView::vmethod_0033(int arg) {}
void TView::vmethod_0034() {}
void TView::vmethod_0035() {}
void TView::vmethod_0036() {}
class TControl* TView::ResolveControlByTag(unsigned int controlTag) {
  return 0;
}
// If the child list's tail element is not already the given child, notify the old/new
// selection (slots 0x5d/0x5c) and refresh the newly active child.
// FUNCTION: IMPERIALISM 0x0048af80
void TView::SwitchActiveChildAndNotify(class TView* child) {
  if (field44 != 0 && reinterpret_cast<TChildList*>(field44)->tail->element != child) {
    vmethod_0093(child);
    vmethod_0092(child, 1);
    child->RefreshControl();
  }
}

// Walk the field44 child list and forward slot-0x27 to each linked child.
// FUNCTION: IMPERIALISM 0x0048c820
void TView::DispatchSlot9CToLinkedChildren() {
  TChildListNode* node;
  if (field44 == 0) {
    node = 0;
  } else {
    node = reinterpret_cast<TChildList*>(field44)->head;
  }
  TView* child;
  if (node == 0) {
    child = 0;
    node = 0;
  } else {
    child = node->element;
    node = node->next;
  }
  while (child != 0) {
    child->DispatchSlot9CToLinkedChildren();
    if (node == 0) {
      child = 0;
      node = 0;
    } else {
      child = node->element;
      node = node->next;
    }
  }
}
void TView::CallVoidSlotA0() {}
void TView::SetEnabled(int enabledState, int refreshFlag) {}
void TView::SetState(int state, int refreshFlag) {}
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
  if (flag4d != 0 && field44 != 0 && reinterpret_cast<TChildList*>(field44)->count != 0) {
    return 1;
  }
  return 0;
}
void TView::vmethod_0053() {}
// Recursively dispatch a control event: walk the field44 child list, forward to each
// child's slot-0x36, then invoke this view's own slot-0x37 handler.
// FUNCTION: IMPERIALISM 0x0048aaf0
void TView::DispatchControlEventToChildrenAndSelf(int eventArg) {
  TChildListNode* node;
  if (field44 == 0) {
    node = 0;
  } else {
    node = reinterpret_cast<TChildList*>(field44)->head;
  }
  TView* child;
  if (node == 0) {
    child = 0;
    node = 0;
  } else {
    child = node->element;
    node = node->next;
  }
  while (child != 0) {
    child->DispatchControlEventToChildrenAndSelf(eventArg);
    if (node == 0) {
      child = 0;
      node = 0;
    } else {
      child = node->element;
      node = node->next;
    }
  }
  vmethod_0055(eventArg);
}
void TView::vmethod_0055(unsigned int styleSeed) {
  (void)styleSeed;
}
void TView::vmethod_0056() {}
void TView::RefreshControl() {}
void TView::vmethod_0058() {}
int TView::IsActionable() {
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
void TView::CaptureLayout(int* buffer, int modeFlag) {}
char TView::Refresh() {
  return 0;
}
void TView::PostRenderSlotFC() {}
void TView::vmethod_0064() {}
void TView::vmethod_0065() {}
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
void TView::vmethod_0078() {}
void TView::InvokeSlot13C() {}
void TView::vmethod_0080() {}
void TView::vmethod_0081() {}
void TView::vmethod_0082() {}
void TView::vmethod_0083() {}
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
void TView::GetCachedPosPoint(int* outPoint) {
  int posY = field30;
  outPoint[0] = field2c;
  outPoint[1] = posY;
}
void TView::vmethod_0087() {}
void TView::vmethod_0088() {}
void TView::vmethod_0089() {}
void TView::ApplyBounds(int* boundsBuffer, int modeFlag) {}
char TView::vmethod_0091(void* arg1) {
  return 0;
}
void TView::vmethod_0092(class TView* child, int flag) {}
void TView::vmethod_0093(class TView* child) {}
void TView::vmethod_0094() {}
void TView::vmethod_0095() {}
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
void TView::vmethod_0101() {}
void TView::vmethod_0102() {}
void TView::vmethod_0103() {}

// KNOWN LINKER ARTIFACT: 0x004064e2 is `jmp TView::TView`.
// FUNCTION: IMPERIALISM 0x004064e2
void __fastcall ConstructTViewBaseStateThunk(TView* self) {
  new (self) TView();
}
