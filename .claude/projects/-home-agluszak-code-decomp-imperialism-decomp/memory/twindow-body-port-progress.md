---
name: twindow-body-port-progress
description: TWindow.cpp method-body porting state and what blocks the remaining ~14 functions
metadata:
  type: project
---

TWindow.cpp (vtable 0x649e58, object size 0xa0, base TView) body-porting status as of
2026-06-24. 21/35 slot bodies ported from autogen with real shapes (commits e850d2f9,
ae0932d4, 5b29418f). Not chasing 100% — FPO residual left alone per decomp-loop goal.

**Done (real fields/globals/virtuals):** GetRuntimeClass, ShallowClone, OwnerPanel,
QueryOwnerContextPanel, IsActionable, GetEmbeddedDialogBehavior (0x48dcc0, returns
&field74), SetField84/SetField88And8c, TestPointInBounds, ReturnFromUiSlot60-63 +
AssertMcAppUILine2358/2554 (one-shot McAppUI gates g_McAppUiFlag_006A1B04..1C),
GetDialogBehaviorByte10/20 (0x48da10/dc60, virtual call to GetEmbeddedDialogBehavior),
0x48e120 (CallVoidSlotA0+Free), 0x48d900 (SendMessageA 0x468 + RefreshControl),
0x48ddc0 (field64 linked-window swap via slots 0x1b/0x1c).

**Data model added:** TWindow own fields field64 (TWindow* @0x64), field74[0x10]
(embedded TDialogBehavior @0x74), field84/88/8c/98; PTR_s_TWindow_006495e8 runtime-class
descriptor (+ GLOBAL marker in global_data_tables.cpp). Renames in
config/function_name_overrides.csv.

**Blocked — need TDialogBehavior recovered first:** 0x48dc90, 0x48dd10, 0x48dd50
dispatch through `*(int*)&field74 + 0xNN` (the 0x74 subobject's OWN vtable). Faithful
port needs field74 modelled as a real class with a real vtable (use class-recovery);
raw `vftable[...]` is banned (Hard Rule 11).

**Blocked — large EH/child-iteration, also touch field74 vtable + child list44:**
0x48de00 (DispatchSlot9CToLinkedChildren), 0x48e060 (CallVoidSlotA0), 0x48da60
(ExecuteViewModalState), 0x48e2a0 (Free) — EH-framed, iterate childList44 and dispatch
slot 0xA0/0x1CC.

**Need helper promotion:** 0x48d9c0 (SetWindowTextOrDelegateToOwner @0x6073b4), 0x48d9f0
(FUN_0060859f GetWindowText path), 0x48e150 (CenterWindow) — promote/declare those callees
first (mind the Hard Rule 9 thunk-signature trap: forward-declare generic + reinterpret_cast).

**Done since (commits 5b29418f..03c0fe15):** TDialogBehavior recovered (fields +
GetRuntimeClass + slot-0x0e 2-arg fix); TWindow GetEmbeddedDialogBehavior returns real
TDialogBehavior*, byte-getters/0x48dc90/0x48dd10(DispatchEvent)/0x48e060(CallVoidSlotA0)
wired with real dispatch; TDialogView fully ported (GetRuntimeClass + EnsureField48Buffer
100%). g_pClassDescTDialogBehavior/TDialogView descriptors added.

**KEY: mfc.h includes real <afx.h>/<afxwin.h>** — CObject/CWnd/CString/CPtrList are the
REAL MFC classes with real virtuals. Do NOT model them. Call them directly
(nativeWindow50->IsKindOf/AssertValid/CenterWindow, delete window, childList44->GetHead())
and rely on // LIBRARY annotations (CObject::IsKindOf @0x606fc0 already annotated in
CObject.cpp) for pairing. The root_types.h CWnd/CObject are unused placeholders.

**0x48e2a0 Free — DONE (62%, commit 6c69fe86)** via real MFC: IsKindOf(CMcWindow,
g_pClassDescCMcWindow @0x64b5d0) + AssertValid + delete; child Free loop; ownerContext
DetachChildFromOwnerList; GetActiveView/QueryStepValue/SetActiveView; field18 Free;
delete this. Template for other teardown/window functions.
Also done: HandleEvent (0x48dd50), CenterWindow wrapper (0x48e150, real CWnd::CenterWindow
@0x60a27d), CallVoidSlotA0 (0x48e060), DispatchEvent (0x48dd10).

**Still TODO — need custom data-structure modeling (not MFC, do carefully not fast):**
- 0x48da60 ExecuteViewModalStateWithPushPopChain (394B): pushes `this` onto the global
  modal block-pool chain (DAT_006a1ac4 head / ac8 tail / acc count / ad0 free / ad4/ad8
  block pool — same intrusive-list+block-pool as TView::SerializeRecordList_0x0C), runs
  dialogBehavior->CreateTCommandInstance() (slot 0x12, the modal loop), pops. Vtable
  dispatch slot 3 (AssertValid) on chain TViews. Helpers: AllocateAndLinkBlockHead
  @0x601b74, WrapperFor_FreeLinkedBlockChain @0x4061c7, 0x60753b, 0x4087e2.
- 0x48de00 DispatchSlot9CToLinkedChildren (472B, EH-framed): creates the MC window
  (CreateMcWindowFromDescriptorAndShow), iterates childList44 with a custom STACK-allocated
  filtered iterator (ctor @0x404368, advance @0x407cb1/@0x408526; fields current/this/
  flag/4charCode/head) — recover that iterator class first. Real virtuals otherwise
  (IsActionable slot 0x3b, field64 slot 0x21, child->DispatchSlot9C slot 0x27).
- Tiny: 0x48d9c0/0x48d9f0 are __thiscall on the CWnd receiver to game helpers
  (SetWindowTextOrDelegateToOwner @0x6073b4, FUN_0060859f) — need the receiver's method
  modeled (don't fake thiscall).
