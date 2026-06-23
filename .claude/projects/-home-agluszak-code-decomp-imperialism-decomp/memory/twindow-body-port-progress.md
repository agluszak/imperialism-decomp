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

**Need helper promotion:** 0x48d9c0 (SetWindowTextOrDelegateToOwner), 0x48d9f0
(FUN_0060859f GetWindowText path), 0x48e150 (CenterWindow) — promote those callees into
their owning files first. See [[next-trade-diplomacy-cleanup]] style handoff.
