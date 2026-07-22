# Cluster / UI-control vtable map (verified ground truth)

Foundation for remodeling the cluster family as correct C++ classes. Every entry
here is read from the binary via `tools/ghidra/vtable_matrix.py` (resolves each
slot through one ILT jmp thunk to the real target). The current headers
(`TView.h`, `TControl.h`, `TCluster.h`, `TUberCluster.h`) are placeholder-named
(`vmethod_NNNN`) and their slot order does **not** match this; they only "work"
because reccmp pairs by `// FUNCTION:` address marker, not by vtable slot order.

Hierarchy is **single inheritance**, flat at the leaves:
`TView → TControl → TCluster → TUberCluster → { TTradeCluster, TProductionCluster,
TIndustryCluster, TRailCluster, TShipyardCluster }` (all leaves call
`TUberCluster::TUberCluster` 0x571460 then write their own vtable).

Vtable addresses: TView `0x649858`, TControl `0x64a098`, TCluster `0x64b0c0`,
TUberCluster `0x65f210`, TProductionCluster `0x6653c8`, TTradeCluster `0x665a70`,
TIndustryCluster `0x665ed0`, TRailCluster `0x666318`, TShipyardCluster `0x666760`.

## Slot ownership (who introduces / overrides)

- **TView introduces slots 0x00–0x67** (104 virtuals). Slot 0x00 = GetClassName/RTTI
  (`0x48a8c0`), slot 0x01 = scalar deleting dtor (`0x48a9a0`).
- **TControl introduces slots 0x68–0x70** (9), overrides 0x00,0x01,0x08,0x0f,0x2f,0x47,0x5b.
- **TCluster introduces slots 0x71–0x72** (2), overrides 0x00,0x01,0x08,0x0f.
- **TUberCluster introduces slot 0x73** (`0x5714e0`) **+ abstract slots 0x74–0x7b**
  (literal NULL in its vtable — concrete clusters fill them), overrides 0x00,0x01,0x08.
  NOTE: slot 0x73 is NULL in TCluster, so it belongs to TUberCluster, not TCluster
  (current `TCluster.h` places vmethod_0115@0x73 — wrong).

## TView slots 0x00–0x67 (real names; `FUN_`/`sub_` embed the address)

```
00 GetClassName(0x48a8c0)        01 scalar dtor(0x48a9a0)
02 HandleTurnEventVtableSlot08ConditionalDispatch  03 NoOpTurnEventStateVtableSlot0C
04 NoOpTurnEventStateVtableSlot10 05 HandleCityDialogNoOpSlot14
06 HandleCityDialogNoOpSlot18     07 CloseCityDialogChildrenAndReleaseSelf
08 CloneEngineerDialogStateToNewInstance  09 HandleTurnEventVtableSlot24CopyPayloadBuffer
0a GetCityDialogFlagByte4         0b SetCityDialogFlagByte4
0c GetCityDialogValueDwordC       0d DispatchQueuedUiCommandAndRelease
0e DispatchUiSelectionToHandler   0f ForwardEngineerDialogCommandToChildSlot40
10 DispatchUiCommandToHandler     11 ForwardCityDialogParamToChildSlot44
12 ForwardCityDialogParamToChildSlot48  13 CanHandleCityDialogActionFalse
14 GetCityDialogValueDword10      15 SetCityDialogValueDword10
16 GetCityDialogValueViaChildSlot58  17 CanStartCityProductionActionFalse
18 GetCityDialogZeroValue         19 HandleCityDialogNoOpA
1a HandleCityDialogNoOpB          1b HandleCityProductionNoOp
1c DispatchUiCommand19ToParent    1d DispatchCityProductionAction1A
1e DispatchCityProductionAction1B 1f ActivateCityProductionViewIfAllowed
20 FUN_0048a5e0                   21 sub_0048a710
22 IsCurrentActiveCityProductionView  23 DetachActiveCityProductionChildIfMatches
24 SetUiResourceOwner             25 FindCityProductionChildByWindowHandle
26 FUN_0048af80                   27 sub_0048c820
28 DispatchVfuncA0ToLinkedChildListSlot44  29 FUN_0048b1c0
2a FUN_0048b070                   2b sub_00427200
2c UpdateMapCursorFromSelectionContext  2d sub_0048c1c0
2e RefreshCityProductionViewStateFromContext  2f sub_00430bd0
30 FUN_0048b4b0  31 FUN_0048ab90  32 FUN_0048b690  33 FUN_0048c000
34 FUN_0048c050  35 FUN_0048c080  36 FUN_0048aaf0  37 FUN_0048ab70
38 FUN_0048abc0  39 FUN_0048b6d0  3a FUN_0048b1a0  3b FUN_0048b200
3c FUN_0048b250  3d sub_0048b3f0  3e FUN_0048b770  3f sub_00427220
40 sub_0048b7b0  41 FUN_0048b7e0  42 FUN_0048b810  43 FUN_0048b8d0
44 sub_00430bf0  45 FUN_0048b860  46 DispatchUiMouseMoveToChildren  47 sub_00430c10
48 FUN_0048c590  49 FUN_00427240  4a FUN_00427260  4b FUN_00427290
4c FUN_004272d0  4d FUN_0048ba80  4e FUN_0048ba40  4f ResetUiInputCaptureState
50 FUN_0048bb00  51 FUN_00427330  52 FUN_0048bb60  53 FUN_0048bbb0
54 FUN_0048bc30  55 FUN_0048bc60  56 sub_0048bb30  57 FUN_00429410
58 FUN_0048bce0  59 FUN_0048b2d0  5a FUN_0048c380  5b FUN_0048c6d0
5c FUN_0048abe0  5d sub_0048ae60  5e sub_0048c970  5f sub_0048c990
60 sub_0048c9e0  61 sub_0048ca00  62 sub_0048ca20  63 sub_0048ca40
64 sub_0048c750  65 FUN_0048c7a0  66 sub_0048c7d0  67 sub_0048bac0
```
ResolveControlByTag is slot **0x25** (offset 0x94) — note `TView.h` grep-order is +2 off
(its dtor/classname aren't declared in slot order).

## TControl-introduced slots 0x68–0x70
```
68 TrackMouse                       69 FUN_0048e980
6a AssertCityProductionGlobalStateInitialized  6b NoOpCityProductionDialogMethod
6c NoOpCityProductionDialogPictureHook  6d SetCityProductionDialogPictureRectAndMaybeRefresh
6e SetControlPictureEntryAndMaybeRefresh  6f LogUnhandledDialogMethodAndReturnFalse
70 SetControlStateFlagAndMaybeRefresh
```
TCluster introduces 0x71 (`0x491770`), 0x72 (`0x491790`).

## Cluster virtual slots 0x73–0x7b (TUberCluster abstract; per-leaf overrides)
```
slot  Uber          TProd        TTrade                      TIndus        TRail         TShip
0x73  0x5714e0      (inherit)    IsTradeSellControlAtMinimum (inherit)     (inherit)     (inherit)
0x74  NULL          SetWord8c    UpdateSell+Bar 0x5882f0     Orphan588c30  Orphan5899c0  RefreshMoveBar
0x75  NULL          SetWord8e    Query 0x587950 (0-arg!)     UpdFromDrag   UpdScaledDrag NULL
0x76  NULL          SetField90/94 IsTradeBidActionable       FUN_588f60    FUN_589d10    NULL
0x77  NULL          NULL         IsTradeOfferActionable      NULL          NULL          NULL
0x78  NULL          NULL         SetTradeBidSecondaryBitmap  NULL          NULL          NULL
0x79  NULL          NULL         SetTradeBidControlBitmap    NULL          NULL          NULL
0x7a  NULL          NULL         SetTradeOfferControlBitmap  NULL          NULL          NULL
0x7b  NULL          NULL         SetTradeOfferSecondaryBitmap NULL         NULL          NULL
0x7c-0x8b  NULL everywhere (unused reserved tail)
```

## CRITICAL CONSTRAINT — ABI-polymorphic slots
Slots 0x74–0x76 are dispatched with **different `__thiscall` arg-counts per caller/leaf**, so
they cannot be a single clean C++ virtual:
- 0x75: trade `Query` 0x587950 = **0 args** (tail-call `PUSH 'Sell';CALL [EAX+0x94];JMP
  [EDX+0x1e8]`, no own cleanup); move clusters = **2 args** (`RET 0x8`, e.g. 0x5899f0);
  `TCivToolbar` calls it = **1 arg** (`->NotifyControlSelectionChange(void*)`).
`__thiscall` callees clean their own args → one base signature can't serve 0/1/2-arg callers,
and the base slots are literal NULL (not `_purecall`) so the original wasn't plain C++ virtuals
here either. A full remodel must pick canonical per-slot signatures and update each diverging
callsite (e.g. TCivToolbar), accepting reduced match there (per "architecture over %").
The TTradeCluster-exclusive slots 0x77–0x7b ARE uniform (`char`/`void`, 0-arg) and model cleanly.

See [[cluster-vtable-ground-truth]] memory for the running plan.
