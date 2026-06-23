---
name: tviewmgr-body-porting
description: TViewMgr.cpp method-body porting — receiver map, what's ported, and the remaining hard bodies
metadata:
  type: project
---

Porting TViewMgr.cpp bodies (vtable already 100%). Receiver/dispatch map recovered from Ghidra:

- **Global `[0x6a2158]`** = app/document root pointer; its `+0x04` field is the active main `TView*`
  (the dispatch root). Modeled in TViewMgr.cpp as file-local `struct MainViewHostContext { void* field0; TView* mainView; }`.
- **Main-view child lookup** = `mainView->ResolveControlByTag(fourcc)` (TView slot 0x25, byte 0x94) → `TControl*`.
- **Toolbar nation-indicator** = `TToolBarCluster::UpdateControlTagTreaTextFromNationAndMapContext(int nationId)`
  (slot 0x74, byte 0x1d0, body 0x585ba0). Base stub at 0x586ff0 is `RET 4` (no-op, 1 arg). I fixed its
  signature from `undefined ()` to `void (int nationId)` (verified: 0x585ba0 reads arg [ESP+0x2c]).
- `g_pUiRuntimeContext->GetActiveNationId()` is the `[0x6a20f8]`-based `short` getter (ILT 0x403b16→0x581260).

DONE this session (both real virtual calls, shape-pass, not chasing 100%):
- **0x5d6b70 RefreshMainViewNationIndicatorForCurrentTurnEvent** — reccmp **59.65%**. GetActiveNationId
  receiver is `g_pLocalizationTable` (0x6a20f8) NOT g_pUiRuntimeContext (0x6a21bc) — call via
  `reinterpret_cast<UiRuntimeContext*>(g_pLocalizationTable)->GetActiveNationId()`; inline the arg into the
  virtual call so the compiler loads the control vtable before the call.
- **0x5d69b0 ComputeTurnEventDialogPlacementByCode** — reccmp **28.57%** (low only because the original used
  FPO/no-frame-pointer while our global match flag is `/Oy-`; that's a per-fn pragma we're told to skip). Real
  `mainView->QueryBounds`/`dialogView->QueryBounds` + Win32 `GetClientRect`. Signature fixed: it's thiscall
  RET 8 = `(TView* dialogView, POINT* outPlacement)`; centers the dialog in a per-event design rect
  (0x200x1c0 margin 0x16 for code 0x3b8/0x7dd; 0x276x1c0 for the "big" code set; else 0x276x1d1 margin 0x1e).

- **0x5d57b0 HandleTurnEventVtableSlot40RefreshGoldDialog** — reccmp **55.77%** (every vtable slot dispatches
  to the correct method; residual is register allocation only). Modeled the runtime-resolved dialog node and
  its 'GOLD' child as real dispatch-interface classes: `struct TurnEventDialogNode : public TView` (own slots
  0x68 ShowTurnEventDialog(int), 0x6b RefreshTurnEventDialog(), 0x6e QueryTurnEventContentObject()→ptr; lower
  slots ResolveControlByTag/CaptureLayoutF0/CallVoidSlotA0/Free inherited) and
  `struct GoldDialogControl : public TControl` (own slot 0x72 SetGoldControlStateByResource(int,int)).
  IMPORTANT pattern: these interface structs have NO VTABLE annotation and are never constructed → MSVC emits
  no vtable, virtual calls dispatch through the runtime object. This is the clean way to "use real method
  calls" on a runtime-polymorphic receiver whose concrete class can't be statically pinned. node comes from
  `TAssetMgr* @ [0x6a2148] ->ResolveTurnEventDialogNodeByMessageContext(0x7e5)` (read the global via address
  constant since g_pUiViewManager has no recomp definition).

Signature promotions made: TToolBarCluster slot 0x74 `(int nationId)`; TViewMgr slot 0x11 `(TView*, POINT*)`;
TAssetMgr slot 0x0a `ResolveTurnEventDialogNodeByMessageContext(int)→TView*`.

REMAINING TViewMgr TODO bodies (3 left; SEH/CString-heavy):
- 0x5d6480 BuildAndShowTurnOverlayByMode — big CString switch + g_pLocalizationTable vtable + SEH; Ghidra labels `this` as TToolBarCluster (suspicious).
- 0x5dcaa0 HandleTurnEventVtableSlot2CInitializeHotKeyDialog — CDialog + SEH + raw vtable.
- 0x5d5a70 RunControlStringProviderAndDispatchLocalizedMessage — MISSING from cpp; SEH + vararg-style stack-passing to DispatchLocalizedUiMessageWithTemplateA13A0; real call = `this->ClassifyTurnStateForOverlayMode()`.
- 0x5d4c60 CreateTViewMgrInstance — operator-new factory, BANNED to port (leave as stub). See [[banned-operator-new-cdecl-factory]].

The no-new-raw-vtable gate (Hard Rule 13) blocks the shortcut these bodies took in autogen, so each needs
its receiver subclass modeled with real virtuals. See [[ui-vtable-hierarchy-ground-truth]], [[model-real-classes-not-callconv-casts]].
