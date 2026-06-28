---
name: TMacViewMgr de-hack
overview: Remove the MacViewInvoke/MacViewUiInvoke wrapper structs and reinterpret_cast hacks in TMacViewMgr by calling real functions directly, porting the still-stubbed QuickDraw/region/UI free functions to real signatures, recovering the dialog/control classes behind the offset casts, and replacing placeholder names/types with semantic ones — all verified phase-by-phase so reccmp scores never regress.
todos:
  - id: p0-baseline
    content: "Phase 0: just build + just stats + just compare on TMacViewMgr.cpp to capture baseline scores"
    status: completed
  - id: p1-forwarders
    content: "Phase 1: delete MacViewInvoke pure-forwarder wrappers + MacViewUiInvoke::FormatStringWithVarArgsToSharedRef; call real functions directly; fix type seams; build+compare"
    status: completed
  - id: p2-port-free
    content: "Phase 2: verify convention/signature in Ghidra and port the stubbed QuickDraw/region/UI free functions (SetQuickDrawStrokeColor, FillRect..., region combine/reset, RebuildSprite..., PumpUiMessages, etc.) to real owned implementations; remove stubs; call cast-free; never restore CallCallbackRepeatedly or callback_helpers"
    status: in_progress
  - id: p3-uiinvoke
    content: "Phase 3: resolve and port AssignStringSharedRefAndReturnThis / RunEnableAndProcessFlag... / BuildUiTextStyleDescriptor targets; delete MacViewUiInvoke namespace"
    status: completed
  - id: p4-classes
    content: "Phase 4: recover TurnEventDialogView, GoldDialogControl, CityOrderSource real classes; promote offset reinterpret_cast field pokes into typed members"
    status: pending
  - id: p5-names
    content: "Phase 5: rename placeholder methods/types via symbols.csv + gen-class; convert file-local __fastcall(self) helpers into real TMacViewMgr methods"
    status: in_progress
  - id: p6-verify
    content: "Phase 6: just gates + just build + just stats vs baseline + format-check on touched paths; report deltas"
    status: pending
isProject: false
---

# TMacViewMgr de-hack and real-method port

Target file: [src/game/TMacViewMgr.cpp](src/game/TMacViewMgr.cpp), header [include/game/TMacViewMgr.h](include/game/TMacViewMgr.h).

The work is split into verification-gated phases. After every phase: `just build`, `just compare --file src/game/TMacViewMgr.cpp` (and any other touched class), confirm no score regression vs the Phase 0 baseline, then continue. Per AGENTS.md gate-chasing guardrail, never revert promoted real C++ to green a gate — fix forward or stop and report.

## Phase 0 — Baseline
- `just build` then `just stats` to capture starting aligned/similarity numbers (compare against `config/reccmp_progress_baseline.json`).
- `just compare --file src/game/TMacViewMgr.cpp` to record per-function scores before edits.

## Phase 1 — Delete pure-forwarder wrappers (score-neutral)
These `MacViewInvoke` members only forward to functions that already have real signatures in headers; delete them and call the real function directly:
- `GetActiveQuickDrawSurfaceContextAndFlags`, `SetActiveQuickDrawSurfaceContext`, `GetSurfaceObjectAtContextOffset24`, `GetSurfaceHeaderFromSurfaceObject`, `ReturnConstantTrueQuickDrawFlag`, `NoOpQuickDrawLifecycleHookB`, `LoadBitmapResourceSurfaceAndRestoreQuickDrawContext`, `WrapperFor_AllocateWithFallbackHandler_At004a1130`, `WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c40` — all declared in [include/game/bitmap_descriptor_helpers.h](include/game/bitmap_descriptor_helpers.h).
- `DispatchTaggedGameStateEvent1F20` (real signature already exists; just call directly).
- `MacViewUiInvoke::FormatStringWithVarArgsToSharedRef` simply calls `dest->Format(...)` — inline it.
- Fix the small type seams these wrappers were hiding (e.g. `savedFlags` should be `undefined4` to match `GetActiveQuickDrawSurfaceContextAndFlags(undefined4*, undefined4*)`; context args are `TQuickDrawSurfaceContext*`).

## Phase 2 — Port the stubbed QuickDraw/region/UI free functions
Each of these is still a `undefined4 Foo(void)` stub (returns 0) under `src/autogen/stubs/`, which is the only reason the `reinterpret_cast` wrappers exist. For each: read Ghidra (`just ghidra-listing 0xADDR`, decompile) to confirm real calling convention + signature + owner, then either (a) for a genuine free `__cdecl`/`__stdcall` function: declare a real signature in an appropriate header (extend [include/game/quickdraw_globals.h](include/game/quickdraw_globals.h) or a new region-helpers header), own it in a `src/game/*.cpp`, port a faithful body, remove the stub via `config/function_ownership.csv` → `just sync-ownership` → `just regen-stubs`; or (b) if it is really `__thiscall`, attach it as a real method on its owning recovered class. Then call cast-free from TMacViewMgr.
- `SetQuickDrawStrokeColor` 0x495070, `FillRectWithQuickDrawBrushAndContextOffset` 0x498980 (region/QuickDraw, operate on `g_nQuickDrawStroke*` globals — likely free).
- `ResetClipRegionAndReadBoundingRect` 0x497810, `CombineTwoRegionsIntoDestinationAndUpdateBox` 0x4977a0, `CombineOptionalSourceRegionIntoDestinationAndUpdateBox` 0x497bb0, `RebuildSpriteNonTransparentPolygonRegion` 0x497ef0, `WrapperFor_LookupHandleMapEntryWithCreate_At00497f90` 0x497f90, `RebuildMapTileNeighborHighlightPolygonsForAllTiles_Impl` 0x497f60, `NoOpRuntimeCallback_00497c00` 0x497c00 — region engine; type the `int region` params as `ClipStateRegionWrapper*` (see [include/game/ClipStateRegion.h](include/game/ClipStateRegion.h)).
- `BuildBitmapMaskOpcodeBufferFromResourceRows` 0x4d5090, `BuildHexNeighborHighlightPolygonForTile` 0x508f30, `RebuildSurfaceRowsWithTemporaryRowBuffer` 0x47c980, `CallObjectOffset24Vslot54IfPresent` 0x4a0f80.
- `PumpUiMessagesAndBackgroundTasks` 0x4868c0 (symbols.csv already has `int __stdcall PumpUiMessagesAndBackgroundTasks(int)` — declare and call directly).
- `CallCallbackRepeatedly` / `callback_helpers` must stay gone. If an EH/vector iterator helper appears in Ghidra, recover the actual element/member type and express it as C++ member arrays, constructors, destructors, or compiler-emitted deleting destructors instead of porting or wrapping the helper.
- Also fold `IsPointInsideHitRegion` / `QueryPointInsideHitRegion` and `scanBracketExpressions` into real declared calls.

Progress:
- 2026-06-28: Fixed `scanBracketExpressions` 0x57fef0 from the stale
  `__stdcall` metadata to the listing-proven cdecl variadic signature
  (`RET`, caller cleanup; replacement strings are varargs). Added
  `include/game/localization_text_helpers.h`, forced this prototype through
  `tools/stubgen.py`, regenerated `src/autogen/stubs/stubs_part018.cpp`, and
  replaced the local `reinterpret_cast` call sites in `TMacViewMgr.cpp`,
  `TCivMgr.cpp`, `TViewMgr.cpp`, and `startup_helpers.cpp` with direct typed
  calls. Verification: `just build` passed, `just gates` passed, and
  `just compare 0x0057fef0 0x0050bea0 0x004d3a60 ...` paired the updated
  functions (`scanBracketExpressions` currently 6.19%; TMacViewMgr city panel
  function 18.05%; TCivMgr engineer action 22.39%). `just tooling-check` still
  fails on pre-existing tooling manifest entries for
  `tools.workflow.mfc_runtime_macros` and `tools.workflow.pe_resources`;
  `uv run python -m py_compile tools/stubgen.py` passed.
- 2026-06-28: Removed the fake cdecl
  `InvokeBuildBitmapMaskOpcodeBufferFromResourceRows` wrapper. Ghidra listing
  for 0x4d5090 shows `ECX` is the receiver and the TMacViewMgr caller walks
  `StrategicMapCallbackRecord` arrays by the real 0x30 element size
  (`callback6bc`, `callbackB3c`, `callbackC5c`). Added
  `StrategicMapCallbackRecord::BuildBitmapMaskOpcodeBufferFromResourceRows`
  with a real thiscall signature, owned 0x4d5090 in manual source, regenerated
  stubs, and replaced TMacViewMgr callsites with direct array-element method
  calls. Verification: `just sync-ownership`, `just regen-stubs`, `just build`,
  and `just gates` passed. Focused compare pairs the new method at 8.17% and
  `TMacViewMgr::RenderOffscreenBitmapGridStripAndRestoreContext` at 15.90%;
  keep improving the encoder body forward, do not restore the wrapper.
- 2026-06-28: Removed generated callable stubs for the compiler helper
  `CallCallbackRepeatedly` 0x5e8c50 and cleanup thunk 0x5e8cc8 by marking them
  non-autogen in `config/function_ownership.csv`; `src/autogen/stubs` no longer
  provides bodies that future source can call. Verification: `just regen-stubs`
  and `just build` passed.
- 2026-06-28: Promoted the adjacent opcode-buffer operations used by
  `StrategicMapCallbackRecord::BuildBitmapMaskOpcodeBufferFromResourceRows`
  into real record methods instead of file-local helpers:
  `EnsureOpcodeBufferByteAtIndex` 0x4d4e40, `AppendOpcodeByte` 0x4d5580,
  `AppendOpcodeBytePair` 0x4d5610, and `FinalizeOpcodeBufferAlignment`
  0x4d5720. Updated `symbols.csv`, synced ownership, regenerated stubs, and
  removed the four old autogen stubs. Verification: `just sync-ownership`,
  `just regen-stubs`, `just build`, `just gates`, and
  `just format-check include/game/StrategicMapCallbackRecord.h` passed. Focused
  compare pairs all six affected functions: 0x4d4e40 18.18%, 0x4d5090 10.43%,
  0x4d5580 14.29%, 0x4d5610 16.33%, 0x4d5720 11.83%, 0x50a9f0 15.90%.

## Phase 3 — MacViewUiInvoke string/style helpers
Resolve the targets behind `AssignStringSharedRefAndReturnThis`, `RunEnableAndProcessFlagWithScopedSharedStringCleanup`, and `BuildUiTextStyleDescriptor` (text/CString/style helpers used by the city-production panel). Confirm owner/convention in Ghidra, port to real signatures (free functions or `TStaticText`/`TControl` methods as evidence dictates), and delete the `MacViewUiInvoke` namespace.

Progress:
- 2026-06-28: Deleted the `MacViewUiInvoke` namespace from
  `TMacViewMgr.cpp`. Ghidra evidence showed the old
  `AssignStringSharedRefAndReturnThis` + `RunEnableAndProcessFlag...` pair was
  not semantic UI logic: the original call constructs a by-value `CString`
  temporary, enters the EH cleanup thunk at 0x5c49d0 / 0x5c4a40, and the thunk
  calls `TView::EnableAndProcessFlag` through ILT 0x408c6a -> 0x48c220 before
  destroying the temporary. Modeled that as
  `TView::EnableAndProcessFlag(CString sharedString)` and direct
  `panel/textEntry->EnableAndProcessFlag(...)` calls. `AssignStringSharedRefAndReturnThis`
  0x49eb00 is just a thiscall-shaped `CString` copy-construction helper
  (`ECX` receiver, one stack `CString*` source), not a TMacViewMgr free cdecl.
- 2026-06-28: Resolved `thunk_BuildUiTextStyleDescriptor` 0x406afa as an ILT
  jump to 0x5c3e80. The target is stack-parameter code with plain `RET`, so
  `TMacViewMgr` now calls `BuildUiTextStyleDescriptor(void*, int, int, int)`
  directly; the prototype is forced through `tools/stubgen.py` and
  `src/autogen/stubs/stubs_part020.cpp`. The target still needs a real owned
  body later, but the wrapper frame is gone.
- Verification: `just regen-stubs`, `just build`, `just vtable TMacViewMgr`,
  and `just gates` passed. Focused compare
  `just compare 0x0050bea0 0x0048c220 0x005c3e80` pairs all three but remains
  below 100% (`TMacViewMgr::RefreshCityProductionDetailPanelAndArrowWidgets`
  16.84%, `TView::EnableAndProcessFlag` 33.33%,
  `BuildUiTextStyleDescriptor` 4.35%). The TMacViewMgr score is lower than the
  earlier wrapper-based 18.05% because the recompiled code now emits the real
  `CString` temporary + direct `TView` method call instead of reproducing the
  compiler cleanup thunk call; do not restore the wrapper to chase that score.

## Phase 4 — Recover the dialog/control classes behind offset casts
Replace the ad-hoc local structs and offset `reinterpret_cast` pokes with real recovered types (follow the class-recovery skill; verify vtable slots in Ghidra before assigning):
- `TurnEventDialogView` (returned by `g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext`) — promote to a real `TView`-derived class; type the `+0x14` completion flag, `+0x3c` mode field as named members.
- `GoldDialogControl` (tag `0x444c4f47`) — real `TControl`-derived class with its slot methods (`gold71`, `SetGoldControlStateByResource`, `InvokeSlot1CC/1D0*`).
- `CityOrderSource` (`QuerySellModeFlag1D8`/`QuerySellQuantity1D4`) — confirm real owner; type `OrphanCallChain_C4_I35_0050bbc0`'s `param_1` accordingly.
- Promote remaining `*(short*)(panel + 0x88/0x92/0x94/0x96/0x98)`, `field04 + 0xac`, control `+0x1c` command-tag pokes (`SetPanelShortField`, `SetControlCommandTagAt1c`) into typed fields on the right `TControl`/`TView` subclass instead of cast helpers (Hard Rule 8).

Progress:
- 2026-06-28: Removed `SetControlCommandTagAt1c`; its offset is the inherited
  `TEventHandler::controlTag` at 0x1c, so the city-production panel controls now
  assign `controlTag` directly. Also replaced dialog `+0x14` / `+0x3c` casts
  with inherited `field14` / `field3c` accesses. Verification: `just build`
  passed after the cleanup.

## Phase 5 — Fix placeholder names and types
Drive renames through `config/symbols.csv` (column 2 `TMacViewMgr::<Name>` + proto) then `just gen-class TMacViewMgr` → `just sync-ownership` → `just regen-stubs` (do NOT hand-edit the generated DECLS block in the header):
- Rename `OrphanCallChain_C4_I35_0050bbc0`, `OrphanCallChain_C10_I80_0050d470`, `OrphanCallChain_C9_I49_0050d5b0`, `OrphanCallChain_C1_I10_0050d920`, `OrphanLeaf_NoCall_Ins06_0050d8d0/_0050d8f0`, `VTableSlot26`, and the `WrapperFor_*` methods to semantic names based on observed behavior.
- Replace `undefined`/`undefined4`/`int*` return and param types with real types (e.g. the `param_1` in dialog dispatchers → `TurnEventDialogView*`/`GoldDialogControl*`, sprite-surface pointers → typed surface structs).
- Convert the file-local `__fastcall ...(TMacViewMgr* self)` helpers (`InitializeStrategicMapViewSystem` 0x509f20, `BuildStrategicMapGaugeAtlasFrom1422And1423` 0x50a470, `RefreshCityCapabilityUiHandlesForActiveNation` 0x50a6a0, `BuildStrategicMapTileOverlayStripSurfaces800To807` 0x50a820, `ReloadBitmap244AndRefreshUiCaches` 0x50b5b0) into real non-virtual `TMacViewMgr` methods (they take `this` via fastcall ecx) — update ownership and call `this->Method()`. Do not restore `WrapperFor_InvokeCallbackNTimesWithSehGuard_At00509e60`; its old job belongs to real callback record arrays and compiler-emitted construction/destruction.

Progress:
- 2026-06-28: Converted `InitializeStrategicMapViewSystem` 0x509f20,
  `BuildStrategicMapGaugeAtlasFrom1422And1423` 0x50a470,
  `RefreshCityCapabilityUiHandlesForActiveNation` 0x50a6a0,
  `BuildStrategicMapTileOverlayStripSurfaces800To807` 0x50a820, and
  `ReloadBitmap244AndRefreshUiCaches` 0x50b5b0 from file-local/free
  fastcall helpers into real non-virtual `TMacViewMgr` methods. Updated
  `config/symbols.csv`, removed the `startup_helpers.cpp` free-function
  forward declaration, and changed startup to call
  `mapView->InitializeStrategicMapViewSystem()`.
- Verification for that batch: `just build` passed; `just vtable TMacViewMgr`
  passed 100%; `just compare 0x00509f20 0x0050a470 0x0050a6a0 0x0050a820
  0x0050b5b0` paired all five methods under `TMacViewMgr::...` with current
  scores 97.96%, 25.00%, 54.44%, 37.91%, and 78.69%. `just format-check
  src/game/startup_helpers.cpp` passed. Full `TMacViewMgr.cpp`/header
  format-check still fails on pre-existing formatting across the file.

## Phase 6 — Final verification
- `just gates` (vtable, antipattern, marker, decomplint, etc.) — must pass without reverting promoted shape.
- `just build` clean.
- `just stats` vs baseline; `just compare --file src/game/TMacViewMgr.cpp` to confirm no per-function regression (architecture-correct partial matches are acceptable over fake 100%).
- `just format-check` on every touched path.
- Report deltas; only `just stats-commit` if the user asks to commit.

## Risks / notes
- Phases 2–4 are the bulk: each stubbed function and each recovered class is its own mini decomp-loop and may span other subsystems (QuickDraw region engine, UI view manager). Some "free" functions may turn out to be `__thiscall` methods — verify convention in Ghidra first and recover the owning class rather than faking a convention.
- Removing a stub requires transferring ownership in `config/function_ownership.csv`; mishandling causes duplicate-`// FUNCTION` or link errors — fix forward via sync-ownership/regen-stubs, never by re-stubbing a promoted callsite.
- `symbols.csv` may be regenerated by `just sync-ghidra`; confirm the rename path persists (use the `name_overrides` mechanism in `just regen-stubs` if needed) before relying on it.
