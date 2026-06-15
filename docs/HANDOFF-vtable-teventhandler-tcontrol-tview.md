# Handoff: TEventHandler / TControl / TView vtables → 100% + re-home TradeControl methods

Goal (from user): bring `just vtable TEventHandler`, `just vtable TControl`, `just vtable
TView` to 100%, AND physically put misplaced methods into the correct class/TU (the
fictitious `TradeControl::` names + TView-base bodies currently authored on TControl).

Plan file: `/home/agluszak/.claude/plans/bring-just-vtable-teventhandler-fancy-moore.md`
Skill to follow: `vtable-matching` (slot classification + fixes). Template commit:
`a98934a` (TSoundPlayer → 100%). Verify loop after every change:
`just sync-ownership` → `just regen-stubs` → `just build` → `just detect` →
`just vtable <Class>`; then `just gates` + `just format-check <files>` +
`just compare-canaries` (base edits touch the whole TView/TControl/Application family).

## DONE so far (uncommitted working tree, on `main`)

- **Phase A — scalar deleting destructors: COMPLETE.** `TEventHandler::vftable` is now
  **100%**. Fixed by renaming the three dtor rows in `config/symbols.csv` to the backtick
  form ``Class::`scalar deleting destructor'`` (was the non-pairing underscore form
  `'scalar_deleting_destructor'`): `0x48a130` (TEventHandler), `0x48a9a0` (TView),
  `0x48e590` (TControl). Added a `// SYNTHETIC: IMPERIALISM 0x0048a130` marker in
  `src/game/TEventHandler.cpp` (TView/TControl already had theirs). Lesson: the symbols.csv
  name must be exactly ``Class::`scalar deleting destructor'`` with comment col
  `undefined ScalarDeletingDestructor()` — copy the `0x5933b0` TSoundPlayer row format.

- **Phase B — ILT thunk un-imports: 4 of 5 DONE.** Each: removed the row from
  `config/symbols.csv`, deleted the hand-written body, removed any generic decl from
  `include/game/ui_widget_thunks.h`, repointed callsites to a qualified non-virtual call
  to the real target. Done:
  - `0x406ba9` → `TView::NoOpUiLifecycleHook` (slot 0xdc). Repointed 5 callers
    (TRailAmtBar, TTraderAmtBar, TIndustryAmtBar, TUberCluster, TShipAmtBar) to
    `reinterpret_cast<TView*>(this)->TView::NoOpUiLifecycleHook(arg)`. Deleted the
    `TView::thunk_NoOpUiLifecycleHook` method + its TView.h decl. **Slot 0xdc resolves.**
  - `0x408b07` → `TControl::HandleCursorHoverSelectionByChildHitTestAndFallback`
    (slot 0xd4). Repointed the two TControl.cpp wrapper callsites + one
    TDiplomacyMapView.cpp callsite (removed the fake `__fastcall(ptr,int/*edx*/,…)` casts).
    **Slot 0xd4 resolves.**
  - `0x406604` → `TView::RefreshControl` (slot 0xe4). Repointed TWorldView.cpp callsite.
  - `0x401e2e` → `TControl::AssertCityProductionGlobalStateInitialized` (slot 0x1a8).
    Deleted the fake body in `src/game/thunks.cpp`; the real body already exists as
    `TControl::AssertCityProductionGlobalStateInitialized` (TControl.cpp:33). No manual
    callers. **(Rebuild + recheck slot 0x1a8 — should resolve.)**

- Builds clean and `just detect` OK after each step. **Not yet committed. Not yet
  re-run `just gates` / `just format-check` / `just compare-canaries`** — do this before
  committing.

## REMAINING WORK

### B5 — last thunk `0x404566` (HIGHER RISK, needs Ghidra)
Blocks **TControl slot 0x3c**. Orig slot = thunk `0x404566` → `0x48e710 =
TControl::HandleEvent(int commandId, TEventHandler*, TEvent*)` (TControl.cpp:233, a real
slot-0x0f override). Callsites use a register-passthrough tail-call pattern, so they do
NOT cleanly map to `HandleEvent(args)`:
- `src/game/THQButton.cpp:57,62` and `src/game/TStatusButton.cpp:71` call
  `thunk_HandleCityDialogToggleCommandOrForward();` **with no args** (inside
  `WrapperFor_HandleCityDialogToggleCommandOrForward_At0058b7f0(THQButton*, int edx,
  int commandId)` etc. — the original tail-jumps into HandleEvent with this/commandId
  still in registers/stack).
- `src/game/TDiplomacyMapView.cpp:727` casts to `__stdcall(int,int,void*)` and calls
  `(commandId, panelEvent, extra)`.
Generic decl still in `include/game/ui_widget_thunks.h`
(`undefined4 thunk_HandleCityDialogToggleCommandOrForward(void);`).
**Approach:** disassemble `0x58b7f0` / `0x404566` (`just ghidra-listing 0x58b7f0`) to
recover the real HandleEvent stack args, then repoint each callsite to
`reinterpret_cast<TControl*>(this_or_button)->TControl::HandleEvent(commandId,
sourceHandler, event)` with the correct args, then remove the symbols.csv row + generic
decl. Validate THQButton/TStatusButton/TDiplomacyMapView scores don't regress.

### C — re-home TView-base bodies wrongly authored on TControl, + claim ret-stub slots
I dumped TView's vtable slot orig-addr vs TControl's vtable slot orig-addr side by side.
**Rule:** if the orig addr is the SAME in both vtables → it is a **TView base body**
currently mis-authored as a `TControl` method → move the body + `// FUNCTION:` marker to
`src/game/TView.cpp`, rename `TControl::X`→`TView::X`, and DELETE the `override` decl in
`include/game/TControl.h` (TControl then inherits). If the addrs DIFFER → genuine TControl
override; instead claim TView's base addr (a ret-stub) onto the TView placeholder method.

TView.h already declares the right placeholder virtual for each slot (slot numbers below).
Per-slot table (TViewOrig = TControlOrig unless noted):

| TView slot off | TView slot# | orig addr | current owner / name | action |
|---|---|---|---|---|
| 0xb0 | 0x2c HandleCursorHoverFallback | 0x48c250 (same) | unowned stub `UpdateMapCursorFromSelectionContext` | promote 0x48c250 onto TView::HandleCursorHoverFallback (write honest body in TView.cpp) |
| 0xb8 | 0x2e vmethod_0043 | 0x48c1e0 (same) | body in TView.cpp (`RefreshCityProductionViewStateFromContext`) but slot unclaimed | give TView slot-0x2e method the 0x48c1e0 marker |
| 0xc0 | 0x30 vmethod_0044 | 0x48b4b0 (same) | TControl.cpp `InvalidateOffsetRegionUsingChildClipRect` | re-home to TView slot 0x30, remove TControl decl |
| 0xd4 | 0x35 HandleCursorHoverSelectionByChildHitTestAndFallback | 0x48c080 (same) | TControl.cpp override | re-home to TView::, **delete TControl.h override line 36** |
| 0x10c | 0x43 PaintVisibleChildrenIntersectingClipRect | 0x48b8d0 (same) | TControl.cpp override | re-home to TView::, delete TControl override |
| 0x110 | 0x44 ApplyRectSlot110 | 0x430bf0 (same, OrphanRetStub, owned by noop_slots.cpp) | claim 0x430bf0 onto TView::ApplyRectSlot110 |
| 0x118 | 0x46 DispatchUiMouseMoveToChildren | 0x48c450 (same) | TControl.cpp override | re-home to TView::, delete TControl override |
| 0x11c | 0x47 BeginMouseCaptureAndStartRepeatTimer | **TView 0x430c10 ≠ TControl 0x48e640** | GENUINE TControl override (0x48e640) | claim TView base `0x430c10` (OrphanRetStub, noop_slots.cpp) onto TView::BeginMouseCaptureAndStartRepeatTimer; **KEEP** TControl override |
| 0x120 | 0x48 DispatchUiMouseEventToChildrenOrSelf_Impl | 0x48c590 (same) | TControl.cpp override | re-home to TView::, delete TControl override |
| 0x124 | 0x49 vmethod_0071 | **TView 0x427240 ≠ TControl 0x48e980** | GENUINE TControl override (0x48e980, pairs) | claim TView base `0x427240` (currently `TradeControl::NoOpControlCallback_Impl`) onto TView::vmethod_0071; KEEP TControl override |
| 0x144 | 0x51 UpdateAfterBitmapChange | 0x427330 (same) | TControl.cpp `CtrlSlot81_SubtractControlPosFromPoint_Impl` | re-home to TView slot 0x51 |
| 0x170 | 0x5c vmethod_0092 | 0x48abe0 (same) | `RunNationInfoModalAndReturnNonCancel_Impl` | promote 0x48abe0 onto TView::vmethod_0092 |

Notes:
- When re-homing an override body, also fix the body's signature to TView's declared slot
  signature, and move it to `src/game/TView.cpp` in ascending-address order (decomplint).
- The BeginMouseCapture (0x48e640) override body stays on TControl; only the TView base
  ret-stub slot needs claiming.
- After C, re-dump both vtables; the SAME-addr slots should pair in BOTH TView and
  TControl at once (TControl inherits the re-homed TView body).

### C (TControl-only leftover mismatches)
- **0xbc** orig `0x429450` (`TradeControl::GetCityProductionControllerField60`): promote
  onto the correct TControl slot-0x2f method (check TView slot 0x2f decl
  `QuerySelectedIndexSlotBC`; TControl may override). Compare TView vs TControl 0xbc to
  classify same as above.
- **0xc0** TControl shows extra greens (`ReturnZeroStatus 0x430bd0`, vmethod_0043/0044) —
  resolves once 0xb8/0xc0 TView re-homing is done; recheck.
- **0x16c** orig `0x48e940` (`TControl::CtrlSlot91_PtInRectWithBoundsFromSlot128_Impl`):
  genuine TControl slot; ensure the declaring method owns 0x48e940 (promote/stub-claim).

### D — kill the fictitious `TradeControl::` names (user's explicit ask)
After the above, rename the remaining `TradeControl::` symbol rows to their real owning
class and put durable renames in `config/function_name_overrides.csv` (symbols.csv is
regenerated by `just sync-ghidra`). Current remaining rows (`grep TradeControl
config/symbols.csv`):
- **TEventHandler base slots** → rename `TradeControl::`→`TEventHandler::`:
  `0x485f70`, `0x485f90`, `0x48a240`, `0x48a2c0`, `0x48a480`, `0x48a500`, `0x48a530`,
  `0x48a550`, `0x415d50` (bodies already in TEventHandler.cpp — leave physically).
- **TControl methods** → rename `TradeControl::`→`TControl::`:
  `0x429450`, `0x429470`, `0x4294a0`, `0x48e9e0`, `0x427240` (after it becomes the TView
  base body via slot 0x49, rename to `TView::` instead). Move any body still in the wrong
  .cpp into the owning class file; update `config/function_ownership.csv`.
Goal: `grep TradeControl config/symbols.csv` → empty; no fictitious class in any
`just vtable` listing.

### Verify / finish
- `just vtable TEventHandler|TControl|TView` each = `100% match`.
- `just gates` passes; `just format-check` on every touched file.
- `just compare-canaries` unchanged.
- Append a worklog entry to `docs/worklog.md` (commands + score deltas), update memory
  notes `teventhandler-real-base`, `tview-vtable-slot-scramble`,
  `ui-vtable-hierarchy-ground-truth` if slot maps change.
- Commit directly on `main` (repo convention), no feature branch; end message with the
  `Co-Authored-By: Claude Opus 4.8` trailer.

## Working-tree files already modified (for awareness)
`config/symbols.csv`, `src/game/TEventHandler.cpp`, `include/game/TView.h`,
`src/game/TView.cpp`, `src/game/TControl.cpp`, `src/game/TDiplomacyMapView.cpp`,
`src/game/TWorldView.cpp`, `src/game/thunks.cpp`, `include/game/ui_widget_thunks.h`,
`src/game/T{Rail,Trader,Industry,Ship}AmtBar.cpp`, `src/game/TUberCluster.cpp`,
plus regenerated `config/function_ownership.csv` and `src/autogen/stubs/*`.
