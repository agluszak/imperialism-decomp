# Worklog

## 2026-03-03

### Tooling surface hardening + prune

1. Added tooling manifest: `config/tooling_surface.csv`.
2. Added validator: `tools/workflow/check_tooling_surface.py`.
3. Added command: `just tooling-check`.
4. Pruned unused scripts not in active workflow surface:
   1. `tools/forensics/check_rich_header.py`
   2. `tools/reccmp/compare_toolchains.py`
   3. `tools/reccmp/flag_sweep.py`
   4. `tools/reccmp/function_shape_stats.py`
   5. `tools/workflow/annotate_orig_callconv.py`
   6. `tools/workflow/decomp_loop.py`
   7. `tools/workflow/split_classes_in_file.py`
5. Trimmed docs to current operational state:
   1. `README.md`
   2. `docs/control_plane.md`
   3. `docs/worklog.md`
   4. `tools/reccmp/README.md`
   5. `docs/toolchain.md`

### Notes

1. `tools/ghidra/SyncExports_Ghidra.py` remains required (runtime dependency of `tools.ghidra.sync_exports`).
2. `tools/reccmp/core_impact_ranking.py` remains required (invoked by `tools.reccmp.session_loop`).

### Validation pass after prune

1. `just tooling-check`: pass.
2. `just build`: pass.
3. `just detect`: pass.
4. `just stats`: pass, unchanged baseline:
   1. aligned functions: `92`
   2. average similarity: `2.88%`
5. `just compare-canaries`: pass (`below_floor=0`).

### TGreatPower similarity pass (manual shape/data edits)

1. Edited `src/game/TGreatPower.cpp` in four target bodies:
   1. `0x004DF010` `ApplyAcceptedDiplomacyProposalCode`
   2. `0x004DE860` `ApplyJoinEmpireMode0GlobalDiplomacyReset`
   3. `0x00541080` `TryDispatchNationActionViaUiThenTurnEvent`
   4. `0x005410F0` `ProcessPendingDiplomacyThenDispatchTurnEvent29A`
2. Added `SharedRefTripleScope` RAII helper to preserve 3-ref init/release envelope shape in `0x004DF010`.
3. Rebuilt and re-detected after each iteration:
   1. `just build`
   2. `just detect`
   3. `just compare 0x004df010`
   4. `just compare 0x004de860`
   5. `just compare 0x00541080`
   6. `just compare 0x005410f0`
4. Result deltas observed in this pass:
   1. `0x004DF010`: `12.27% -> 16.74%` (improved)
   2. `0x004DE860`: `26.83% -> 26.74%` (small regression from null-check removal pass)
   3. `0x00541080`: now `19.51%` after dispatch-gate shape alignment
   4. `0x005410F0`: now `38.46%` after pending-bit clear loop alignment
   5. `0x004EA470`: verified `100%` (already matched)
5. Ran `just session-loop 12 120 1` once for ranking; it auto-mutated `reccmp-project.yml` ignore lists. Restored `reccmp-project.yml` back to `HEAD` content immediately.

### TGreatPower ctor/dtor semantic wrapper experiment

1. Goal: introduce explicit C++ constructor/destructor semantics without changing the known reccmp-mapped init/release addresses.
2. Added semantic wrappers in class API:
   1. `TGreatPower(int arg1, int arg2)` delegates to init path (`0x004D8CC0` body).
   2. `~TGreatPower()` uses non-deleting cleanup body.
3. Kept address-mapped functions as the canonical implementation points:
   1. `0x004D8CC0` `InitializeNationStateRuntimeSubsystems`
   2. `0x004D9160` `ReleaseOwnedGreatPowerObjectsAndDeleteSelf`
4. To avoid delete recursion, factored shared cleanup statements into a macro body reused by:
   1. `~TGreatPower()` (non-deleting cleanup)
   2. `ReleaseOwnedGreatPowerObjectsAndDeleteSelf()` (cleanup + slot01 delete)
5. Validation:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004d8cc0` (`31.98%`)
   5. `just compare 0x004d9160` (`35.51%`)
   6. `just stats` unchanged: aligned `92`, average similarity `2.92%`.

### TGreatPower real-body expansion pass (event/diplomacy paths)

1. Reworked low-fidelity placeholders into fuller GHIDRA-shaped code in `src/game/TGreatPower.cpp`:
   1. `0x004DEFD0` `QueueDiplomacyProposalCodeForTargetNation` now uses a packed short-pair record.
   2. `0x00540AC0` `QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16` now builds explicit packet payload fields before dispatch.
   3. `0x005410F0` `ProcessPendingDiplomacyThenDispatchTurnEvent29A` now uses the major-nation pointer walk (`0x6A4370..0x6A438C`) and thunk queue processing path.
   4. `0x005416B0` `ApplyClientGreatPowerCommand69AndEmitTurnEvent1E` replaced one-line payload queue with full event-packet build/emit flow.
   5. `0x0055C970` `QueueInterNationEventIntoNationBucket` now routes through localization gate flag `+0x7A` and per-event queue slot writes.
   6. `0x0055CBD0` `QueueInterNationEventType0FWithBitmaskMerge` now scans existing queue entries and merges mask by nation bit when possible.
2. Added small typed helpers:
   1. `LocalizationRuntime_ReadGateFlag7A`
   2. `GreatPower_GetInterNationQueueByEventCode`
3. Added missing thunk declarations used by those promoted bodies:
   1. `thunk_SetTimeEmitPacketGameFlowTurnId`
   2. `thunk_CreateAndSendTurnEvent21_ThreeBytes`
4. Validation commands:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004defd0`
   5. `just compare 0x00540ac0`
   6. `just compare 0x00541080`
   7. `just compare 0x005410f0`
   8. `just compare 0x005416b0`
   9. `just compare 0x0055c970`
   10. `just compare 0x0055cbd0`
   11. `just stats`
5. Current key scores from this pass:
   1. `0x004DEFD0`: `40.00%`
   2. `0x00540AC0`: `15.09%`
   3. `0x00541080`: `9.09%`
   4. `0x005410F0`: `43.59%`
   5. `0x005416B0`: `6.56%`
   6. `0x0055C970`: `17.24%`
   7. `0x0055CBD0`: `39.76%`
6. Global snapshot after pass (`just stats`):
   1. aligned functions: `91` (delta `-1`)
   2. average similarity: `2.91%` (delta `-0.01 pp`)

### TGreatPower UI-dispatch ABI correction pass

1. Corrected known `ret 0x10` signature mismatch pair to 4-arg shapes:
   1. `0x004DDBB0` `TryDispatchNationActionViaUiContextOrFallback`
   2. `0x00541080` `TryDispatchNationActionViaUiThenTurnEvent`
2. Replaced failing `__thiscall` local typedefs (MSVC500 C4234) with `__fastcall` bridge casts using explicit `(this, edx, ...)` argument flow.
3. Switched `0x541080` dispatch thunk call from no-arg cast to 4-arg cast to preserve call payload flow.
4. Validation commands:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004ddbb0`
   5. `just compare 0x00541080`
   6. `just stats`
5. Result deltas:
   1. `0x004DDBB0`: `37.36% -> 43.30%`
   2. `0x00541080`: `9.09% -> 50.00%`
6. Global snapshot unchanged after this sub-pass:
   1. aligned functions: `91`
   2. average similarity: `2.92%`

### Vcall facade shape pass + eligibility-thunk alignment

1. Refactored facade generation:
   1. `tools/workflow/generate_vcall_facades.py` now emits direct slot-bound call wrappers (typed function pointer bound to `vcall_runtime::resolve_slot`) instead of routing each call through `vcall_runtime::fastcall*` helper functions.
   2. Regenerated `include/game/generated/vcall_facades.h`.
2. Updated `src/game/TGreatPower.cpp` eligibility helper:
   1. `IsNationSlotEligibleForEventProcessingFast` now loads manager from `kAddrEligibilityManagerPtr` (`0x006A43E0`).
   2. Return type switched to `char` flag shape to better match `AL`-based branches in original code.
3. Validation commands:
   1. `just gen-vcall-facades`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004d8cc0`
   5. `just compare 0x004d92e0`
   6. `just compare 0x004dbf00`
   7. `just compare 0x004de860`
   8. `just compare 0x004df010`
4. Result deltas on active top-impact set:
   1. `0x004D8CC0`: `31.98% -> 31.98%` (no change)
   2. `0x004D92E0`: `30.54% -> 31.09%` (improved)
   3. `0x004DBF00`: `29.14% -> 29.14%` (no change)
   4. `0x004DE860`: `26.74% -> 28.68%` (improved)
   5. `0x004DF010`: `16.74% -> 20.66%` (improved)
5. Guardrail check:
   1. Tried direct raw-vtable calls inside `src/game/TGreatPower.cpp`; `just vtable-gate` correctly failed.
   2. Reverted manual raw-vtable edits and kept improvement path in generated facades + typed helpers.
6. Post-pass sanity:
   1. `just compare-canaries`: pass (`below_floor=0`).
   2. `just stats`: aligned functions `91`, average similarity `2.92%` (global unchanged).

### TGreatPower UI-dispatch call-shape tightening (`0x004DDBB0`)

1. Targeted function:
   1. `0x004DDBB0` `TryDispatchNationActionViaUiContextOrFallback`
2. Change summary in `src/game/TGreatPower.cpp`:
   1. Removed non-original null/function-pointer guards on UI-dispatch branch.
   2. Moved `g_pUiRuntimeContext` load into the taken branch to match original call flow.
   3. Kept fallback dispatch path unchanged (`slot 0x1B0` call shape preserved).
3. Validation loop:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004ddbb0`
   5. `just compare 0x00541080`
   6. `just compare 0x004df010`
   7. `just compare-canaries`
4. Result deltas:
   1. `0x004DDBB0`: `43.30% -> 51.69%` (improved)
   2. `0x00541080`: `50.00% -> 50.00%` (unchanged)
   3. `0x004DF010`: `20.66% -> 20.66%` (unchanged)
5. Guardrails:
   1. `just vtable-gate`: pass (no new raw-vtable baseline violations).
   2. `just compare-canaries`: pass (`below_floor=0`).

### TGreatPower turn-event dispatch ABI correction (`0x00541080`)

1. Targeted function:
   1. `0x00541080` `TryDispatchNationActionViaUiThenTurnEvent`
2. Change summary in `src/game/TGreatPower.cpp`:
   1. Updated `thunk_DispatchTurnEvent1AWithNationActionPayload` callsite to `__stdcall`.
   2. Added prepended nation argument (`this->nationSlot`) so emitted payload order matches the original push sequence.
3. Validation loop:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x00541080`
   5. `just compare 0x004ddbb0`
   6. `just compare-canaries`
4. Result deltas:
   1. `0x00541080`: `50.00% -> 81.48%` (major improvement)
   2. `0x004DDBB0`: `51.69% -> 51.69%` (unchanged)
5. Guardrails:
   1. `just vtable-gate`: pass.
   2. `just compare-canaries`: pass (`below_floor=0`).

### TGreatPower class-shape pass (`1,3,4`: layout guards + typed pointers + explicit pads)

1. Edited `src/game/TGreatPower.cpp`:
   1. Kept unknown member naming explicit (`pad_*`), including `pad_44_ptr`.
   2. Promoted known object members from `void*` to opaque typed pointers (`TListObject*`, `TQueueObject*`, `TMinisterObject*`, `TRelationManagerObject*`).
   3. Added compile-time layout guards for stable core offsets and kept tail offsets as non-fatal probes.
   4. Fixed leftover old-name callsite in `ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries` (`unassignedTrackedList` -> `pad_44_ptr`).
2. Validation:
   1. `just build`: pass.
   2. `just detect`: pass.
   3. `just stats`: pass, unchanged vs immediate pre-pass baseline:
      1. aligned functions: `91`
      2. average similarity: `2.92%`

### TGreatPower targeted score pass (`0x004DE340`, `0x004DD740`, `0x00601F1D`)

1. Scope:
   1. Kept work inside `src/game/TGreatPower.cpp` and `config/vtable_slots.csv`.
   2. Added localization slot facades for slot `0x84`:
      1. `VCall_LocalizationRuntime_CallSlot84`
      2. `VCall_LocalizationRuntime_CallSlot84WithId`
2. `0x004DE340` `SetDiplomacyGrantEntryForTargetAndUpdateTreasury`:
   1. Refined body shape around grant-accept path and shared-ref message dispatch.
   2. Wired localization slot calls through generated facades (instead of ad-hoc casts).
   3. Kept higher-scoring variant after an attempted `__try/__finally` pass regressed.
   4. Delta: `9.62% -> 12.31%`.
3. `0x004DD740` `GetDiplomacyExternalStateB6ByTarget`:
   1. Verbose diff showed original shape uses `ret 4` and reads `this+0x894`.
   2. Changed method to one-arg getter-style signature and used explicit `+0x894` typed offset view.
   3. Delta: `0.00% -> 22.22%`.
4. `0x00601F1D` `CPtrList`:
   1. Tested alternate shape; retained prior variant because newer rewrite regressed.
   2. Current: `9.09%`.
5. Validation loop:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004de340`
   5. `just compare 0x004dd740`
   6. `just compare 0x00601f1d`
   7. `just compare-canaries`
   8. `just stats`
6. Guardrails / snapshot:
   1. `just vtable-gate`: pass.
   2. `just compare-canaries`: pass (`below_floor=0`).
   3. `just stats`: aligned `91`, average similarity `2.93%`.

### TGreatPower iterative body pass (`0x004DB380`, `0x004DAF30`, `0x004DE340`)

1. Scope:
   1. `src/game/TGreatPower.cpp`.
   2. Added one explicit global pointer constant: `kAddrNationInteractionStateManagerPtr = 0x006A43CC`.
   3. Added `TGreatPowerPressureUpdateView` for stable offset-based access in pressure/escalation code.
2. `0x004DB380` `UpdateGreatPowerPressureStateAndDispatchEscalationMessage`:
   1. Replaced prior simplified branch with a shape closer to Ghidra:
      1. weighted base-pressure computation (`slot 0x5F` + `this+0x166/0x168/0x840`),
      2. smoothing update at `+0x8F0`,
      3. tier transitions around `+0x8FC`,
      4. pressure value rise/decay at `+0x8F4`,
      5. final drain equation writing `+0x900`.
   2. Kept localized dispatch path in C++ (no asm/raw slot offsets in gameplay body).
   3. Delta: `12.24% -> 24.38%`.
3. `0x004DAF30` `CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage`:
   1. Replaced previous small payload-only body with a larger ordered-slot scan:
      1. fixed nation priority list,
      2. external-state delta zeroing at `+0xB6 + slot*2`,
      3. manager refresh/call path (`+0x80`, `+0x4C`),
      4. localized dispatch envelope.
   2. Corrected threshold gate to read `+0x8FC` via typed view (not provisional class member offset drift).
   3. Delta: `13.86% -> 13.53%` (small regression accepted for now in exchange for real body extraction).
4. `0x004DE340` safety check:
   1. Tried an alternative shaping pass (char flags + direct matrix indexing + explicit shared-ref locals) that regressed to `7.56%`.
   2. Reverted only that function to the previous better variant.
   3. Final remains: `12.31%`.
5. Validation commands (repeated through the pass):
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004db380`
   5. `just compare 0x004daf30`
   6. `just compare 0x004de340`
   7. `just compare-canaries`
   8. `just stats`
6. Current checkpoint:
   1. `0x004DB380`: `24.38%`
   2. `0x004DAF30`: `13.53%`
   3. `0x004DE340`: `12.31%`
   4. `just compare-canaries`: pass (`below_floor=0`)
   5. `just stats`: aligned functions `91`, average similarity `2.93%`.
