# Imperialism RE TODO (Active Queue)

History/logs moved to `agent_2.md`.

## Current Plan (This Wave)
- [x] Step 1: Static Windows vtable scan from PE file bytes
  - update `scan_windows_static_vtables` to read `.rdata` pointer runs from on-disk executable bytes (VA->file mapping), not in-project memory.
  - keep existing class-evidence/xref attribution path for confidence/evidence fields.
- [x] Step 2: Expand macOS vtable layout coverage beyond prior baseline
  - improve `extract_macos_vtable_layout` to evaluate all constructors per class and support LOAD-based vtable pointer recovery.
  - re-run extraction and verify classes/rows materially increase beyond prior 13-class baseline.
- [x] Step 3: Re-run cross-platform pipeline and apply conservative rename wave
  - run `run_cross_platform_vtable_recovery` end-to-end.
  - build a conservative rename CSV (generic current names only; medium/high first, low-confidence fallback when empty) and apply via `run_wave_bundle --apply`.
  - result notes:
    - static scan now returns `36078` rows over `746` vtable candidates (`scan_source=file_bytes`)
    - macOS layout now extracts `242` rows across `22` classes (up from `174/13`)
    - cross-platform static seed matching still returned `0` rows this pass
    - conservative runtime-backed wave applied `8` renames cleanly (`rename_ok=8`)

## Completed
- [x] Split-arrow callback ABI normalization
  - created `force_callback_abi_parameter_storage` command with CUSTOM_STORAGE
  - `unaff_retaddr` eliminated from both `0x0058c640` and `0x005869c0`
  - `EArrowSplitCommandId` typing retained

- [x] Nation-metrics dispatch table lane (`0x0066d9f0..0x0066da18`)
  - identified as NationInteractionStateManager vtable (base `0x0066d990`)
  - labeled 41 vtable slots; de-orphaned 4 nation-metric helpers

- [x] Runtime-pointer state class extraction follow-up
  - resolved all anonymous fields in `TCViewOwnedBufferRegistryState_00648560`
  - remaining 4 structs already fully typed; all this-pointers already typed

- [x] Thunk-island bulk signature propagation (`0x00401000..0x0040AFFF`)
  - reduced `undefined` return types from 5,424 → 3,930 (1,494 fixed, 27.5%)
  - applied: 246 SDDs, 49 ctor/dtors, 20 factories, 188 wrapper→callee, 181 void-pattern,
    101 orphan-leaf, 86 vtable-stubs, 174 ret-stubs, 69 hidden-stack, 37 ECX→thiscall, 39 getters, 79 allocators, 23 booleans
  - fixed external-address crash in `generate_single_jmp_thunk_pairs.py`

- [x] Hidden-param register-artifact cleanup
  - reduced from 194 → 124 hidden-param functions via automated waves
  - remaining 124 are ECX-only (global variable access patterns)

- [x] `void *` this-pointer and parameter typing (class-namespaced)
  - 0 candidates remain in class namespaces; all class this-pointers typed
  - 2,294 `void * this` remain in Global namespace (blocked on class assignment)

- [x] Return-type inference via decompiler body analysis (3,942 of 3,942 fixed, 100%)
  - created `infer_return_type_from_decomp` command (decompiles each function, extracts inferred types)
  - created `apply_return_type_and_cc` command (sets cc + return type without touching params)
  - applied: 1,864 void + 1,681 int + 281 other + 63 remaining + 39 thunk cascade + 10 CRT
  - 0 `undefined` return types remaining

- [x] CC resolution (cc=unknown: 292 → 0)
  - created `resolve_unknown_cc` command (thunk-chain propagation + decompiler inference)
  - resolved all 250 remaining cc=unknown functions (all `__cdecl` via decomp inference)
  - CC distribution: __cdecl 9,071, __thiscall 4,922, __fastcall 659, __stdcall 269

- [x] Global data naming (1,350 indirect + 38 direct = 1,388 named)
  - extended `inventory_unnamed_globals` with indirect-ref rename (Category B)
  - 3,403 globals inventoried; 1,652 with code context, 1,751 data-only
  - 302 remaining direct-ref globals are ftol wrappers (correctly skipped)

- [x] Datatype namespace unification (250 types moved from root / to /imperialism/classes/)
  - created `move_class_datatypes_to_canonical` command
  - moved 236 types, resolved 14 collisions (2 src-richer, 12 dst-richer), 0 failures
  - /imperialism datatype count: 436 → 816; root / reduced: 1,091 → 690 (remaining are Ghidra builtins)

## Active (max 3)
- [~] macOS symbol integration lane (class inventory first, conservative-assisted)
  - added maintained commands:
    - `build_macos_class_gap_map` (ranked per-class method-gap inventory from `macos_class_methods.csv`)
    - `generate_macos_vocab_candidates` (wave-ready conservative rename/signature CSV generation)
    - `apply_macos_vocab_wave` (orchestrates gap map -> vtable inference -> candidate build -> wave apply)
    - `extract_windows_runtime_vtable_slot_writes` (attempts class/slot/function recovery from runtime-style write paths)
  - upgraded `extract_macos_vtable_layout` with fallback data-ref cluster recovery:
    - now extracts `174` rows across `13` classes (from prior `0`).
    - emits `layout_source` per row (`ctor_vtable_store` vs `fallback_data_ref_cluster`).
  - executable-bytes slot recovery now implemented:
    - `extract_windows_runtime_vtable_slot_writes` falls back to parsing the on-disk PE bytes (VA->file offset) when Ghidra memory bytes are zeroed.
    - full unfiltered pass recovers `32174` class-slot mappings across `383` classes from file bytes (`tmp_decomp/windows_runtime_vtable_slot_map_all.csv`).
    - raw + best CSVs now include `vtable_base_addr` to directly locate table bases in `.rdata`.
  - correlation safety hardening:
    - `generate_macos_vocab_candidates` now treats broad placeholder names (`thunk_*`, `OrphanCallChain_*`, `*_VtblSlot*`) as generic and skips ambiguous multi-class address collisions.
    - `infer_name_from_macos_vtable` now downgrades non-constructor-backed layouts to `low` confidence.
  - blocker for auto-apply:
    - all currently inferred macOS slot candidates are `low` confidence because affected classes are fallback-only (`layout_source=fallback_data_ref_cluster`), not true constructor vtable extracts.
    - next: obtain constructor-backed macOS vtable slots (or independent slot anchors) before any medium/high semantic rename wave.
  - windows-first reconstruction pass completed (safe, non-semantic):
    - added maintained command `build_windows_vtable_apply_plans`.
    - generated:
      - `tmp_decomp/windows_vtable_base_labels_apply.csv` (`298` base labels, non-Candidate classes)
      - `tmp_decomp/windows_vtable_slot_attach_apply.csv` (`1215` class-attach rows, `1056` slot-name normalizations)
    - applied:
      - `apply_global_data_from_csv`: labeled vtable bases (`ok=8`, `skip=287`, `fail=3` duplicate-name collisions)
      - `attach_functions_to_class_csv`: `ns_ok=38`, `rename_ok=1056`
    - current state snapshot:
      - functions named with `_VtblSlot`: `1077` (broad class-slot structural naming now in place for decomp readability)
  - follow-up namespace + thunk readability wave completed:
    - added maintained command `ensure_class_namespaces_from_slot_map` (filtered, evidence-thresholded namespace creation from slot-map evidence)
    - namespace creation run:
      - `tmp_decomp/windows_missing_class_namespace_plan.csv`: `246` candidates, `22` missing created
    - regenerated/reattached slot plan:
      - `windows_vtable_slot_attach_apply.csv`: `1431` rows (`+216` over prior wave)
      - attach apply: `ns_ok=123`, `rename_ok=166`, `rename_skip=1056`
    - semantic-thunk rename wave from structural slot names:
      - generated `windows_vtblslot_jmp_thunk_renames.csv` (`1210` rows)
      - filtered + applied `windows_vtblslot_jmp_thunk_renames_filtered.csv` (`993/993` applied)
      - follow-up applied wrapper/orphan thunk-target names (non-mangled) from `windows_vtblslot_jmp_thunk_renames_remaining.csv` (`207/207`)
      - final single-callee cleanup applied `windows_vtblslot_final_single_callee.csv` (`3/3`)
    - state after follow-up:
      - `_VtblSlot` function names reduced `1238 -> 46`
      - `thunk_*_At<addr>` names now `3003` (much richer call-target readability in decomp)

- [~] Enum extraction + propagation wave lane (new reusable flow)
  - added maintained wave command: `run_enum_domain_wave`
  - checked-in reusable domain packs: `config/enum_domains/*.csv` (`all_high_confidence`, `core_callbacks`, `diplomacy_raw`, `map_mode_strict`, `turn_instruction_token`)
  - extraction now includes instruction-level `PUSH imm -> CALL` evidence for callback-command constants
  - applied lanes so far:
    - `arrow_command + control_tag` over `0x00500000..0x005fffff`: 36 candidates, 2 inferred enums, 5 param typings, 0 hotspots
    - `diplomacy_*_raw` over `0x00500000..0x0062ffff`: 65 candidates, 3 inferred enums, 1 param typing, 0 hotspots
    - strict `map_interaction_mode` lane: 25 candidates, 1 inferred enum (merged safely), 2 param typings, 0 hotspots
  - consolidated high-confidence lane now hotspot-clean (`batch_enum_waveN_all_apply`): +1 final arrow param typing (`HandleTransportPictureSplitArrowCommand64or65`)
  - table-dispatch follow-up completed:
    - new maintained command `create_turn_event_factory_types` now canonicalizes `ETurnEventFactorySlotId` + `STurnEventFactoryPacket` and reapplies core factory signatures.
    - new maintained command `annotate_turn_instruction_dispatch_internals` annotates TERM/table-bound sentinels in dispatcher internals.
    - `create_turn_instruction_types` now adds `TURN_TOKEN_TERM` and labels token-table end sentinel.
  - next: extend struct-field enum propagation beyond current param-heavy matches using the new `struct_field` candidate lane

- [~] Bulk class-namespace assignment (3,559 of 4,922 assigned, 72.3%)
  - applied: 388 vtable-unique, 204 callee-round1, 75 name-based, 71 callee-round2, 82 vtable-majority, 30 indirect-ref, 20 decomp-v2, 403 this-passing
  - post-FillOutStructure round: +18 (6 high, 12 medium) via re-run of all three inference commands
  - FillOutStructure wave auto-retyped ~2,654 this-pointers via improved struct layouts
  - created `infer_class_from_indirect_refs` command (vtable/class-global data refs)
  - created `infer_class_from_this_passing` command (this-pointer passing from class methods)
  - enhanced `infer_class_from_decomp` with symbol-name vtable writes (`g_vtblTFoo` patterns)
  - QC audit reverted 590+76 misattributions (TradeControl junk drawer, TView dtor thunks, DLL namespaces, excess dtor copies)
  - post-audit re-inference: +71 high/medium via this-passing + callers depth-2 + decomp
  - created `run_qc_pass` command: 7-category health check in one Ghidra session (class %, stale names, gates, dups)
  - created `generate_stale_wrapper_renames` command: auto-detect WrapperFor stale names
  - 15 stub-only classes (TNavyMgr, TCivMgr, TOcean, TCivUnit, etc.) need vtable-guided seeding (inference finds no signal)
  - remaining 1,363 Global __thiscall void* lack clear class indicators

- [~] Class hierarchy reconstruction (573 ranked edges, 90 high+medium, max depth 3)
  - created `reconstruct_class_hierarchy` command: decompiles class methods + Global helpers, extracts vtable write sequences
  - created `apply_class_hierarchy` command: embeds parent structs at offset 0 with topological ordering
  - upgraded to Pcode SSA analysis (default): walks STORE op def-chains to trace `this`/param0, resolves vtable addresses/symbols from value varnodes
  - post-FillOutStructure re-run: 90 high+medium edges (up from 10), 89 classes with parents (up from 9), 10 tree roots
  - applied hierarchy: 27 new parent embeddings, 1 struct grown (TButton 0x48→0x82), 26 already embedded
  - verified chains at depth 3: TView→TStaticText→TEditText→TDropShadowNumberText, TView→TPageView→TMilitaryPageView→TGarrisonView
  - new edges from FillOutStructure: TView→TControl, TView→TCivDescription, TView→TAmtBar, TControl→TGWorldButton, TControl→TRadio, etc.

- [~] Struct field coverage expansion (26k+ fields via FillOutStructure + SSA mining)
  - created `mine_struct_field_access` command: decompiles class methods + follows thunk chains into Global impl functions
  - created `apply_mined_struct_fields` command: grows stub structs and applies field names/types
  - created `mine_struct_field_access_ssa` command: Pcode SSA-based field mining (replaces regex approach)
  - created `fill_out_structure_wave` command: runs FillOutStructureCmd across all class methods with topological ordering
  - created shared `core/decompiler.py`: reusable DecompInterface factory + param0 varnode tracing
  - regex miner: 1,817 field access points across all classes (4,801 class methods + 1,298 impl functions)
  - SSA miner: 124 unnamed field access points across top 20 classes (superset of regex results)
  - FillOutStructure round 1: 26,110 fields added across 452 classes, 3,803 methods processed
  - FillOutStructure round 2: +38 fields (converged at fixpoint)
  - applied SSA-mined names: 92 fields applied, 6 failed (struct size conflicts at existing typed boundaries)
  - key growth: TradeControl 0x198→0xfe2, TMinister 0x4→0x190, TCityInteriorMinister 0x4→0x158, TToolBarCluster 0x1e4→0x524
  - remaining: struct size conflict fields (e.g. TGreatPower+0x8a4, TradeControl+0x4) need manual resolution
