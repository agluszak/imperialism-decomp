# Imperialism RE TODO (Active Queue)

History/logs moved to `agent_2.md`.

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
- [~] Enum extraction + propagation wave lane (new reusable flow)
  - added maintained wave command: `run_enum_domain_wave`
  - checked-in reusable domain packs: `config/enum_domains/*.csv` (`all_high_confidence`, `core_callbacks`, `diplomacy_raw`, `map_mode_strict`, `turn_instruction_token`)
  - extraction now includes instruction-level `PUSH imm -> CALL` evidence for callback-command constants
  - applied lanes so far:
    - `arrow_command + control_tag` over `0x00500000..0x005fffff`: 36 candidates, 2 inferred enums, 5 param typings, 0 hotspots
    - `diplomacy_*_raw` over `0x00500000..0x0062ffff`: 65 candidates, 3 inferred enums, 1 param typing, 0 hotspots
    - strict `map_interaction_mode` lane: 25 candidates, 1 inferred enum (merged safely), 2 param typings, 0 hotspots
  - consolidated high-confidence lane now hotspot-clean (`batch_enum_waveN_all_apply`): +1 final arrow param typing (`HandleTransportPictureSplitArrowCommand64or65`)
  - next: turn-state/turn-event domain CSV lanes + selective struct-field enum propagation (new struct candidate extraction lane now available)

- [~] Bulk class-namespace assignment (850 of 2,294 assigned, 37%)
  - applied: 388 vtable-unique, 204 callee-round1, 75 name-based, 71 callee-round2, 82 vtable-majority, 30 indirect-ref
  - created `infer_class_from_indirect_refs` command (vtable/class-global data refs)
  - this-pointers auto-typed on namespace move (DYNAMIC_STORAGE mode)
  - remaining ~1,448 Global __thiscall lack clear class indicators
  - parked: further assignment needs caller-based or deeper decompiler analysis

- [~] Struct field coverage expansion (1,729 fields named across 199 structs)
  - created `mine_struct_field_access` command: decompiles class methods + follows thunk chains into Global impl functions
  - created `apply_mined_struct_fields` command: grows stub structs and applies field names/types
  - mined 1,817 field access points across all classes (4,801 class methods + 1,298 impl functions)
  - applied 1,729 fields total, grew 219 structs from stubs to proper sizes
  - key structs populated: TGreatPower (69 fields, 0x1→0xef4), TCountry (37), TToolBarCluster (30), TradeControl (+11 new)
  - remaining: large UI-heavy structs (TBattleReportView 9,392 anon) have few thunk-reachable impl functions
