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

## Active (max 3)
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

## Active (max 3)
- [~] Bulk class-namespace assignment (820 of 2,294 assigned, 36%)
  - applied: 388 vtable-unique, 204 callee-round1, 75 name-based, 71 callee-round2, 82 vtable-majority
  - this-pointers auto-typed on namespace move (DYNAMIC_STORAGE mode)
  - remaining ~1,466 lack clear class indicators (no name match, no unique vtable, callee voting yields only base classes)
  - parked: further assignment needs caller-based or deeper decompiler analysis

- [x] Return-type inference via decompiler body analysis (3,932 of 3,942 fixed, 99.7%)
  - created `infer_return_type_from_decomp` command (decompiles each function, extracts inferred types)
  - created `apply_return_type_and_cc` command (sets cc + return type without touching params)
  - applied: 1,864 void + 1,681 int + 281 other + 63 remaining + 39 thunk cascade
  - remaining 10 are CRT internals ($E350, $E355, __seh_longjmp_unwind, etc.)
  - cc=unknown: 3,893 → 292 (cascade chains where every function has unknown cc)

- [~] Struct field coverage expansion (1,729 fields named across 199 structs)
  - created `mine_struct_field_access` command: decompiles class methods + follows thunk chains into Global impl functions
  - created `apply_mined_struct_fields` command: grows stub structs and applies field names/types
  - mined 1,817 field access points across all classes (4,801 class methods + 1,298 impl functions)
  - applied 1,729 fields total, grew 219 structs from stubs to proper sizes
  - key structs populated: TGreatPower (69 fields, 0x1→0xef4), TCountry (37), TToolBarCluster (30), TradeControl (+11 new)
  - remaining: large UI-heavy structs (TBattleReportView 9,392 anon) have few thunk-reachable impl functions

- [x] Datatype namespace unification (250 types moved from root / to /imperialism/classes/)
  - created `move_class_datatypes_to_canonical` command
  - moved 236 types, resolved 14 collisions (2 src-richer, 12 dst-richer), 0 failures
  - /imperialism datatype count: 436 → 816; root / reduced: 1,091 → 690 (remaining are Ghidra builtins)
