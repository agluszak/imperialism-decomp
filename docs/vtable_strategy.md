# Vtable Strategy

## Goal

Keep vtable call plumbing deterministic and centralized while class layouts are still evolving.

## Source of Truth

1. `config/vtable_slots.csv` stores wrapper metadata:
   1. `owner_file`, `wrapper_name`, `return_type`, `slot_expr`, `arg_types`
   2. optional extended fields: `slot_unit`, `callconv`, `edx_mode`, `edx_value`, `status`, `class_name`
2. `tools/workflow/generate_vcall_facades.py` generates:
   1. `include/game/generated/vcall_facades.h`
3. `include/game/vcall_runtime.h` is the only low-level place that may resolve and cast vtable slots.

## Lifecycle

1. `provisional`:
   1. slot/signature inferred from decompilation shape, still unstable.
   2. use generated `VCall_*` wrappers in gameplay code.
2. `verified`:
   1. slot, signature, and owner class confirmed from Ghidra/reccmp evidence.
   2. wrapper remains, but can be considered safe for broader reuse.
3. `native_migrated`:
   1. callsites moved to native class `virtual` methods.
   2. wrapper can remain as compatibility shim until cleanup.

## Rules

1. Gameplay code should call `VCall_*` wrappers or native class methods, never raw `vftable[...]` indexing.
2. New vtable usage must be added to `config/vtable_slots.csv`, then regenerated.
3. Run:
   1. `just gen-vcall-facades`
   2. `just vtable-gate`
   3. `just build`
4. For migration from wrapper to native virtual:
   1. keep address ownership and annotations unchanged,
   2. compare targeted functions before/after with `just compare 0xADDR`,
   3. revert quickly if call-shape regression is large.
