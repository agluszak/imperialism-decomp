---
name: class-recovery
description: Reconstruct C++ classes and vtables for the Imperialism decomp — run slice/class discovery, use Mac CodeWarrior evidence as a name oracle, record ClassCandidate evidence, manage the vcall facade registry (config/vtable_slots.csv), and migrate vtable calls toward real virtuals. Use when recovering a class layout, assigning a vtable, deciding facade-vs-virtual dispatch, or attributing functions/fields to a class.
---

# Class & vtable recovery

Treat C++ recovery as **staged MSVC reconstruction**, not a single Ghidra result.
Hard Rules and the MSVC calling-convention guardrail are in `AGENTS.md`; matching
tactics for specific class families are in `decomp-loop/heuristics.md` (#25–36,
#49, #58–84).

## ABI model (Imperialism.exe = MSVC x86)

1. Objects carry one or more `vfptr` fields; a `vfptr` points to a vftable
   function-pointer array; with RTTI, the complete-object-locator may be at
   `vfptr[-1]`.
2. Vftable slots are **byte offsets** in disassembly and **pointer indices** in the
   wrapper config: a call through `[vftable + 0x40]` is slot index `0x40/4 == 16`.
   Record BOTH index and byte offset (some generated facades use a raw index).
3. Do not apply Itanium ABI rules to this binary.

## Evidence order (most → least trusted)

1. RTTI / complete-object-locator / type descriptor (if present).
2. Vftable groups and ctor/dtor `vfptr` writes.
3. Secondary vftable offsets / repeated subobject `vfptr` writes.
4. Virtual callsites and `this` adjustments.
5. Allocation sizes and repeated `this + offset` field accesses.
6. Names and symbol proximity. **Names alone are never inheritance or membership
   evidence.**

## Discovery workflow (per vertical slice)

1. The Mac CodeWarrior evidence is vendored at `vendor/macos_codewarrior/evidence/`;
   `just mac-evidence-check` validates it. Regenerating it (`just mac-evidence`) is
   rarely needed and requires `MACOS_IMPERIALISM_DUMP` in `.env` (the external dump).
2. `just class-discovery [Classes]` — rank class/vtable ownership candidates from
   in-repo evidence before any attach/rename (excludes already-owned addresses).
3. `just slice-discovery <Class> 0xADDR` — emits
   `tmp_decomp/slice_discovery/<class>_<addr>/class_candidate.json`.
4. Separate the slice into: real `this` field accesses, actual vcall wrappers,
   global/helper boundaries, and ctor/dtor/lifetime evidence. A helper *called from*
   a class method is not membership evidence.
5. Only then edit source or vcall metadata. Verify with `just compare 0xADDR` and
   `just stats`.

For a suspect class name, use a synthetic label with explicit anchors:

```sh
uv run python -m tools.workflow.slice_discovery Candidate_666998 \
  --address 0x0058aaa0 --source src/game/TShipAmtBar.cpp \
  --vtable 0x00666998 --classdesc 0x00663010 --name-source synthetic
```

### ClassCandidate evidence object

Record observations conservatively before editing layout/inheritance. Shape:
`name_source` (rtti|symbol|synthetic|manual), `abi: msvc`, `typeinfo_addr`,
`primary_vtable_addr`, `secondary_vtables[(addr, offset_to_top, base_offset)]`,
`vtable_slots[(slot, function_addr, thunk?, destructor_kind?)]`, `ctor_candidates`,
`dtor_candidates`, `allocation_sizes`, `field_accesses[(offset, size, rw, function)]`,
`virtual_callsites[(function, this_offset, slot_index)]`,
`base_edges[(base, confidence, evidence)]`. Empty fields are fine; invented fields are
not.

## Mac CodeWarrior evidence (oracle only)

The Mac build is a PowerPC PEF compiled with CodeWarrior; its normalized evidence is
vendored under `vendor/macos_codewarrior/evidence/`. It guides class names, method
names, and likely signatures — but is NOT ABI-compatible with the Windows target and
must **never** directly assign Windows addresses, vtable slots, calling conventions,
or inheritance edges.

## Vcall facade registry

Keep vtable-call plumbing centralized while layouts evolve.

- **Source of truth**: `config/vtable_slots.csv` (`owner_file`, `wrapper_name`,
  `return_type`, `slot_expr`, `arg_types`; optional `slot_unit`, `callconv`,
  `edx_mode`, `edx_value`, `status`, `class_name`).
- Generator: `tools/workflow/generate_vcall_facades.py` →
  `include/game/generated/vcall_facades.h`. The only place allowed to resolve/cast
  vtable slots is `include/game/vcall_runtime.h`.
- After any change: `just gen-vcall-facades` → `just vtable-gate` → `just build`.

### Facade lifecycle

1. `provisional` — slot/signature inferred from decomp shape; gameplay calls go
   through generated `VCall_*` wrappers.
2. `verified` — slot, signature, and owner class confirmed; wrapper safe to reuse.
3. `native_migrated` — callsites moved to real `virtual` methods; wrapper kept as a
   compatibility shim until cleanup.

**Facade vs real virtual**: for *unknown/unstable* receivers, use generated facades.
For *grounded* receivers (slot byte-offset, signature, return usage, and owning class
all confirmed), prefer real `__thiscall` virtual dispatch via a typed view class — it
drops the spurious `edx=0` the facades emit (heuristics.md "Vtable dispatch as real
virtuals"). Keep address ownership/annotations unchanged across the migration and
`just compare` before/after.

## Guardrails

1. Do not move a helper into a class just because a class method calls it.
2. Do not infer inheritance from names alone; defer base edges until structural
   (vptr/offset) evidence exists.
3. Do not mix MSVC and Itanium table layouts.
4. No raw vtable indexing in gameplay code — add facade metadata instead.
5. Treat both Ghidra recovered-class output and Mac symbols as oracles to compare
   against, not source of truth.
6. The real-C++-construction Hard Rules (no manual vptr writes, no `new (this)` base
   construction, no `__thiscall` reinterpret_cast, retire bridge helpers) are enforced
   by `just antipattern-gate`. Run `just gates` before committing a recovery change.

## C++-inheritance migration (EH-framed base destructors)

To match EH-framed base destructors (e.g. `CObArray::~` `0x601bdd`, `CPtrList::~`
`0x601f7c`, `CDocument::~` `0x6109eb`), model the MFC foundation hierarchy as real C++
classes with `// VTABLE:` markers and virtual destructors — the `__EH_prolog` frame
can only be emitted by the compiler from a real destructor (no inline asm). Real
layouts (dumped via `just ghidra-vtable-dump`): `CObject` (`0x66fec4`, 5 slots),
`CObArray`/`TIndexAndRankList` (`0x672eac`, 5 slots), `CPtrList` (`0x672eec`, 5 slots),
`TSortedPtrList` (`0x649068`, 16 slots). Stage it as one coherent pass
(`CObject` base → `TIndexAndRankList : CObject` → `CPtrList` → `TSortedPtrList :
TIndexAndRankList` → `CDocument`), unify each manual ctor's vtable write onto the same
DATA symbol the C++ vtable resolves to, and re-verify the whole family +
`just stats` (it touches ~20 already-100% functions). See heuristics.md #61–66
for the concrete ctor/factory recipes.
