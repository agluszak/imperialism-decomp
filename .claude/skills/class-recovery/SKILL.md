---
name: class-recovery
description: Reconstruct C++ classes and vtables for the Imperialism decomp — run slice/class discovery, use Mac CodeWarrior evidence as a name oracle, record ClassCandidate evidence, and migrate vtable calls toward real virtuals on recovered class headers. Use when recovering a class layout, assigning a vtable, or attributing functions/fields to a class.
---

# Class & vtable recovery

Treat C++ recovery as **staged MSVC reconstruction**, not a single Ghidra result.
Hard Rules and the MSVC calling-convention guardrail are in `AGENTS.md`; matching
tactics for specific class families are in `heuristics.md` next to this file;
convention/receiver questions load `calling-conventions`, collection-shaped fields
load `mfc-collections`.

## Source-only class recovery workflow

The class recovery workflow is source-first and source-only. There are no manifests or consistency gates.

To recover or modify a class:
1. Edit class headers (`include/game/<ClassName>.h`) and source files (`src/game/<ClassName>.cpp`) directly.
2. Compile and link the code with `just build`.
3. Assert and verify virtual table layout and correctness against the original binary using `just vtable [ClassName]`.
4. Ensure no mechanical formatting or annotation policies are violated by running `just gates`.


## ABI model (Imperialism.exe = MSVC x86)

1. Objects carry one or more `vfptr` fields; a `vfptr` points to a vftable
   function-pointer array; with RTTI, the complete-object-locator may be at
   `vfptr[-1]`.
2. Vftable slots are **byte offsets** in disassembly and **pointer indices** in the
   wrapper config: a call through `[vftable + 0x40]` is slot index `0x40/4 == 16`.
   Record BOTH index and byte offset when documenting slot evidence.
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
4. Separate the slice into: real `this` field accesses, virtual callsites,
   global/helper boundaries, and ctor/dtor/lifetime evidence. A helper *called from*
   a class method is not membership evidence.
5. Only then edit source (class headers + manual TUs). Verify with `just compare 0xADDR` and
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

## Vtable dispatch on recovered classes

Declare provisional or confirmed `virtual` methods on the owning class header at the
verified slot offset, then call through normal C++ dispatch (`obj->Method(args)`).

After header changes: `just vtable-gate` → `just build` → `just compare` on touched
functions.

**Unknown receivers**: recover a minimal view/base class with the needed slot(s) first;
do not add local `typedef ...Fn` + `reinterpret_cast` vtable casts in gameplay code.

## Guardrails

1. Do not move a helper into a class just because a class method calls it.
2. Do not infer inheritance from names alone; defer base edges until structural
   (vptr/offset) evidence exists.
3. Do not mix MSVC and Itanium table layouts.
4. No raw vtable indexing in gameplay code — declare real `virtual` methods on the
   owning class instead.
5. Treat both Ghidra recovered-class output and Mac symbols as oracles to compare
   against, not source of truth.
6. The real-C++-construction Hard Rules (no manual vptr writes, no `new (this)` base
   construction, no `__thiscall` reinterpret_cast, retire bridge helpers) are enforced
   by `just antipattern-gate`. Run `just gates` before committing a recovery change.

## Structured reccmp evidence for class work

Run `just triage` before treating a raw diff as layout evidence. A trusted
`memory_address` mismatch with the same non-stack base and different displacement is
a strong prompt to inspect receiver class layout, field declaration order, padding,
construction, and `ASSERT_SIZE`; it does not by itself name the field. An EBP/ESP base
is stack-layout evidence instead, so route it to `just stackcmp`. A `call_argument`
on ECX can expose a wrong receiver attribution, but confirm the caller's ECX source.

Do not use safe or uncertain results as class evidence: `effective` with
`frame_slot_layout` or `register_allocation` was proved harmless, and
`inconclusive` means reccmp established no source defect.

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
`just stats` (it touches ~20 already-100% functions). See decomp-loop/heuristics.md
(vtable pairing infrastructure) and `ctors-dtors-eh` (scalar deleting destructors)
for the ctor vtable-pairing and scalar-deleting-destructor recipes.
