# Class Recovery Strategy

This project treats C++ recovery as staged reconstruction, not as a single
Ghidra analyzer result.

## ABI

The current working model for `Imperialism.exe` is MSVC x86:

1. Objects carry one or more `vfptr` fields.
2. A `vfptr` points to a vftable function-pointer array.
3. If MSVC RTTI exists, the complete object locator may be available at
   `vfptr[-1]`.
4. Vftable slots are byte offsets in disassembly and pointer indices in the
   generated wrapper config. For example, a call through `[vftable + 0x40]`
   is slot index `0x40 / 4 == 16`.

Do not apply Itanium ABI rules to this binary unless a non-Windows target is
being analyzed separately.

## Evidence Order

Use signals in this order of trust:

1. RTTI / complete object locator / type descriptor evidence, if present.
2. Vftable groups and constructor/destructor `vfptr` writes.
3. Secondary vftable offsets or repeated subobject `vfptr` writes.
4. Virtual callsites and `this` adjustments.
5. Allocation sizes and repeated `this + offset` field accesses.
6. Names and symbol proximity.

Names alone are not inheritance or class-membership evidence.

## ClassCandidate

Local tools should emit a conservative evidence object shaped like:

```text
ClassCandidate {
  name_source: rtti | symbol | synthetic | manual
  abi: msvc
  typeinfo_addr
  primary_vtable_addr
  secondary_vtables: [(addr, offset_to_top, base_offset)]
  vtable_slots: [(slot, function_addr, thunk?, destructor_kind?)]
  ctor_candidates: [addr]
  dtor_candidates: [addr]
  allocation_sizes: [...]
  field_accesses: [(offset, size, read/write, function)]
  virtual_callsites: [(function, this_offset, slot_index)]
  base_edges: [(base, confidence, evidence)]
}
```

Empty fields are acceptable. Invented fields are not.

## Current Local Workflow

For a vertical slice:

1. Run `just slice-discovery <Class> 0xADDR`.
2. Inspect `tmp_decomp/slice_discovery/<class>_<addr>/class_candidate.json`.
3. Separate the slice into:
   1. real `this` field accesses,
   2. generated vcall wrappers,
   3. global/helper boundaries,
   4. constructor/destructor/lifetime evidence.
4. Only then edit source or vcall metadata.
5. Verify with targeted `just compare 0xADDR` and adjacent canaries.

If the class name itself is suspect, use a synthetic label and explicit anchors:

```sh
uv run python -m tools.workflow.slice_discovery Candidate_666998 \
  --address 0x0058aaa0 \
  --source src/game/TShipAmtBar.cpp \
  --vtable 0x00666998 \
  --classdesc 0x00663010 \
  --name-source synthetic
```

This keeps the evidence tied to addresses and vptr writes instead of to a
possibly wrong class name.

For broader Ghidra-side work:

1. Enumerate RTTI/typeinfo/COL objects if present.
2. Enumerate vftables and slots.
3. Xref vftable addresses to find `vfptr` writes.
4. Infer constructors/destructors from those writes and lifetime patterns.
5. Build/update structs from repeated field offsets.
6. Apply typed `Class *this` only after the evidence is recorded.
7. Defer inheritance edges until there is structural evidence.

## Guardrails

1. Do not move a helper into a class because a class method calls it.
2. Do not infer inheritance from names alone.
3. Do not mix MSVC and Itanium table layouts.
4. Do not introduce raw vtable indexing in gameplay code; add generated vcall
   facade metadata instead.
5. Treat Ghidra recovered class output as an oracle to compare against, not as
   source of truth.
