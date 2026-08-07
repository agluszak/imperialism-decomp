---
name: recover-class
description: Reconstruct Imperialism C++ classes, layouts, inheritance, constructors, destructors, virtual methods, and vtable slot ownership from Windows listing evidence with Mac symbols as a limited oracle. Use for unknown receivers, repeated offsets, class discovery, inheritance questions, wrong-slot or below-100-percent vtable results, and retiring raw vtable or construction scaffolding under decomp/.
---

# Recover a class

Run from `decomp/` and obey the construction, type-modeling, and virtual-call invariants in
`AGENTS.md`.

## Choose the lane

- For an unknown layout or inheritance edge, read
  [class-recovery.md](references/class-recovery.md).
- For a known class whose `just vtable Class` result has missing, extra, inherited, destructor,
  thunk, or wrong-slot entries, read [vtable-matching.md](references/vtable-matching.md).
- For function-body details inside the class, also load `decompile-function` and its applicable
  references.

## Workflow

1. Gather constructor/destructor sequencing, vtable slot targets, field xrefs, allocation sizes,
   caller receivers, and prefix-layout evidence. Use Mac symbols only for names/signatures.
2. Keep uncertain attribution opaque. Do not infer inheritance from names or merge classes merely
   because an offset or slot position resembles another class.
3. Express the evidence as real C++: typed fields in offset order, real inheritance, real members,
   ordinary constructors/destructors, and real virtual methods in verified slot order.
4. Retire manual vptr writes, raw vtable indexing, `VCall_*`, placement construction, and deleting-
   destructor bridges as the model becomes known. Never restore them to clear a gate.
5. Verify layout assertions, focused bodies, `just vtable Class`, structured triage, build, and gates.
   Treat oversized boundary/null diagnostics according to their actual evidence.

Search [class-recovery-heuristics.md](references/class-recovery-heuristics.md) and
[vtable-heuristics.md](references/vtable-heuristics.md) before retrying a known pattern. Record new
transferable evidence there, not in production source.
