---
name: recover-class
description: Recover an Imperialism C++ class, layout, inheritance edge, or vtable from retail evidence under decomp/.
---

# Recover a class

Run from `decomp/`.

1. Identify constructors, destructors, allocation sites, method callers, and candidate vtables with
   `just ghidra` listing/xref queries.
2. Build an evidence table for allocation size, base/member construction order, field accesses,
   receiver types, prefix layout, virtual slots, and destructor behavior. Record contradictions rather
   than resolving them from names.
3. Update the class declaration and owned definitions according to the source and ABI invariants in
   `AGENTS.md`. Update affected base/override declarations and retire superseded recovery scaffolding.
4. Run focused builds and triage for affected functions, then `just vtable ClassName`.
5. Use `decompile-function` for substantial bodies and `verify` for final checks.
