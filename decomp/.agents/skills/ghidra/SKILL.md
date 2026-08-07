---
name: ghidra
description: Inspect and document the Imperialism retail executable through the repository's pyghidra and just interfaces. Use for listings, decompilation, xrefs, strings, field references, vtables, calling-convention evidence, function documentation, class datatype synchronization, or deliberate Ghidra database mutation under decomp/.
---

# Use Ghidra evidence

Run from `decomp/`. Prefer `just ghidra ...` targets and the persistent query daemon over ad hoc
scripts. The installed Ghidra must match `ghidra.toml`.

Read [workflow.md](references/workflow.md) for the complete command catalog, listing/decompile/xref
methodology, thunk handling, and mutation safety. Read
[function-documentation.md](references/function-documentation.md) when promoting durable names,
signatures, comments, or parameter/local documentation in the project. Read
[class-datatypes.md](references/class-datatypes.md) only for the class datatype synchronization
workflow.

Ground conclusions in instructions and data. Validate calling conventions from register/stack
behavior, resolve ILT thunks to their targets, and keep Mac evidence within its oracle boundary.
Treat the vendored project as authoritative; export and commit deliberate DB changes through the
documented pipeline rather than editing derived exports.
