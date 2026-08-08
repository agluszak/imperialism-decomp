---
name: recover-class
description: Recover an Imperialism C++ class, layout, inheritance edge, or vtable from retail evidence under decomp/.
---

# Recover a class

Run from `decomp/` and follow the construction and type-modeling rules in `AGENTS.md`.

1. Collect constructor/destructor order, allocation size, caller receiver, field accesses, vtable
   slots, and prefix-layout evidence. Mac evidence may identify a name or signature; it never proves
   Windows addresses, calling conventions, vtables, or inheritance.
2. Keep unresolved attribution opaque. Do not merge classes or infer a base edge from a name or one
   coincident offset.
3. Express confirmed evidence as normal C++: fields in construction/layout order, real base classes,
   member objects, ordinary ctors/dtors, and real virtual declarations at verified slots. Retire raw
   vtable calls, vptr writes, placement construction, and temporary bridges instead of preserving them.
4. Verify focused code, `just vtable ClassName`, `just triage`, build, and gates. A failed check is a
   reason to fix the model forward, never to restore a fake source shape.

For function bodies, also load `decompile-function`.
