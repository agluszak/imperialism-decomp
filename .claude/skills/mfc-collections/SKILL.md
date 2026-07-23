---
name: mfc-collections
description: Recover and model MFC collection classes/subobjects in Imperialism decomp. Use when a vtable, constructor, destructor, or field region looks like CPtrList/CObList/CObArray/CList/CTypedPtrList, when an embedded collection vtable has no standalone RTTI, or when already-ported code is walking MFC protected internals instead of public collection APIs.
---

# MFC Collection Recovery

Use this skill before turning a collection-like field into a new local class. MFC
has both concrete runtime classes (`CPtrList`, `CObList`, `CObArray`) and header
template specializations (`CList<TYPE, ARG_TYPE>`, `CTypedPtrList<...>`). Template
specializations can emit vtables and member functions without getting their own
`CRuntimeClass`.

## The three-problem taxonomy (diagnose BEFORE changing source)

Embedding the MFC collection is usually the correct source model. Collection
mismatches conflate three separate issues — classify which one you have before
touching source, because only the first two are fixable in C++:

1. **Incorrect member construction/destruction order** — fix in source
   (initializer list + declaration order; see below).
2. **Incorrect template identity or element type** — fix in source
   (exact `TYPE`/`ARG_TYPE`; see the identity checklist below).
3. **Compiler/linker emission of inline template bodies and duplicate COMDATs** —
   NOT a source problem. Belongs in comparison metadata
   (`config/template_aliases.csv`) or controlled build experiments.

**A weak or unpaired duplicate template destructor is not evidence that the
collection member model is wrong.** The original executable frequently contains
multiple bodies for the same template instantiation (one near an owner ctor, one
near a dtor/serializer in another TU, separate vtable addresses, bodies differing
only by EH-handler addresses or relocations). `/OPT:NOREF` reproduces the same
result as baseline; `/OPT:REF` destroys coverage (95.95% → 44.17%) — the duplicate
problem is not fixed by linker flags, and never by source contortions.

**Never reproduce per-TU template duplication by inventing subclasses, wrappers,
raw storage, manual vptr writes, or duplicate gameplay implementations.**
Classify it as a template-emission/comparison problem first.

Proven-correct embedded members (do not regress these): TApplication's
`CList<void*, void*>` at +0x2c (size asserted 0x48);
TTurnEventDialogFactoryRegistry's `CList<TurnEventDialogFactoryProc, ...>` at
+0x04 (block size 10); CIncludeView's dirty-rect queue at +0x4c; the two
module-cache `CMap<>` specializations at +0x04 and +0x20.

## Initialization order (problem 1)

An embedded MFC collection is nontrivial; it constructs among the owner's
members, not at the start or end of the ctor body. When a class embeds one:

- place the member at the proven offset;
- declare surrounding members in exact layout order;
- initialize all observed scalar fields through the **member-initializer list, in
  declaration order** — body assignments force the member construction first and
  mismatch;
- do NOT explicitly call `RemoveAll()` to simulate the member destructor;
- do NOT manually construct or destroy the collection;
- the owner dtor contains only owner-specific cleanup — the compiler emits the
  member's destruction afterward;
- **always compare the owner ctor and dtor together** — a ctor mismatch without
  checking the dtor is an incomplete diagnosis.

Reference shape (CIncludeView, 69.77% → 86.36% from moving scalar inits into the
initializer list; the residual is one scheduling difference around the collection
vptr store, not a wrong member model):

```cpp
CIncludeView::CIncludeView()
    : CView(),
      m_activeDialogContext(0),
      m_field44(0),
      m_pOffscreenDib(0),
      m_tickTimerId(0),
      m_field70(0),
      m_capturedControl74(0),
      m_uiInteractiveFlag90(1) {}
```

## Exact template identity (problem 2)

Same physical shape ≠ same instantiation. `CList<void*, void*>`,
`CList<TView*, TView*>`, `CList<TView*, TView*&>`, `CList<Record, Record&>`, and
`CList<Record*, Record*>` all have the 0x1c layout but generate different symbols
and helper bodies. Before choosing template arguments, collect:

- constructor block-size argument;
- element stride in `NewNode`, serialization, and iteration;
- whether destruction invokes element destructors;
- whether serialization is bulk bytes, pointer serialization, or element-wise;
- the decorated template name in the original or recomp PDB;
- vtable slot-0 identity;
- ALL distinct original vtable addresses attributed to the instantiation.

Do not settle for `CList<void*, void*>` merely because the size is 0x1c.
VC5 instantiates inline template member functions aggressively — including
functions not directly called — so element types may need to be complete at
instantiation (the registry header includes the full TView definition because
instantiation reaches `DestructElements`).

## Inline call-shape mismatches (separate, site-local problem)

`list.AddTail(v)` / `list.RemoveTail()` may be a direct out-of-line COMDAT call
in the original but inline in the recomp (or vice versa). `/Ob1` permits but does
not force a stable per-site decision. Policy:

- use the normal public MFC API by default;
- add a wrapper only for an identified high-impact call-shape mismatch;
- mark it as a code-generation adapter, not the semantic collection API;
- never use a wrapper to construct, destroy, or hide the member;
- measure the whole affected TU (inlining shifts register allocation and frame
  layout far beyond the call site).

## Classification Workflow

1. Inspect the suspect vtable and extent:

```sh
just ghidra vtable-dump Name 0xVFTABLE
uv run python -m tools.ghidra.vtable_slots Name=0xVFTABLE:8
uv run python -m tools.ghidra.vtable_extent 0xVFTABLE 80
uv run python -m tools.ghidra.xrefs_to 0xVFTABLE
```

2. Compare against the real MFC concrete class vtables when relevant:

```sh
uv run python -m tools.ghidra.vtable_slots CPtrList=0x00672eec:5 CObList=0x00672ecc:5 CObArray=0x00672eac:5 Candidate=0xVFTABLE:5
```

Use the repo's current evidence if addresses drift, but keep the comparison shape:
slot 0 should tell you whether the candidate has its own runtime-class getter or
inherits `CObject::GetRuntimeClass` unchanged.

3. Read constructor/destructor listings around every xref:

```sh
just ghidra listing 0xCTOR 0xEND
just ghidra listing 0xDTOR 0xEND
```

Look for the collection subobject offset, vptr writes, `m_pNodeHead`,
`m_pNodeTail`, count, free-list, block-size, and `CPlex` chain cleanup.

## Decision Table

| Evidence | Model |
| --- | --- |
| Vtable slot 0 is concrete `CPtrList::GetRuntimeClass` / `CObList::GetRuntimeClass`, and RTTI ancestry says concrete class -> `CObject` | Use the concrete MFC class (`CPtrList`, `CObList`, `CObArray`) as the field/base. |
| Vtable slot 0 is inherited `CObject::GetRuntimeClass`, no derived `CRuntimeClass`, but layout and functions match `CList`/`CTypedPtrList` | Model it as an MFC template member such as `CList<void*, void*>`, not as a standalone recovered game class. |
| Constructor writes a secondary collection vptr at `this + offset`, then primary owner vptr later | This is an embedded subobject. Put the collection field at that offset in the owner layout. |
| Only Ghidra invented a class name for the vtable | Treat the name as provisional. Do not create a class from the name alone. |

## Source Modeling Rules

- Prefer the real MFC public API in already-ported code:
  `AddHead`, `AddTail`, `Find`, `RemoveAt`, `RemoveAll`, `IsEmpty`,
  `GetHeadPosition`, `GetNext`, `GetPrev`, `GetAt`, `GetCount`.
- Do not walk `CList`/`CPtrList` protected nodes in manual gameplay code just to
  preserve a decompiler shape. Public inline accessors usually compile to the same
  node loads in MSVC500 release builds.
- Do not hand-write a fake `EmbeddedList` class just because an embedded template
  specialization has a vtable symbol.
- Do not hand-write scalar deleting destructors or serialize helpers for an MFC
  template specialization. Let MSVC instantiate them from the real member type
  unless there is concrete evidence that the game owns a real class.
- Keep the field name semantic and owner-local, e.g. `trackedEntries`, with a
  comment for the subobject offset/vtable when it helps later audits.
- Include `<afxtempl.h>` for `CList`/`CTypedPtrList` template fields; include the
  repo MFC header for concrete MFC types.

Example owner field:

```cpp
TView* activeView;                  // 0x20
int screenModeAt24;                 // 0x24
int field28;                        // 0x28
CList<void*, void*> trackedEntries; // 0x2c, vtable 0x00648ca8
```

Example public-API loop:

```cpp
POSITION pos = trackedEntries.GetHeadPosition();
while (pos != 0) {
  void* entry = trackedEntries.GetNext(pos);
  // Dispatch to the recovered receiver API or existing bridge.
}
```

## Verification

After changing a collection model:

1. Run `just build`.
2. Run targeted `just compare 0xADDR...` for the owner ctor/dtor and list users.
3. If marker ownership changed, run `just build` (stubs regenerate inside it).
4. Run `just gates` before committing. If an unrelated global gate is already
   failing, record the exact failing gate and keep the collection diff scoped.

Good evidence should explain both the type choice and why alternatives were
rejected, especially `CPtrList` vs `CList<void*, void*>`.

## Field notes

Accumulated collection/MFC matching lessons live in `heuristics.md` next to this
file — template facades (TLongintList), CMap embedded tables, dialog families,
GDI OnPaint, stretch<T> vs CArray discrimination, inline-wrapper COMDAT traps.
