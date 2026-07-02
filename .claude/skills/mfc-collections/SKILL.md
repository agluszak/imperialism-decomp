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

## Classification Workflow

1. Inspect the suspect vtable and extent:

```sh
just ghidra-vtable-dump Name 0xVFTABLE
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
just ghidra-listing 0xCTOR 0xEND
just ghidra-listing 0xDTOR 0xEND
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
3. If marker ownership changed, run `just regen-stubs && just build`.
4. Run `just gates` before committing. If an unrelated global gate is already
   failing, record the exact failing gate and keep the collection diff scoped.

Good evidence should explain both the type choice and why alternatives were
rejected, especially `CPtrList` vs `CList<void*, void*>`.
