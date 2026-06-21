# MFC Collection/List Recovery Plan

This tracks the list-family inconsistencies found while replacing the old
`ApplicationUiRootEmbeddedList` scaffold with `TApplication::trackedEntries`
(`CList<void*, void*>`). The common failure mode is trusting Ghidra-adjacent names
or vtable overreads instead of constructor writes, RTTI chains, and MFC collection
layout evidence.

## Current Findings

| ID | Surface | Evidence | Status | Fix |
| --- | --- | --- | --- | --- |
| L1 | `TApplication::trackedEntries` embedded vtable `0x00648ca8` | Vtable slot 0 inherits `CObject::GetRuntimeClass`; no derived `CRuntimeClass`; ctor writes subobject vptr at `TApplication + 0x2c`; public `CList<void*, void*>` API matches the insert/remove body. | Fixed | Source is `CList<void*, void*>`; stale symbol rows now use `TApplication::trackedEntries` instead of fake standalone `EmbeddedList` identity. |
| L2 | MFC array vtable `0x00672eac` | `config/symbols.csv` labeled it `TIndexAndRankList::'vftable'`, but `TIndexAndRankList` source/manifest vtable is `0x00659c58`; `0x00672eac` sits next to `CPtrArray::classRuntimeClass` and the retail MFC array functions. | Fixed | Global symbol renamed to `CPtrArray::'vftable'`; it is no longer used as the game `TIndexAndRankList` identity in `symbols.csv`. |
| L3 | `TIndexAndRankList` manifest ancestry | Header says `TIndexAndRankList : CPtrArray`; `config/classes/TIndexAndRankList.yml` says `base: TSortedPtrList`. | Won't-fix (manifest) | Ground truth: ctor (via 0x00488400 family) writes a CPtrArray-derived (size 0x18) vtable; header `TIndexAndRankList : CPtrArray` is the source of truth. The `config/classes/*.yml` manifests are generated reference only and are not reconciled — source headers win. |
| L4 | `TSortedPtrList` / `TPtrList` vtable crossing | Two distinct Family-1 (CPtrArray, size 0x18) classes: vtable `0x00649010` and `0x00649068`. | Fixed | Ground truth from ctor vtable writes + RTTI: `0x00488400` writes `0x00649068` (GetRuntimeClass `0x00488510` → RTTI `0x00648eb0`); the sibling `0x00649010` has dtor `0x00488390`, GetRuntimeClass `0x004883e0` → RTTI `0x00648e98`. `symbols.csv` had named BOTH scalar dtors (`0x00488390`, `0x004884c0`) `TSortedPtrList`, mispairing our `~` to `0x00488390`. De-duplicated `0x00488390` → `TSortedPtrListSibling_649010`; source class (VTABLE `0x00649068`) now matches 100%. |
| L5 | `TList` / `TSortedList` base edge + missing base slots | `TList`/`TSortedList` are siblings; their shared in-construction base vtable is `0x006485c0`. Source base `TPtrList` was missing virtual slots `0x64-0x78`. | Fixed | Ctors `0x00487a90`/`0x00487e50` both write base vtable `0x006485c0` then their own (`0x00648ee0`/`0x00648f78`) — siblings, no `TList`↔`TSortedList` edge. Added the 6 missing base virtuals (`VirtualSlot64..78`) to `TPtrList`; this fixed derived `TArmyStackList`/`TTaskList` vtables (their new/override virtuals had been landing in the wrong slot). |
| L6 | `ProvinceCollectionVirtualShape` local facade | `TCivDescription.cpp` declared a local virtual shape. | Fixed | Facade no longer present in source. |
| L7 | `CIterator` raw node cursor | `CIterator` reads the embedded `CPtrList` head from `TPtrList + 8`. | Accepted | Kept as a deliberate cursor (`include/game/CIterator.h`); needed for compare. |

## Fix Order

1. **Symbol identity cleanup:** fix stale `symbols.csv` rows for L1/L2. This is low
   risk and prevents future audits from rediscovering fake class identities.
2. **Manifest source cleanup:** repair the list-family base/vtable facts in
   `config/classes/*.yml` or the Ghidra labels feeding them, then run the class
   generator only for the affected list classes.
3. **Source model cleanup:** after manifests agree with headers, replace local
   list facades such as `ProvinceCollectionVirtualShape`.
4. **Codegen cleanup:** only after the class model is stable, revisit raw node
   cursor code (`CIterator`) and compare public API alternatives.

## Evidence Commands

Use the wrappers where possible; run Ghidra commands serially because the project
lock is exclusive.

```sh
just ghidra-vtable-dump TApplicationTrackedEntries 0x00648ca8
just ghidra-vtable-dump CPtrArray 0x00672eac
just ghidra-vtable-dump TIndexAndRankList 0x00659c58
just ghidra-vtable-dump TSortedPtrList 0x00649068
just ghidra-listing 0x00488400 0x00488530
just ghidra-listing 0x00534870 0x005348f0
```

Acceptance for each fix is `just build` plus the relevant narrow gate
(`just synthetic-gate`, `just vtable-collision-gate`, or `just manifest-gate`
when touching class manifests). Full `just gates` is currently known to fail on
broad generated-decls drift unrelated to this list audit.
