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
| L3 | `TIndexAndRankList` manifest ancestry | Header says `TIndexAndRankList : CPtrArray`; `config/classes/TIndexAndRankList.yml` says `base: TSortedPtrList`. | Pending | Fix the manifest generation source/curated base so `TIndexAndRankList -> CPtrArray -> CObject`; then regenerate affected headers. |
| L4 | `TSortedPtrList` / `TPtrList` manifest crossing | Header says `TSortedPtrList` vtable `0x00649068` and base `TIndexAndRankList`; manifests assign `0x00649010` to `TSortedPtrList` and `0x00649068` to `TPtrList`. | Pending | Re-audit constructor writes for `0x00488400`, `0x004884c0`, `0x00488510`, and `0x004888f0`; fix manifests after the owning vtables are separated. |
| L5 | `TList` / `TSortedList` base edge | Headers model both leaves as `TPtrList` wrappers; `TList.yml` says `base: TSortedList`. | Pending | Verify CRuntimeClass `m_pBaseClass` versus ctor sequencing; update either headers or manifests based on structural evidence. |
| L6 | `ProvinceCollectionVirtualShape` local facade | `TCivDescription.cpp` declares a local virtual shape whose slots line up with `TIndexAndRankList` list-operation slots. | Pending | Replace the local facade with the real recovered list-family class once L3/L4 are stable. |
| L7 | `CIterator` raw node cursor | `CIterator` reads the embedded `CPtrList` head from `TPtrList + 8`. | Pending | Keep as a deliberate cursor if compare requires it; otherwise test public `CPtrList`/`TPtrList` API codegen after the list hierarchy is stable. |

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
