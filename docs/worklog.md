# Worklog

## 2026-06-06

### TGreatPower/TAutoGreatPower class split and vtable-grounded slot 0x20 pass

1. Promoted the misbucketed base vtable slot `0x20`:
   - `TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals` now owns body `0x004DDC30`.
   - Slot evidence: base vtable entry `0x00407392 -> 0x004DDC30`, TAuto override entry `0x00409971`.
   - Body evidence from Ghidra: self-vtable calls at byte offsets `0x38` and `0x198`, field writes at `+0x198`, `+0x840`, `+0x844`, `+0x910`.
2. Split class declarations out of `TGreatPower.cpp`:
   - Added `include/game/TGreatPower.h` for the base virtual skeleton and current field layout.
   - Added `include/game/TAutoGreatPower.h` and `src/game/TAutoGreatPower.cpp` for the derived class substrate.
   - Added `src/game/TAutoGreatPower.cpp` to `CMakeLists.txt`.
3. Seeded `TAutoGreatPower` with small, connected bodies:
   - `0x004E6B30` `GetTAutoGreatPowerClassNamePointer`.
   - `0x004E6B50` `ConstructTAutoGreatPowerBaseState`.
   - `0x004E7810` `RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix`.
   - `0x004E7BE0` `ReplayQueuedDiplomacyProposalRowsAndProcessQueue`.
4. Added read-only Ghidra helper:
   - `tools/ghidra/function_slice.py` plus `just ghidra-function-slice`.
   - Emits direct callers/callees, indirect vtable-like calls, likely vptr writes, and memory refs for selected functions.
5. Updated `docs/tgreatpower_vtable_evidence.csv` with missing rows for slots `0x1e`, `0x20`, and `0x59`.
6. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - Compare batch: `0x004DDC30` `63.16%`, `0x004E6B30` `50.00%`, `0x004E6B50` `70.59%`, `0x004E7810` `90.91%`, `0x004E7BE0` `81.63%`.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: passed.
   - `just stats`: aligned unchanged, average similarity `+0.03 pp`.
7. Next high-yield follow-up:
   - Do not tune `0x004DDC30` immediately unless it blocks a caller.
   - Continue TAuto substrate with `0x004E9FF0`/`0x004EA0E0` flag methods and `0x004E8680`/`0x004EAE70`/`0x004EB0D0` once `autoTrackedListB60` list shape is confirmed.

## 2026-06-04

**CArchive::WriteObject (0x006121e1): 51% -> 94.23%** by modeling the object's real
C++ virtuals instead of the vcall_runtime facades. Replaced
`VCall_CObject_GetRuntimeClassSlot0`/`VCall_CObject_SerializeSlot8` with calls
through a real `CObject*` (`pOb->GetRuntimeClass()`, `pOb->Serialize(this)`) and
removed both rows from `config/vtable_slots.csv` (regen-vcall-facades: 127->125
wrappers). This eliminated the facade `xor edx,edx` and let MSVC cache the object
vtable in one register across both virtual calls (`mov ebx,[edi]; call [ebx]; ...
call [ebx+8]`), exactly matching the original. Also restructured the body to the
genuine MFC `WriteObject` shape (three-way `if/else if/else`, first-time path
returns, shared tag-write trailer with the `0x7fff` escape) — that single shape
change was worth 58.82%->94.23%. Remaining 6% is one optimizer-specialized null
block (original reuses `edi`=0 and skips the size `cmp`); not chased.

Corrected `CObject` vtable order to canonical MFC (`GetRuntimeClass`, `~CObject`,
`Serialize`@+0x8, `AssertValid`@+0xc, `Dump`@+0x10); the header had `Serialize` at
+0x10. Proven by WriteObject calling slot +0x8 with `this` as the only arg.
Canaries clean (below_floor=0).

**CArchive::WriteClass (0x0061240d): stub -> 100%** and **CRuntimeClass::Store
(0x00611b7c): newly owned -> 100%.** WriteClass is the MFC class-token serializer
(throw-on-0xFFFF-schema, MapObject, store-map lookup, new-class `0xffff` tag +
`Store` + register, or already-stored handle with the `0x8000`/`0x80000000` class
tag bits). Per repeated user guidance, modeled `Store` as a **real
`CRuntimeClass::Store(CArchive*)` method** (new `CRuntimeClass` class) and call it
as `pClassRef->Store(this)` — NOT a thiscall-as-fastcall cast bridge. Store body:
`lstrlenA` + two chained `WriteWord`s (schema, len) + `WriteBytes(name, (WORD)len)`;
needed `#pragma optimize("ys")` (FPO+favor-size) and a `(unsigned short)` cast (not
`& 0xffff`, which emits `and` instead of `movzx`) to reach 100%. Owned via marker +
`sync-ownership`/`regen-stubs`; added `src/game/CRuntimeClass.{h,cpp}` to CMake.
Strengthened the AGENTS.md calling-convention guardrail (Ghidra callconvs are
unreliable; model real classes/virtuals; the `vcall_runtime` facade layer is legacy
to be removed).

## 2026-06-03

### TStream family — TFileStream byte wrappers + THandleStream extent advance

Depth pass on the stream serialization cluster. Ported three previously-stubbed
functions out of `src/autogen/stubs` into `src/game/stream.cpp` (markers added,
`just sync-ownership` → `just regen-stubs` → `just build`):

- `TFileStream::ReadBytesFromBackingArchive` (`0x00489220`) → **100.00%**.
- `TFileStream::WriteBytesToBackingArchive` (`0x00489290`) → **100.00%**.
- `THandleStream::AdvanceExtent` (`0x00489550`) → **100.00%**.

Matching notes:
- The two byte wrappers guard on the backing pointer with the game nil-pointer
  assert: `MessageBoxA(0, "Nil Pointer", "Failure", 0x30)` then
  `thunk_TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\McAppStream.cpp", line)`
  (read line `0x3cc`, write line `0x410`). Modeled as a `static __inline
  FailNilPointer(int line)`.
- Two codegen levers were decisive: (1) declare `MessageBoxA` as
  `__declspec(dllimport)` so the call is the indirect import form, and (2) use raw
  string literals (not named `const char[]` arrays) so they pool to the original
  STRING addresses — string pooling is enabled in the match build.
- Backing archive access inlined via `static __inline CArchive*` reading `*(+4)`.
- `THandleStream` field `directionOrMode`→`currentExtent` (behavior-derived: advanced
  by delta, bounded by `highWatermark`). Names remain provisional.

Canaries: 0 below floor (no regression).

Then: `0x00489070` (calls vtable slots `0x1e`/`0x22` — needs facade registration).

### TNetMgr↔CArchive reconciliation + TFileStream object wrappers

The autogen's provisional `TNetMgr` class is the same class as our `CArchive` (its
`ReadBytes`/`WriteBytes` already own `0x611d26`/`0x611e34` as CArchive methods). The
two object-serialization callees belong to it too:

- `CArchive::WriteObject` (`0x006121e1`, autogen `TNetMgr::WriteObject`)
- `CArchive::ReadObject` (`0x0061225e`, autogen models it as a *free* `ReadObject`).

Owned both as real `CArchive` members in `CArchive.cpp` (declared in `CArchive.h`),
with TODO bodies — the internal handle-map/class-token machinery (MapObject,
WriteClass, CheckCount, NodeScanner::ReadClass, CreateObject, InsertAt, vtable
slot-2 dispatch) is not yet ported. With real members in place, the wrappers match
exactly:

- `TFileStream::ReadObjectFromBackingArchive` (`0x00489300`) → **100.00%** (returns a
  success byte: `char` return so MSVC emits `mov al,1` over the call result, matching
  the original `CONCAT31(result>>8, 1)`).
- `TFileStream::WriteObjectToBackingArchive` (`0x00489330`) → **100.00%**.

Process notes (lessons):
- **No call-conv cast bridges.** A first attempt called the free `ReadObject` via a
  `__fastcall` `reinterpret_cast` bridge — wrong dispatch model, and it tripped
  `just vtable-gate`. Correct fix: model the callee as a real class method.
- `tools/stubgen.py` only emits *free* `undefined4 Name(void)` stubs and cannot
  promote a free function to a member (chunk only includes `decomp_types.h`); a name
  override does not help. Own such methods in the class `.cpp`.
- After several `just build`/`regen-stubs` cycles, `compare-canaries` reported
  `parse_error` for all rows — stale `build-msvc500/reccmp-build.yml`. `just detect`
  refreshes it. Canaries then clean (0 below floor).

Deferred: `0x00489070` (vtable slots `0x1e`/`0x22` — facade registration), and the
full bodies of `CArchive::WriteObject`/`ReadObject`.

### Split stream.{h,cpp} into per-class files (rule 7)

Replaced the combined `include/game/stream.h` + `src/game/stream.cpp` with per-class
files:

- `TStream.h` (base), `TFileStream.{h,cpp}`, `TCountingStream.{h,cpp}`,
  `THandleStream.{h,cpp}`.
- Per-class descriptor globals (`g_pClassDescT*`) and helpers (`FailNilPointer`,
  `BackingArchive`) moved into the owning class's `.cpp` (only `TFileStream` uses the
  assert/archive helpers). CMake updated; `stream.cpp`/`stream.h` removed.
- Gotcha: `override` is a `compat.h` macro under MSVC500, so every stream header
  needs `#include "compat.h"`.

`just sync-ownership` reattributed 16 markers to the new files. All 15 stream
functions remain **100%**; vtable gate passes; canaries clean.

### Foundation/list g_vtbl cleanup (real vtables, not manual writes)

Followed the stream-class recipe (commit f6a0588) to replace the manual
`*(void**)this = &g_vtbl<Class>` ctor writes with compiler-emitted vtables. The
**critical** step is deleting the `<addr>|g_vtbl<Class>||global|` DATA row from
`config/symbols.csv` so the `// VTABLE:` annotation owns the address; otherwise
reccmp flags the recompiled `Class::`vftable' (VTABLE)` against the original's
`g_vtbl<Class> (DATA)` and the ctor drops (~90.91%). (Earlier I wrongly concluded
this couldn't be done — the cleanup works and even fixes broken ctors.)

Cleaned (manual write + C++ global + symbols row removed):
- `CPtrList::CPtrList` (`0x00601f1d`) — **100%** (family 0x00601f40/5c/7c/af all 100%).
- `TIndexAndRankList::TIndexAndRankList` (`0x00601baa`) — **13.33% -> 100%**. Required
  inlining the base: moved `CPtrArray::CPtrArray` into `CPtrArray.h` as a header inline
  (its field-zero order `entries/growBy/capacity/count` = the original's
  `+4/+0x10/+0xc/+8`), so MSVC emits one vtable write + inlined zeroes instead of a
  `CPtrArray::CPtrArray` call.
- `TSortByPriceList::TSortByPriceList` (`0x00534710`) — converted the `Construct*` flat
  method into a real ctor; **100%** (factory `0x00534680` `new` site stays 100%).
- `TSortedPtrList::TSortedPtrList` (`0x00649068`) — inline ctor cleaned; **100%**
  (factory `0x00488400` and the relationship-list sites stay 100%).

Left manual (cannot convert):
- `TSortedByRelationshipList` (`0x00654d38`) — its `ConstructObArrayWithVtable654D38`
  (`0x004ee540`) deliberately calls the **grandparent** `TIndexAndRankList` ctor,
  skipping `TSortedPtrList`, and is thunk-called from `TGreatPower`. A real ctor can't
  skip a base or be taken by address, so it keeps the manual write + DATA symbols row.

Plus the dozens of UI classes using the raw `obj->vftable = &g_vtbl*` field pattern are
a separate, larger slice (left untouched). Canaries unchanged (0 below floor); vtable
gate passes. Heuristic note 86 records the full recipe and the two non-convertible
cases.

### TFileStream::WriteLengthPrefixedCString (0x00489070) — last stream fn

Serializes a length-prefixed C-string: write the length through virtual slot 0x22
(byte 0x88), then the bytes through slot 0x1e (byte 0x78). Registered two clean
`thiscall|none` write-slot facades in `config/vtable_slots.csv`
(`VCall_Stream_WriteCountSlot88`, `VCall_Stream_WriteBytesSlot78`) +
`just gen-vcall-facades`. Decisive: the original computes the length with `repne
scasb` (MSVC intrinsic `strlen`), not a hand loop — declaring `strlen` + `#pragma
intrinsic(strlen)` and calling it produced the exact `repne scasb` and let the vtable
load cache into a register across both slot calls. **28.57% (hand loop) -> 100%**.
The whole `TFileStream` is now ported and 100%.

## 2026-06-02

### TSortedByRelationshipList and TSortByPriceList alignment

1. **TSortedByRelationshipList alignment**:
   - Inlined `TSortedByRelationshipList` constructor in [TSortedByRelationshipList.h](file:///home/agluszak/code/decomp/imperialism-decomp/include/game/TSortedByRelationshipList.h).
   - Promoted `CreateTSortedByRelationshipListInstance` (`0x004ee4b0`) to **100.00%** match.
   - Refactored `ConstructObArrayWithVtable654D38` (`0x004ee540`) to use the C++ qualified constructor call `this->TIndexAndRankList::TIndexAndRankList()` to avoid the placement `new` null-check, achieving **100.00%** match.
   - Aligned `DestructTSortedByRelationshipListAndMaybeFree` (`0x004ee570`) to **90.91%** match (with only incremental link thunk call-pairing residual remaining).
2. **TSortByPriceList alignment**:
   - Created [TSortByPriceList.h](file:///home/agluszak/code/decomp/imperialism-decomp/include/game/TSortByPriceList.h) and [TSortByPriceList.cpp](file:///home/agluszak/code/decomp/imperialism-decomp/src/game/TSortByPriceList.cpp) and integrated into the CMake build.
   - Added class vtable `0x00659ef0` (registered in [symbols.csv](file:///home/agluszak/code/decomp/imperialism-decomp/config/symbols.csv)) and `// VTABLE: IMPERIALISM 0x00659ef0` annotation.
   - Mapped and fully aligned all 6 functions:
     - `AllocateAndConstructTSortByPriceList` (`0x00534680`) to **100.00%** match.
     - `GetTSortByPriceListClassNamePointer` (`0x005346f0`) to **100.00%** match.
     - `ConstructTSortByPriceList` (`0x00534710`) to **100.00%** match (using the qualified constructor call).
     - `DeletingDestructTSortByPriceList` (`0x00534740`) to **90.91%** match (call-pairing thunk residual).
     - `DestructTSortByPriceList` (`0x00534770`) to **100.00%** match.
     - `CompareSortByPriceListEntriesByField2Ascending` (`0x005347b0`) to **100.00%** match (using `__stdcall` calling convention and inverted comparison condition to leverage compiler optimization pattern).
3. **VTABLE annotations audit**:
   - Added missing `// VTABLE:` annotations for `TSortedList` (`0x00648ee0`), `TSortedPtrList` (`0x00649068`), and `RefCountedObjectBase` (`0x006485c0`) in their respective headers to satisfy PDB metadata annotations.
4. **Outcome**: Cleanly compiled with zero regressions, canaries verified, aligned functions count improved to 138 (+8 delta).

### Foundational C++ class model cleanup: MFC CPtrArray/CPtrList split and inheritance recovery

1. Renamed MFC-like lowercase files:
   - `include/game/cobject.h` -> `CObject.h`
   - `src/game/cobject.cpp` -> `CObject.cpp`
   - `include/game/carchive.h` -> `CArchive.h`
   - `src/game/carchive.cpp` -> `CArchive.cpp`
   - `include/game/cdocument.h` -> `CDocument.h`
   - `src/game/cdocument.cpp` -> `CDocument.cpp`
2. Extracted the MFC `CPtrList` engine from `TPtrList.h` / `TPtrList.cpp` to `include/game/CPtrList.h` and `src/game/CPtrList.cpp`. Restored standard MFC names (`RemoveTail`, `InsertBefore`, `InsertAfter`, `RemoveAt`).
3. Extracted the MFC `CPtrArray` engine from `TIndexAndRankList.h` / `TIndexAndRankList.cpp` to `include/game/CPtrArray.h` and `src/game/CPtrArray.cpp`.
4. Recovered clean C++ inheritance and constructors:
   - `TIndexAndRankList` now derives from `CPtrArray` which derives from `CObject`.
   - `TSortedPtrList` now derives from `TIndexAndRankList`.
   - `TPtrList` now uses the extracted `CPtrList`.
   - `TSortedList` now derives from `TPtrList`.
5. Fixed MSVC 5.0 compatibility: removed post-C++98 keywords (`nullptr`, `override`, `static_assert`) and replaced size checks with standard array-size typedef compile checks.
6. Cleaned up duplicate declarations and placement-new patterns in `TGreatPower.cpp` and `diplomacy_state.cpp`.
7. Outcome: Compiles successfully with zero regressions and aligned functions count improved to 130 (+1 delta).

### CDocument::AddView + CObject EH-destructor feasibility

1. `CDocument::AddView` (`0x611810`): appends to the view list via
   `CPtrList::AddTail`, sets `view->m_pDocument` (`+0x3c`), fires the slot-0x70
   notification through a new facade `VCall_CDocument_NotifyViewListChangedSlot70`
   (thiscall, `edx_mode=none` to avoid a spurious `xor edx,edx`). **100% effective**
   (only a behaviorally-irrelevant store reorder).
2. CObject virtual-destructor investigation (requested unlock for the `__EH_prolog`
   `Destruct…BaseState` family):
   - The project already models CObject as `TEventHandler` (`// VTABLE: 0x0066fec4`,
     `virtual ~`) and `TView : TEventHandler` (`// VTABLE: 0x649858`). `TView::~TView`
     (`0x48a9d0`) is a real C++ virtual destructor and **matches 93.33%** with the EH
     frame — so the pattern is supported and works.
   - BLOCKERS for the specific deferred destructors: (a) `__EH_prolog` can only be
     emitted by the C++ compiler from real destructors (no inline asm, rule #1);
     (b) `CObArray`/`CPtrList` need a 4-byte CObject base (data at `+4`) but
     `TEventHandler` is `0x10` bytes and already owns vtable `0x66fec4` — two classes
     can't share that vtable; (c) adding a `virtual ~` to the manual-vtable
     `TIndexAndRankList` would collide with `g_vtblTIndexAndRankList` at `0x672eac`
     and/or shift the vtable slots the matched `0x488110` vcall relies on.
   - Conclusion: matching `0x601bdd`/`0x601f7c`/`0x6109eb` needs a focused migration
     of the manual-vtable list/array hierarchy to the C++ `// VTABLE:` inheritance
     pattern (with a 4-byte CObject base distinct from `TEventHandler`), not an
     incremental edit. Deferred to avoid regressing the ~18 matched manual-vtable
     functions.

### Foundation breadth: CObject RTTI, CString split, CDocument, CArchive

1. CObject/CRuntimeClass RTTI (`src/game/list_utils.cpp`): `IsKindOf` (`0x606fc0`),
   `IsDerivedFrom` (`0x607077`), `AfxDynamicDownCast` (`0x606fd2`) were structurally
   correct but stuck at 27–62%; one `#pragma optimize("ys", on)` took all three to **100%**.
2. CString split (`src/game/string_shared.cpp`): bracketed favor-size+FPO by default with the
   build default restored around the functions that regress badly under it (concat-assign
   wrappers `0x605b21`/`0x605b87`/`0x605bfb`, ref-assign `0x605d0a`). Net big gains
   (`0x605ae0`→100, `0x6059fc`→86, several to 80) with regressors held at baseline. (A
   class-vs-bridges file split was started then postponed at the user's request.)
3. CDocument (`src/game/cdocument.cpp`, new): `DisconnectViews` (`0x610a5f`) — walks the view
   list through the recovered `CPtrList::RemoveHead`, clearing each view's `m_pDocument`
   (`+0x3c`) — and the scalar-deleting destructor wrapper `0x6109cf`, both **100%**. The
   view list is a `CPtrList` at `CDocument+0x28`. EH-framed ctor/base-dtor left stubbed.
4. CArchive (`src/game/carchive.cpp`, new): buffered insertion operators
   `WriteByte/Word/Dword ToSerializedBuffer` (`0x5e6d04`/`0x5e6d27`/`0x5e6d4e`), all **100%**.
   Buffer cursor `m_lpBufCur@0x24`, end `m_lpBufMax@0x28`; flush-on-overrun via `Flush`
   (`0x611ec4`, extern). The buffered `ReadBytes`/`WriteBytes` (`0x611d26`/`0x611e34`) and
   `Flush` remain unowned (vtable dispatch on the file object — need facades).
5. All favor-size; `just compare-canaries` clean throughout; no regressions.

### Foundation port: TStream / TFileStream / TCountingStream / THandleStream

1. Scope: `include/game/stream.h` (new), `src/game/stream.cpp` (new), `CMakeLists.txt`,
   `config/function_ownership.csv`, `src/autogen/stubs/*`.
2. Ported the serialization stream hierarchy wrappers (factory base-state, class-name
   accessor, scalar-deleting destructor, and the CObject vtable-reset `_Impl`s):
   - TFileStream: `GetClassName` (`0x004890f0`), `ConstructBaseState` (`0x00489110`),
     `DestructAndMaybeFree` (`0x00489130`) — all **100%**.
   - TCountingStream: `GetClassName` (`0x004893f0`), `ConstructBaseState` (`0x00489410`),
     `DestructBaseState` (`0x00489470`) — **100%**; `DestructAndMaybeFree` (`0x00489440`)
     **90.91%**.
   - THandleStream: `GetClassName` (`0x004895c0`), `ConstructBaseState` (`0x004895e0`),
     `DestructBaseState` (`0x00489640`) — **100%**; `DestructAndMaybeFree` (`0x00489610`)
     **90.91%**.
3. Notes:
   1. Constructors return `this` (note 61) and install their own vtable; the `_Impl`
      teardowns reset the vptr to the shared CObject runtime vtable
      (`PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4` at `0x0066fec4`,
      already defined in `TCapacityOrder.cpp`).
   2. TFileStream's destructor calls the TObject base teardown thunk
      (`thunk_DestructTObjectAndMaybeFree` `0x00407644`) directly, so it matches 100%.
      The TCounting/THandle destructors route through ILT thunks (`0x00403c1f`→`0x00489470`,
      `0x004058c1`→`0x00489640`); calling the `_Impl` method directly leaves a single
      call-target mismatch (90.91%).
   3. These stream wrappers use favor-speed (`#pragma optimize("y", on)`), unlike the
      favor-size collection engines.
4. Validation: `just build` clean; `just compare-canaries` passed; CPtrList/CObArray family
   unaffected.

### Foundation port: full CPtrList + CObArray engines (favor-size lever)

1. Scope:
   1. `include/game/TPtrList.h`, `src/game/TPtrList.cpp`
   2. `include/game/TIndexAndRankList.h`, `src/game/TIndexAndRankList.cpp`
   3. `config/function_ownership.csv`, `src/autogen/stubs/*`
2. Ported the complete MFC `CPtrList` linked-list engine as real `CPtrListSentinelView`
   methods plus the `CPlex` block helpers: `AllocateAndLinkBlockHead` (`0x00601b74`),
   `FreeLinkedBlockChain` (`0x00601b94`), `RemoveAll` (`0x00601f5c`), `NewNode`
   (`0x00601faf`), `FreeNode` (`0x00602004`), `AddHead` (`0x0060201d`), `AddTail`
   (`0x00602047`), `RemoveHead` (`0x006020b9`), `RemoveTailNodeAndReturnPayload`
   (`0x006020dd`), `InsertNodeBeforeAndSetPayload` (`0x00602101`),
   `InsertNodeAfterAndSetPayload` (`0x00602140`), `RemoveAt_60217d` (`0x0060217d`),
   `Find` (`0x006021d6`). Node layout `{next@0,prev@4,data@8}`.
3. Ported the MFC `CObArray`/`CPtrArray` engine as `TIndexAndRankList` methods:
   `SetSize` (`0x00601c14`), `SetAtGrow` (`0x00601de3`), `InsertAt` (`0x00601e0a`),
   `RemoveAt` (`0x00601e9f`). Array layout `{m_pData@4,m_nSize@8,m_nMaxSize@0xc,m_nGrowBy@0x10}`.
4. KEY LEVER: the original MFC collection code is favor-size, not favor-speed. Setting the
   list engine regions to `#pragma optimize("ys", on)` (FPO + favor-size) took the whole
   CPtrList node family from 29–78% to **100%** in a single flag and lifted the previously
   deferred destructors `0x00601f40` (CPtrList dtor) and `0x00601bc1` (CObArray dtor wrapper)
   from 81.82% to **100%**. The outer `TPtrList` wrappers want favor-speed, so they are
   bracketed `#pragma optimize("yt", on)` and the file switches back to `("ys", on)` for the
   engine. See INSTRUCTIONS notes 65–67.
5. Results: 15 functions at **100%** (`0x00601b74` 100% effective), plus the two destructors
   to 100%. `SetSize` **72.17%** and `InsertAt` **47.62%** carry compiler-internal residuals
   (register allocation + the `(a-b)*4` → `b*0x3fffffff + a` byte-offset fusion); both are
   behaviorally correct and large gains from 0% stubs. `mem*` helpers: `memset` `0x005e9a90`,
   `CopyMemoryPossiblyOverlapping` `0x005e9cf0`, `MoveMemoryOverlapSafe` `0x005e8420`.
6. Validation: `just build` clean; `just compare-canaries` passed (`below_floor=0`,
   `parse_error=0`). No regressions in the previously-100% list/factory family.

### List factory EH-`new` frame recovery + RefCountedObjectBase modeling

1. Scope:
   1. `include/game/RefCountedObjectBase.h` (new)
   2. `include/game/TPtrList.h`
   3. `include/game/TSortedList.h`
   4. `include/game/TSortedPtrList.h`
   5. `include/game/TIndexAndRankList.h`
   6. `src/game/TPtrList.cpp`
   7. `src/game/TSortedList.cpp`
   8. `src/game/TSortedPtrList.cpp`
   9. `src/game/TIndexAndRankList.cpp`
   10. `config/symbols.csv`
2. Constructor return-`this` + vtable-as-data-symbol pass (the recurring MFC ctor shape
   `mov eax,ecx; xor ecx,ecx; ...; mov [eax],<vtbl symbol>`):
   1. `TIndexAndRankList::CPtrArray` (`0x00601baa`): **13.33% -> 100.00%**. Changed return
      type to `TIndexAndRankList*` (return `this`) and referenced `&g_vtblTIndexAndRankList`
      instead of a raw `0x672eac` literal.
   2. `CPtrListSentinelView::CPtrList` (`0x00601f1d`): **9.52% -> 100.00%**. Same return-`this`
      change; corrected the embedded list vtable from the stale `0x672ea4` constant to the
      real `0x672eec` (added `g_vtblCPtrList`).
3. EH-`new` factory frame (the project-wide ~52% factory ceiling: `push -1; push __ehhandler;
   mov fs:[0]` cleanup frame emitted by MSVC for `new T()` with a throwing constructor):
   1. Recipe: give the class an inline `void* operator new(unsigned int){ return
      AllocateWithFallbackHandler(size); }`, an inline `operator delete`, and an inline
      constructor (all in the header so MSVC inlines them at the `new` site), then write the
      factory body as `return new T();`. Out-of-line definitions do NOT inline and score
      worse than the old plain `Allocate + if` body.
   2. `TSortedPtrList::ConstructTSortedPtrListBaseState` (`0x00488400`): **52.63% -> 94.12%**.
      Also converted the installed vtable to the new `g_vtblTSortedPtrList` data symbol
      (`0x649068`). Residual gap is one extra `mov [esi],<C++ vftable>` write that MSVC emits
      because `TSortedPtrList` inherits C++ virtuals from `TIndexAndRankList`; keeping those
      virtuals is what lets the sibling `0x00488110` stay 100% (it caches the vtable in `edi`
      and calls slots `0x1c`/`0x28`), so the 94% is an accepted trade.
   3. `TSortedList::CreateTSortedListInstance` (`0x00487a90`): **51.16% -> 100.00%**.
4. RefCountedObjectBase modeling (closes the `mov byte [esp+0x14],1` EH-state transition):
   1. Added a real `struct RefCountedObjectBase { void* vftable; ctor; ~dtor; }` whose inline
      constructor installs `g_vtblRefCountedObjectBase` (matches the standalone
      `InitializeRefCountedObjectBaseVtable` at `0x00484970`) and whose user-declared
      destructor is non-trivial.
   2. Made `TPtrList : public RefCountedObjectBase` (the `vftable` field now lives in the base;
      layout unchanged: vftable@0, listState@4, size 0x20).
   3. `TSortedList()` no longer writes the base vtable itself — the base ctor does it first,
      then the body runs `listState.CPtrList(10)` and installs the derived vtable. The
      non-trivial base destructor is what makes MSVC emit the post-base EH-state transition,
      taking `0x00487a90` from 90.91% to **100.00%**.
5. Validation:
   1. `just build` clean.
   2. Family scores after pass: `0x00601baa` **100%**, `0x00601f1d` **100%**,
      `0x00487a90` **100%**, `0x00487b10` **100%**, `0x004883e0` **100%**,
      `0x00488110` **100%**, `0x00488160` **100%**, `0x00488510` **100%**,
      `0x00407da6` **100%**, `0x00488400` **94.12%**, `0x00601bc1` **81.82%**,
      `0x00601f40` **81.82%**, `0x004885d0`/`0x004885f0` **80.00%** (unchanged ILT
      call-pairing residual), `0x00409868` **0.00%** (unchanged tail-thunk).
   3. `just compare-canaries`: passed (`below_floor=0`, `parse_error=0`).
6. Notes:
   1. `0x00601f40` residual is a single `pop ecx` (size-opt cdecl arg cleanup) vs our
      `add esp,4`; not worth risking the file's other 100% matches by changing opt level.

### TSortedPtrList / array-backed pointer-list recovery

1. Scope:
   1. `include/game/TPtrList.h`
   2. `include/game/TIndexAndRankList.h`
   2. `include/game/TSortedPtrList.h`
   3. `include/game/TSortedList.h`
   3. `src/game/TPtrList.cpp`
   4. `src/game/TIndexAndRankList.cpp`
   4. `src/game/TSortedPtrList.cpp`
   5. `src/game/TSortedList.cpp`
   6. `src/game/diplomacy_state.cpp`
   7. `CMakeLists.txt`
   8. `config/function_ownership.csv`
   9. `src/autogen/stubs/*`
2. Big picture:
   1. `TPtrList` / `TSortedList` are the linked-list family backed by an embedded `CPtrList` sentinel.
   2. The `0x4881xx` cluster is the array-backed sibling backed by `TIndexAndRankList::CPtrArray` (`0x00601baa`), with pointer storage at `+0x04` and count at `+0x08`.
   3. The `TSortedPtrList` autogen bucket is partially misleading: the helper family is generic pointer-array logic, and at least one nearby factory (`0x00488400`) still writes the generic pointer-list vtable rather than a distinct sorted subclass vtable.
3. Changes:
   1. Added real headers for `TPtrList` and `TSortedPtrList` so the recovered list types are declared explicitly instead of being local ad-hoc structs in `.cpp` files.
   2. Added `TIndexAndRankList` and `TSortedList` headers/translation units so the array-backed base and linked-list sorted owner each have their own manual home.
   3. Renamed `TPtrList`'s embedded `CPtrListSentinelView` fields to the real list-state roles: `headNode`, `tailNode`, `nodeCount`, `freeNodeList`, `blockChain`, `blockSize`.
   4. Replaced the old free `CPtrArray` bridge use in `diplomacy_state.cpp` with the typed `TIndexAndRankList::CPtrArray()` base call.
   5. Promoted `0x00601baa` and `0x00601bc1` into `TIndexAndRankList.cpp`.
   6. Promoted `0x004883e0` / `0x00488400` into `TSortedPtrList.cpp`.
   7. Promoted `0x00487a90` / `0x00487b10` into `TSortedList.cpp`.
   8. Kept the previously promoted `0x00488110`, `0x00488160`, and `0x00407da6` in the same family slice.
4. Validation:
   1. `just sync-ownership`
   2. `just regen-stubs`
   3. `just build`
   4. `just compare 0x00407da6`: **100.00%**
   5. `just compare 0x00409868`: **0.00%**
   6. `just compare 0x00488110`: **100.00%**
   7. `just compare 0x00488160`: **100.00%**
   8. `just compare 0x004883e0`: **100.00%**
   9. `just compare 0x00487b10`: **100.00%**
   10. `just compare 0x00601bc1`: **81.82%**
   11. `just compare 0x00488400`: **52.63%**
   12. `just compare 0x00487a90`: **51.16%**
   13. `just compare 0x00601baa`: **13.33%**
   14. `just compare-canaries`: passed (`below_floor=0`, `parse_error=0`)
5. Notes:
   1. `0x00409868` is a stubborn single-JMP thunk to the now-matched `0x00488160`; MSVC500 still lowers the wrapper to `push/call/ret` instead of a tail jump, even when the helper signature preserves the incoming `ecx`/stack arg shape.
   2. `0x00601baa` / `0x00488400` / `0x00487a90` are now compile-safe typed owners, but they still need a future similarity pass if we want their original EH/factory frame shape exactly.

### TPtrList wrapper recovery and build integration

1. Scope:
   1. `src/game/TPtrList.cpp`
   2. `src/game/TGreatPower.cpp`
   3. `CMakeLists.txt`
   4. `config/function_ownership.csv`
   5. `src/autogen/stubs/*`
2. Changes:
   1. Added `src/game/TPtrList.cpp` to the build so its owned markers stop colliding with generated stubs during compare.
   2. Replaced the incorrect Ghidra `TArmyStack::AddHead` wrappers with a real local `TPtrList` definition plus an embedded `CPtrListSentinelView` layout.
   3. Promoted the embedded list constructor/deleting-destructor helpers into `TPtrList.cpp` so the `TPtrList` wrappers call real member methods instead of casted free-function bridges.
   4. Removed the old `0x00601F1D` manual body from `TGreatPower.cpp` and let ownership/stub sync move the helper ownership to `TPtrList.cpp`.
   5. Enabled file-local FPO for `TPtrList.cpp`; this removed the extra frame-setup noise and restored the original 5-instruction wrapper shape for the two `TPtrList` methods.
3. Validation:
   1. `just sync-ownership`
   2. `just regen-stubs`
   3. `just build`
   4. `just compare 0x00488510`: **100.00%**
   5. `just compare 0x004885d0`: **80.00%**
   6. `just compare 0x004885f0`: **80.00%**
   7. `just compare-canaries`: passed (`below_floor=0`, `parse_error=0`)
4. Notes:
   1. The residual mismatch on `0x004885d0`/`0x004885f0` is now only the paired call target (`<OFFSET1>` in the original vs the current helper symbol in our build); the wrapper bodies themselves now match the original `mov/add/push/call/ret` shape.

## 2026-06-01

### TCityProductionView and TDiplomacyMapView Legend Slice Progress

1. Scope:
   1. `src/game/TCityProductionView.cpp`
   2. `src/game/TDiplomacyMapView.cpp`
2. Changes:
   1. Defined missing global extern arrays `g_apNationStates` and `g_Render_Nation_Header_Value_*` in `TCityProductionView.cpp` to resolve linker LNK2001 errors.
   2. Corrected stub `(void)` signatures and added appropriate `reinterpret_cast` calls on `thunk_DrawCenteredGuideLineOnMapDc`, `thunk_SetQuickDrawTextOriginWithContextOffset`, `GetCurrentLocalEpochSecondsWithTimezoneCache`, and `ConvertEpochSecondsToLocalTmWithDstAdjust`.
   3. Promoted and optimized `TCityProductionViewLayout::RenderNationHeaderDateLabelWithPeriodicRefresh` (`0x004badd0`) to **72.55%** using ternary comparisons `(sVar2_val == 2) ? ... : ...` to trigger the MSVC branchless `sete/neg/sbb` register allocations.
   4. Adjusted `TDiplomacyMapViewLayout::RebuildDiplomacyLegendPaletteMode4AndBlit` (`0x004f64c0`) and `RebuildDiplomacyLegendPaletteMode1AndBlit` (`0x004f6840`) to nest the `ReturnConstantTrueQuickDrawFlag` call and use field-by-field RECT copying to match the compiler's stack frames and instruction selections. Improved scores to **37.74%** and **35.53%** respectively.
3. Validation:
   1. `just build`: passed.
   2. `just compare 0x004badd0`: `72.55%`.
   3. `just compare 0x004f64c0`: `37.74%`.
   4. `just compare 0x004f6840`: `35.53%`.
   5. `just compare-canaries`: passed.
   6. `just stats`: average similarity `3.17%`, aligned functions `102`.


### Mac-guided amount-bar method recovery

1. Scope:
   1. `src/game/TShipAmtBar.cpp`
   2. `src/game/TTraderAmtBar.cpp`
   3. `src/game/TIndustryAmtBar.cpp`
   4. `src/game/TRailAmtBar.cpp`
   5. `src/game/trade_screen.cpp`
   6. `config/symbols.csv`
2. Mac evidence used:
   1. `TShipAmtBar`: `_DefaultConstructor`, `DoPostCreate(TDocument*)`, `DrawAmt`, constructor, `GetClassDescDynamic() const`.
   2. `TTraderAmtBar`: `_DefaultConstructor`, `DoPostCreate(TDocument*)`, `DrawAmt`, `AdjustForZero(short, short)`, constructor, classdesc helpers.
3. Changes:
   1. Introduced provisional `TShipAmtBarState` and `TTraderAmtBarState` typed views for this vertical slice.
   2. Introduced provisional `TIndustryAmtBarState` and `TRailAmtBarState` typed views for sibling lifecycle/name recovery.
   3. Renamed `0x0058ABF0` from `SelectTradeSpecialCommodityAndRecomputeBarLimits(int)` to `TShipAmtBar::DoPostCreate(TDocument*)`.
   4. Renamed `0x0058AF80` from generic nation-gauge update to `TTraderAmtBar::DoPostCreate(TDocument*)`.
   5. Renamed `0x00589260` to `TIndustryAmtBar::DoPostCreate(TDocument*)`.
   6. Renamed `0x0058A020` to `TRailAmtBar::DoPostCreate(TDocument*)`.
   7. Renamed and reshaped `0x0058B070` from `WrapperFor_GetActiveNationId_At0058b070` to `TTraderAmtBar::AdjustForZero(short, short)`.
   8. Renamed the four amount-bar render bodies to sibling `DrawAmt()` methods where Mac evidence lists the method:
      1. `0x00589340`: `TIndustryAmtBar::DrawAmt`
      2. `0x0058A1B0`: `TRailAmtBar::DrawAmt`
      3. `0x0058AC80`: `TShipAmtBar::DrawAmt`
      4. `0x0058B0F0`: `TTraderAmtBar::DrawAmt`
   9. Routed lifecycle completion through `TView::thunk_NoOpUiLifecycleHook` to preserve the observed member-call shape.
4. Validation:
   1. `just build`: passed.
   2. `just detect`: passed.
   3. `just compare 0x0058abf0`: `93.33%`.
   4. `just compare 0x0058af80`: `57.81%` (up from `16.18%` at start of this pass).
   5. `just compare 0x0058b070`: `77.61%` (up from `49.12%` at start of this pass).
   6. `just compare 0x00589260`: `61.26%` (up from `44.90%` at start of this pass).
   7. `just compare 0x0058a020`: `46.23%` (up from `37.96%` at start of this pass).
   8. `just compare 0x00589340`: `31.21%`.
   9. `just compare 0x0058ac80`: `25.68%`.
   10. `just compare 0x0058b0f0`: `13.70%`.
   11. `just compare-canaries`: passed, `below_floor=0`, `parse_error=0`.
   12. `just stats`: aligned functions `100`, average similarity `3.06%`.
5. Lesson:
   1. For Mac-guided class slices, first test true method signatures and stack args; this can reveal the correct virtual/lifecycle role before any inheritance decision.

### Mac CodeWarrior evidence integration

1. Added persistent Mac evidence tooling:
   1. `tools/workflow/macos_evidence.py`
   2. `just mac-evidence`
   3. `just mac-evidence-check`
2. Evidence workspace is outside git at `/home/agluszak/code/decomp/imperialism_knowledge/macos_codewarrior`.
3. Extended `slice_discovery.py` so `class_candidate.json` includes `external_evidence.macos_codewarrior` when persistent Mac evidence has been generated.
4. Evidence policy:
   1. Mac CodeWarrior symbols guide class names, method names, and likely signatures.
   2. Windows Ghidra/vptr/vtable/reccmp evidence remains authoritative for addresses, calling conventions, vtable slots, and inheritance.
5. Generated and validated persistent evidence:
   1. `just mac-evidence`: `classes=524`, `symbols=6758`, output `/home/agluszak/code/decomp/imperialism_knowledge/macos_codewarrior/evidence`.
   2. `just mac-evidence-check`: passed.
6. Verified slice attachment:
   1. `just slice-discovery TGreatPower 0x004dc540`: Mac evidence attached for `TGreatPower` with `170` normalized method records.
   2. Synthetic `Candidate_666998` slice for `0x0058AAA0`/vftable `0x00666998`: Mac evidence attached for `TShipAmtBar` with `5` normalized method records.
7. Verification:
   1. `just tooling-check`: passed.
   2. `uv run python -m compileall tools/workflow/macos_evidence.py tools/workflow/slice_discovery.py`: passed.
   3. `just build`: passed.
   4. `just detect`: passed.
   5. `just compare-canaries`: passed, `below_floor=0`, `parse_error=0`.
   6. `just stats`: average similarity `3.05%`, aligned functions `100`, no metric movement expected from tooling-only changes.

### Class/tooling detour for vertical-slice work

1. Downgraded the sibling knowledge environment through `uv` so the moved checkout can run again:
   1. `jpype1==1.5.2` to satisfy `pyghidra==3.1.0`.
   2. Removed the stale `java-stubs-converted-strings` dependency because it required `jpype1>=1.6.0` and was not imported by the available tooling.
   3. Added a minimal `impk` compatibility entrypoint in `/home/agluszak/code/decomp/imperialism_knowledge` so existing `just class-discovery` can run while replacement local tooling is built.
2. Restored `just class-discovery TGreatPower`:
   1. Output: `/home/agluszak/code/decomp/imperialism_knowledge/tmp_decomp/class_discovery/tgreatpower/summary.json`.
   2. Anchors: `g_pClassDescTGreatPower=0x00653688`, `g_vtblTGreatPower=0x00653938`.
   3. Constructor/vtable evidence still points at `0x004D89F0`/`thunk_ConstructNationStateBase_Vtbl653938`; candidate methods are intentionally conservative under the compatibility shim.
3. Added repo-local vertical-slice tooling:
   1. `tools/workflow/slice_discovery.py`
   2. `just slice-discovery <Class> 0xADDR`
   3. Tool reads local `symbols.csv`, `src/ghidra_autogen/index.csv`, `config/vtable_slots.csv`, and manual source to summarize class anchors, actual function calls, vcall wrappers, and `this` field accesses.
   4. Tool now also emits `class_candidate.json`, a conservative MSVC `ClassCandidate` evidence object with vtable, constructor/destructor, field-access, and virtual-callsite evidence.
4. Ran `just slice-discovery TGreatPower 0x004dc540`:
   1. Output: `tmp_decomp/slice_discovery/tgreatpower_004dc540/summary.md`.
   2. Slice uses one `this` field: `nationSlot`.
   3. Slice uses one true vcall wrapper: `VCall_GreatPower_GetNodeContextSlot40`.
   4. `FindFirstPortZoneContextByNation`, navy score helpers, defend-province score helpers, and allocator calls are global/helper boundaries, not evidence that those objects belong inside `TGreatPower`.
   5. `class_candidate.json` records MSVC ABI, primary vftable `0x00653938`, no typeinfo yet, constructor candidates `0x004016AE` and `0x004D89F0`, lifetime/destructor candidate `0x004D9160`, field access `nationSlot@0x0C`, and virtual callsite slot index `16`.
5. Sampled adjacent target `0x004DC660` with `just slice-discovery TGreatPower 0x004dc660` and `just compare 0x004dc660`:
   1. Current score: `18.63%`.
   2. Slice uses `this->nationSlot`, diplomacy/global map helper boundaries, and shared-string construction/destruction.
   3. Original has SEH/shared-string lifetime shape that the current body does not yet preserve, making this a better next vertical slice than further micro-tuning `0x004DC540`.
6. Added `docs/class_recovery.md` as the current class-recovery operating model:
   1. MSVC ABI only for this binary.
   2. Evidence order: RTTI/COL if present, vftables/vptr writes, secondary vftable offsets, virtual callsites/this adjustments, allocation/field offsets, then names.
   3. No inheritance/class membership from naming alone.
7. Extended `slice_discovery.py` so class labels can be synthetic:
   1. Added `--vtable`, `--classdesc`, and `--name-source`.
   2. Added allocation-size extraction from `AllocateWithFallbackHandler(...)`.
   3. Added vptr-write evidence when the sliced body assigns a `g_vtbl*` symbol.
   4. Example synthetic candidates:
      1. `Candidate_666998` for `0x0058AAA0`, vftable `0x00666998`, allocation size `0x6C`.
      2. `Candidate_666ba0` for `0x0058AE30`, vftable `0x00666BA0`, allocation size `0x68`.
8. Sampled non-`TGreatPower` UI/trade lifetime slices:
   1. `0x0058ABA0` ship amount-bar deleting destructor remained `66.67%`; changing delete flag width did not improve stack-frame shape and was reverted.
   2. `0x0058AF30` trader amount-bar deleting destructor improved `64.00% -> 66.67%` by changing the wrapper from `void` to returning `TradeAmountBarLayout*`, matching original `mov eax, esi`.
   3. Factory vptr writes for `0x0058AAA0` and `0x0058AE30` were reordered to match observed factory construction shape: base constructor, zero short fields, final vptr write. Similarity stayed `42.11%` because missing SEH setup dominates those factory bodies.

### Post-move toolchain recovery and first TGreatPower canary pass

1. Verified host Wine install restored normal compare/stat workflow:
   1. `just compare 0x004de860`: pass, `28.68%`.
   2. `just stats`: pass, aligned functions `92`, average similarity `2.97%`.
   3. `just compare-canaries`: pass, `below_floor=0`, `parse_error=0`.
2. Targeted `0x004DC540` `TGreatPower::CompareMissionScoreVariantsByMode`:
   1. Changed the method from `void` to `char` return so the original `AL` success/fallthrough shape is represented and score comparisons are not optimized away.
   2. Corrected `FindFirstPortZoneContextByNation` callsite to pass `this->nationSlot` through a typed cdecl cast, matching the pushed scalar argument visible before the thunk call.
   3. Removed non-original null fallback paths around the port-zone vector dereference.
3. Result:
   1. `0x004DC540`: `43.06% -> 69.77%`.
   2. `just compare-canaries`: pass; `0x004DC540` now stretch-met.
   3. `just stats`: average similarity `2.98%`; aligned functions unchanged at `92`.
4. Rejected one `0x004DBF00` data-pass guess:
   1. Tried remapping stage counter resource buckets from current Ghidra locals.
   2. Score regressed `29.27% -> 22.39%`.
   3. Reverted the change; restored `0x004DBF00` to `29.27%`.

## 2026-03-03

### Class discovery pipeline (read-only)

1. Added `tools/workflow/class_discovery.py`:
   1. Runs class-inference lanes (`infer_class_from_callers`, `infer_class_from_decomp`, `infer_class_from_this_passing`, `infer_class_from_indirect_refs`).
   2. Runs vtable discovery lanes (`scan_windows_static_vtables`, `attribute_vtables_from_slot_func_names`).
   3. Runs `run_windows_class_recovery_wave` without `--apply` and stores all outputs in a class-scoped run dir.
   4. Resolves class anchor addresses (`g_vtbl<Class>`, `g_pClassDesc<Class>`) from `config/symbols.csv`.
   5. Exports:
      1. `candidate_methods.csv` (ranked class-candidate methods)
      2. `vtable_report.csv` (winner/current/reason/anchors)
      3. `constructor_report.csv` (constructor vtable writes from xrefs)
      4. `summary.json` (run metadata and counts)
2. Wired command entrypoint:
   1. `just class-discovery` (defaults to `CLASS_DISCOVERY_CLASSES` from env, fallback `TGreatPower,TAutoGreatPower`).
3. Updated tooling inventory:
   1. `config/tooling_surface.csv` now tracks `tools.workflow.class_discovery`.
4. Updated `.env.example`:
   1. Added `CLASS_DISCOVERY_CLASSES` example variable.

### TGreatPower/TAutoGreatPower vtable mapping lock

1. Resolved ambiguous class/vtable pairing using constructor-write evidence:
   1. `0x00653938` <- `0x004D89F0` (`ConstructNationStateBase_Vtbl653938`) => `TGreatPower`
   2. `0x00654088` <- `0x004E6A70`/`0x004E6B50` (`CreateAutoGreatPowerNationState`/`ConstructTAutoGreatPowerBaseState`) => `TAutoGreatPower`
2. Persisted this as explicit overrides in `config/vtable_annotation_overrides.csv`:
   1. `TGreatPower|653938`
   2. `TAutoGreatPower|654088`

### Tooling surface hardening + prune

1. Added tooling manifest: `config/tooling_surface.csv`.
2. Added validator: `tools/workflow/check_tooling_surface.py`.
3. Added command: `just tooling-check`.
4. Pruned unused scripts not in active workflow surface:
   1. `tools/forensics/check_rich_header.py`
   2. `tools/reccmp/compare_toolchains.py`
   3. `tools/reccmp/flag_sweep.py`
   4. `tools/reccmp/function_shape_stats.py`
   5. `tools/workflow/annotate_orig_callconv.py`
   6. `tools/workflow/decomp_loop.py`
   7. `tools/workflow/split_classes_in_file.py`
5. Trimmed docs to current operational state:
   1. `README.md`
   2. `docs/control_plane.md`
   3. `docs/worklog.md`
   4. `tools/reccmp/README.md`
   5. `docs/toolchain.md`

### Notes

1. `tools/ghidra/SyncExports_Ghidra.py` remains required (runtime dependency of `tools.ghidra.sync_exports`).
2. `tools/reccmp/core_impact_ranking.py` remains required (invoked by `tools.reccmp.session_loop`).

### Validation pass after prune

1. `just tooling-check`: pass.
2. `just build`: pass.
3. `just detect`: pass.
4. `just stats`: pass, unchanged baseline:
   1. aligned functions: `92`
   2. average similarity: `2.88%`
5. `just compare-canaries`: pass (`below_floor=0`).

### TGreatPower similarity pass (manual shape/data edits)

1. Edited `src/game/TGreatPower.cpp` in four target bodies:
   1. `0x004DF010` `ApplyAcceptedDiplomacyProposalCode`
   2. `0x004DE860` `ApplyJoinEmpireMode0GlobalDiplomacyReset`
   3. `0x00541080` `TryDispatchNationActionViaUiThenTurnEvent`
   4. `0x005410F0` `ProcessPendingDiplomacyThenDispatchTurnEvent29A`
2. Added `SharedRefTripleScope` RAII helper to preserve 3-ref init/release envelope shape in `0x004DF010`.
3. Rebuilt and re-detected after each iteration:
   1. `just build`
   2. `just detect`
   3. `just compare 0x004df010`
   4. `just compare 0x004de860`
   5. `just compare 0x00541080`
   6. `just compare 0x005410f0`
4. Result deltas observed in this pass:
   1. `0x004DF010`: `12.27% -> 16.74%` (improved)
   2. `0x004DE860`: `26.83% -> 26.74%` (small regression from null-check removal pass)
   3. `0x00541080`: now `19.51%` after dispatch-gate shape alignment
   4. `0x005410F0`: now `38.46%` after pending-bit clear loop alignment
   5. `0x004EA470`: verified `100%` (already matched)
5. Ran `just session-loop 12 120 1` once for ranking; it auto-mutated `reccmp-project.yml` ignore lists. Restored `reccmp-project.yml` back to `HEAD` content immediately.

### TGreatPower ctor/dtor semantic wrapper experiment

1. Goal: introduce explicit C++ constructor/destructor semantics without changing the known reccmp-mapped init/release addresses.
2. Added semantic wrappers in class API:
   1. `TGreatPower(int arg1, int arg2)` delegates to init path (`0x004D8CC0` body).
   2. `~TGreatPower()` uses non-deleting cleanup body.
3. Kept address-mapped functions as the canonical implementation points:
   1. `0x004D8CC0` `InitializeNationStateRuntimeSubsystems`
   2. `0x004D9160` `ReleaseOwnedGreatPowerObjectsAndDeleteSelf`
4. To avoid delete recursion, factored shared cleanup statements into a macro body reused by:
   1. `~TGreatPower()` (non-deleting cleanup)
   2. `ReleaseOwnedGreatPowerObjectsAndDeleteSelf()` (cleanup + slot01 delete)
5. Validation:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004d8cc0` (`31.98%`)
   5. `just compare 0x004d9160` (`35.51%`)
   6. `just stats` unchanged: aligned `92`, average similarity `2.92%`.

### TGreatPower real-body expansion pass (event/diplomacy paths)

1. Reworked low-fidelity placeholders into fuller GHIDRA-shaped code in `src/game/TGreatPower.cpp`:
   1. `0x004DEFD0` `QueueDiplomacyProposalCodeForTargetNation` now uses a packed short-pair record.
   2. `0x00540AC0` `QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16` now builds explicit packet payload fields before dispatch.
   3. `0x005410F0` `ProcessPendingDiplomacyThenDispatchTurnEvent29A` now uses the major-nation pointer walk (`0x6A4370..0x6A438C`) and thunk queue processing path.
   4. `0x005416B0` `ApplyClientGreatPowerCommand69AndEmitTurnEvent1E` replaced one-line payload queue with full event-packet build/emit flow.
   5. `0x0055C970` `QueueInterNationEventIntoNationBucket` now routes through localization gate flag `+0x7A` and per-event queue slot writes.
   6. `0x0055CBD0` `QueueInterNationEventType0FWithBitmaskMerge` now scans existing queue entries and merges mask by nation bit when possible.
2. Added small typed helpers:
   1. `LocalizationRuntime_ReadGateFlag7A`
   2. `GreatPower_GetInterNationQueueByEventCode`
3. Added missing thunk declarations used by those promoted bodies:
   1. `thunk_SetTimeEmitPacketGameFlowTurnId`
   2. `thunk_CreateAndSendTurnEvent21_ThreeBytes`
4. Validation commands:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004defd0`
   5. `just compare 0x00540ac0`
   6. `just compare 0x00541080`
   7. `just compare 0x005410f0`
   8. `just compare 0x005416b0`
   9. `just compare 0x0055c970`
   10. `just compare 0x0055cbd0`
   11. `just stats`
5. Current key scores from this pass:
   1. `0x004DEFD0`: `40.00%`
   2. `0x00540AC0`: `15.09%`
   3. `0x00541080`: `9.09%`
   4. `0x005410F0`: `43.59%`
   5. `0x005416B0`: `6.56%`
   6. `0x0055C970`: `17.24%`
   7. `0x0055CBD0`: `39.76%`
6. Global snapshot after pass (`just stats`):
   1. aligned functions: `91` (delta `-1`)
   2. average similarity: `2.91%` (delta `-0.01 pp`)

### TGreatPower UI-dispatch ABI correction pass

1. Corrected known `ret 0x10` signature mismatch pair to 4-arg shapes:
   1. `0x004DDBB0` `TryDispatchNationActionViaUiContextOrFallback`
   2. `0x00541080` `TryDispatchNationActionViaUiThenTurnEvent`
2. Replaced failing `__thiscall` local typedefs (MSVC500 C4234) with `__fastcall` bridge casts using explicit `(this, edx, ...)` argument flow.
3. Switched `0x541080` dispatch thunk call from no-arg cast to 4-arg cast to preserve call payload flow.
4. Validation commands:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004ddbb0`
   5. `just compare 0x00541080`
   6. `just stats`
5. Result deltas:
   1. `0x004DDBB0`: `37.36% -> 43.30%`
   2. `0x00541080`: `9.09% -> 50.00%`
6. Global snapshot unchanged after this sub-pass:
   1. aligned functions: `91`
   2. average similarity: `2.92%`

### Vcall facade shape pass + eligibility-thunk alignment

1. Refactored facade generation:
   1. `tools/workflow/generate_vcall_facades.py` now emits direct slot-bound call wrappers (typed function pointer bound to `vcall_runtime::resolve_slot`) instead of routing each call through `vcall_runtime::fastcall*` helper functions.
   2. Regenerated `include/game/generated/vcall_facades.h`.
2. Updated `src/game/TGreatPower.cpp` eligibility helper:
   1. `IsNationSlotEligibleForEventProcessingFast` now loads manager from `kAddrEligibilityManagerPtr` (`0x006A43E0`).
   2. Return type switched to `char` flag shape to better match `AL`-based branches in original code.
3. Validation commands:
   1. `just gen-vcall-facades`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004d8cc0`
   5. `just compare 0x004d92e0`
   6. `just compare 0x004dbf00`
   7. `just compare 0x004de860`
   8. `just compare 0x004df010`
4. Result deltas on active top-impact set:
   1. `0x004D8CC0`: `31.98% -> 31.98%` (no change)
   2. `0x004D92E0`: `30.54% -> 31.09%` (improved)
   3. `0x004DBF00`: `29.14% -> 29.14%` (no change)
   4. `0x004DE860`: `26.74% -> 28.68%` (improved)
   5. `0x004DF010`: `16.74% -> 20.66%` (improved)
5. Guardrail check:
   1. Tried direct raw-vtable calls inside `src/game/TGreatPower.cpp`; `just vtable-gate` correctly failed.
   2. Reverted manual raw-vtable edits and kept improvement path in generated facades + typed helpers.
6. Post-pass sanity:
   1. `just compare-canaries`: pass (`below_floor=0`).
   2. `just stats`: aligned functions `91`, average similarity `2.92%` (global unchanged).

### TGreatPower UI-dispatch call-shape tightening (`0x004DDBB0`)

1. Targeted function:
   1. `0x004DDBB0` `TryDispatchNationActionViaUiContextOrFallback`
2. Change summary in `src/game/TGreatPower.cpp`:
   1. Removed non-original null/function-pointer guards on UI-dispatch branch.
   2. Moved `g_pUiRuntimeContext` load into the taken branch to match original call flow.
   3. Kept fallback dispatch path unchanged (`slot 0x1B0` call shape preserved).
3. Validation loop:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004ddbb0`
   5. `just compare 0x00541080`
   6. `just compare 0x004df010`
   7. `just compare-canaries`
4. Result deltas:
   1. `0x004DDBB0`: `43.30% -> 51.69%` (improved)
   2. `0x00541080`: `50.00% -> 50.00%` (unchanged)
   3. `0x004DF010`: `20.66% -> 20.66%` (unchanged)
5. Guardrails:
   1. `just vtable-gate`: pass (no new raw-vtable baseline violations).
   2. `just compare-canaries`: pass (`below_floor=0`).

### TGreatPower turn-event dispatch ABI correction (`0x00541080`)

1. Targeted function:
   1. `0x00541080` `TryDispatchNationActionViaUiThenTurnEvent`
2. Change summary in `src/game/TGreatPower.cpp`:
   1. Updated `thunk_DispatchTurnEvent1AWithNationActionPayload` callsite to `__stdcall`.
   2. Added prepended nation argument (`this->nationSlot`) so emitted payload order matches the original push sequence.
3. Validation loop:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x00541080`
   5. `just compare 0x004ddbb0`
   6. `just compare-canaries`
4. Result deltas:
   1. `0x00541080`: `50.00% -> 81.48%` (major improvement)
   2. `0x004DDBB0`: `51.69% -> 51.69%` (unchanged)
5. Guardrails:
   1. `just vtable-gate`: pass.
   2. `just compare-canaries`: pass (`below_floor=0`).

### TGreatPower class-shape pass (`1,3,4`: layout guards + typed pointers + explicit pads)

1. Edited `src/game/TGreatPower.cpp`:
   1. Kept unknown member naming explicit (`pad_*`), including `pad_44_ptr`.
   2. Promoted known object members from `void*` to opaque typed pointers (`TListObject*`, `TQueueObject*`, `TMinisterObject*`, `TRelationManagerObject*`).
   3. Added compile-time layout guards for stable core offsets and kept tail offsets as non-fatal probes.
   4. Fixed leftover old-name callsite in `ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries` (`unassignedTrackedList` -> `pad_44_ptr`).
2. Validation:
   1. `just build`: pass.
   2. `just detect`: pass.
   3. `just stats`: pass, unchanged vs immediate pre-pass baseline:
      1. aligned functions: `91`
      2. average similarity: `2.92%`

### TGreatPower targeted score pass (`0x004DE340`, `0x004DD740`, `0x00601F1D`)

1. Scope:
   1. Kept work inside `src/game/TGreatPower.cpp` and `config/vtable_slots.csv`.
   2. Added localization slot facades for slot `0x84`:
      1. `VCall_LocalizationRuntime_CallSlot84`
      2. `VCall_LocalizationRuntime_CallSlot84WithId`
2. `0x004DE340` `SetDiplomacyGrantEntryForTargetAndUpdateTreasury`:
   1. Refined body shape around grant-accept path and shared-ref message dispatch.
   2. Wired localization slot calls through generated facades (instead of ad-hoc casts).
   3. Kept higher-scoring variant after an attempted `__try/__finally` pass regressed.
   4. Delta: `9.62% -> 12.31%`.
3. `0x004DD740` `GetDiplomacyExternalStateB6ByTarget`:
   1. Verbose diff showed original shape uses `ret 4` and reads `this+0x894`.
   2. Changed method to one-arg getter-style signature and used explicit `+0x894` typed offset view.
   3. Delta: `0.00% -> 22.22%`.
4. `0x00601F1D` `CPtrList`:
   1. Tested alternate shape; retained prior variant because newer rewrite regressed.
   2. Current: `9.09%`.
5. Validation loop:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004de340`
   5. `just compare 0x004dd740`
   6. `just compare 0x00601f1d`
   7. `just compare-canaries`
   8. `just stats`
6. Guardrails / snapshot:
   1. `just vtable-gate`: pass.
   2. `just compare-canaries`: pass (`below_floor=0`).
   3. `just stats`: aligned `91`, average similarity `2.93%`.

### TGreatPower iterative body pass (`0x004DB380`, `0x004DAF30`, `0x004DE340`)

1. Scope:
   1. `src/game/TGreatPower.cpp`.
   2. Added one explicit global pointer constant: `kAddrNationInteractionStateManagerPtr = 0x006A43CC`.
   3. Added `TGreatPowerPressureUpdateView` for stable offset-based access in pressure/escalation code.
2. `0x004DB380` `UpdateGreatPowerPressureStateAndDispatchEscalationMessage`:
   1. Replaced prior simplified branch with a shape closer to Ghidra:
      1. weighted base-pressure computation (`slot 0x5F` + `this+0x166/0x168/0x840`),
      2. smoothing update at `+0x8F0`,
      3. tier transitions around `+0x8FC`,
      4. pressure value rise/decay at `+0x8F4`,
      5. final drain equation writing `+0x900`.
   2. Kept localized dispatch path in C++ (no asm/raw slot offsets in gameplay body).
   3. Delta: `12.24% -> 24.38%`.
3. `0x004DAF30` `CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage`:
   1. Replaced previous small payload-only body with a larger ordered-slot scan:
      1. fixed nation priority list,
      2. external-state delta zeroing at `+0xB6 + slot*2`,
      3. manager refresh/call path (`+0x80`, `+0x4C`),
      4. localized dispatch envelope.
   2. Corrected threshold gate to read `+0x8FC` via typed view (not provisional class member offset drift).
   3. Delta: `13.86% -> 13.53%` (small regression accepted for now in exchange for real body extraction).
4. `0x004DE340` safety check:
   1. Tried an alternative shaping pass (char flags + direct matrix indexing + explicit shared-ref locals) that regressed to `7.56%`.
   2. Reverted only that function to the previous better variant.
   3. Final remains: `12.31%`.
5. Validation commands (repeated through the pass):
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just detect`
   4. `just compare 0x004db380`
   5. `just compare 0x004daf30`
   6. `just compare 0x004de340`
   7. `just compare-canaries`
   8. `just stats`
6. Current checkpoint:
   1. `0x004DB380`: `24.38%`
   2. `0x004DAF30`: `13.53%`
   3. `0x004DE340`: `12.31%`
   4. `just compare-canaries`: pass (`below_floor=0`)
   5. `just stats`: aligned functions `91`, average similarity `2.93%`.

### Ghidra refresh from `imperialism_knowledge` + TGreatPower aid-matrix offset fix

1. Source refresh:
   1. Ran `just sync-ghidra` against:
      1. `GHIDRA_PROJECT_DIR=/home/agluszak/code/personal/imperialism_knowledge`
      2. `GHIDRA_PROJECT_NAME=imperialism-decomp`
      3. `GHIDRA_PROGRAM_NAME=Imperialism.exe`
   2. Export result:
      1. functions: `12975`
      2. globals: `9631`
      3. decomp files: `483`
      4. type headers: `18`
2. Repo sync/build:
   1. `just sync-ownership`
   2. `just regen-stubs`
   3. `just build`
   4. `just detect`
   5. `just stats`
3. Targeted function fix:
   1. Address: `0x004DD340` (`TGreatPower::AddAmountToAidAllocationMatrixCellAndTotal`).
   2. Change in `src/game/TGreatPower.cpp`:
      1. switched to explicit offset-based writes for this function:
         1. aid matrix cell at `this + 0x280 + index*4`
         2. aid total at `this + 0x914`
      2. kept class-wide layout untouched (local offset-view strategy).
4. Validation loop:
   1. `just format src/game/TGreatPower.cpp`
   2. `just build`
   3. `just compare 0x004dd340`
   4. `just compare-canaries`
   5. `just stats`
5. Result deltas:
   1. `0x004DD340`: `23.33% -> 30.00%` (improved)
   2. canaries: all floors met (`below_floor=0`)
   3. global aligned count: `91` (unchanged)
   4. global avg similarity: `2.93%` (unchanged)

### Ordered follow-up: TGreatPower/TAutoGreatPower discovery + promoted pair verification

1. Step 1 (lock vtable ambiguity decisions):
   1. Added explicit lock overrides in `config/vtable_annotation_overrides.csv`:
      1. `TAutoGreatPower|654088|locked-by-ctor-writes-004e6a70-and-004e6b50`
      2. `TGreatPower|653938|locked-by-ctor-write-004d89f0`
2. Step 2 (verify promoted pair with full loop):
   1. Commands:
      1. `just detect`
      2. `just compare 0x004b73b0`
      3. `just compare 0x00582630`
      4. `just stats`
   2. Results:
      1. `0x004B73B0` (`CommitCityRecruitmentOrderDelta`): `5.10%`
      2. `0x00582630` (`HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder`): `2.30%`
      3. global checkpoint unchanged: aligned `91`, average similarity `2.93%`
3. Step 3 (tighten class discovery queue):
   1. Updated `tools/workflow/class_discovery.py`:
      1. reads ownership map (`--ownership-csv`, default `config/function_ownership.csv`)
      2. excludes non-autogen/manual-owned addresses from `candidate_methods.csv` by default
      3. keeps opt-out via `--include-owned-candidates`
      4. emits priority bucket column (`priority`: `P0/P1/P2`) based on score/lane density/confidence
      5. writes exclusion count in `summary.json`
   2. Updated `justfile`:
      1. `just class-discovery` now passes `--ownership-csv {{function_ownership}}`
   3. Validation:
      1. `just class-discovery`
      2. output now shows:
         1. excluded owned addresses: `419`
         2. candidate rows saved: `9`
         3. owned candidates filtered out: `4`

### TGreatPower loop: map-context event message functions (`0x004DC660`, `0x004DC840`)

1. Scope:
   1. `src/game/TGreatPower.cpp`
   2. Function focus:
      1. `BuildGreatPowerMapContextTriggeredNationEventMessages` (`0x004DC660`)
      2. `BuildGreatPowerEligibleNationEventMessagesFromLinkedList` (`0x004DC840`)
2. Changes:
   1. Added missing shared-string message construction calls in `0x004DC840` path:
      1. `thunk_AssignSharedStringFromIndexedA8EntryNameField`
      2. `AssignSharedStringConcatCStrAndRef`
      3. `AssignStringSharedFromRef(this_ptr, src_ref_ptr)` using typed local refs
   2. Kept `0x004DC660` at prior shape after a regression attempt:
      1. tested adding extra shared-string assignment calls
      2. reverted those two lines because it lowered score
   3. Added function declarations needed by the `0x004DC840` message path:
      1. `thunk_AssignSharedStringFromIndexedA8EntryNameField`
      2. `AssignSharedStringConcatCStrAndRef`
      3. `AssignStringSharedFromRef(undefined4 this_ptr, int* src_ref_ptr)`
3. Validation commands:
   1. `just build`
   2. `just detect`
   3. `just compare 0x004dc660`
   4. `just compare 0x004dc840`
   5. `just compare-canaries`
   6. `just stats`
4. Result deltas:
   1. `0x004DC660`: `20.00% -> 20.00%` (restored baseline)
   2. `0x004DC840`: `14.39% -> 15.48%` (improved)
   3. canaries: pass (`below_floor=0`)
   4. global checkpoint unchanged: aligned `91`, average similarity `2.93%`

### Shared-string pass: promote missing helpers + compile-safe bodies

1. Scope:
   1. `src/game/string_shared.cpp`
   2. `include/game/string_shared.h`
   3. ownership/stub sync for shared-string addresses
2. Promotions and ownership:
   1. `just promote src/game/string_shared.cpp --address 0x00605B21 --address 0x00605B87 --address 0x00605CF5`
   2. `just promote src/game/string_shared.cpp --address 0x00605BFB`
   3. `just sync-ownership`
   4. `just regen-stubs`
3. Code changes:
   1. Replaced raw GHIDRA promoted blocks with compile-safe implementations for:
      1. `AssignSharedStringConcatRefAndRef` (`0x00605B21`)
      2. `AssignSharedStringConcatRefAndCStr` (`0x00605B87`)
      3. `AssignSharedStringConcatCStrAndRef` (`0x00605BFB`)
      4. `AppendSingleByteToSharedStringFromArg` (`0x00605CF5`)
   2. Improved `ReleaseSharedStringRefIfNotEmpty` (`0x006058E2`) to inline release/decrement/free path.
   3. Added missing shared-string helper declarations in `include/game/string_shared.h`.
   4. Updated `src/game/TGreatPower.cpp` local declaration/callsite for `AssignSharedStringConcatCStrAndRef`.
4. Validation loop:
   1. `just build`
   2. `just detect`
   3. `just compare 0x006058E2`
   4. `just compare 0x00605B21`
   5. `just compare 0x00605B87`
   6. `just compare 0x00605BFB`
   7. `just compare 0x00605CF5`
   8. `just stats`
5. Targeted compare results (moved from zero to non-zero in verbose compare loop):
   1. `0x006058E2`: `27.27%`
   2. `0x00605B21`: `20.51%`
   3. `0x00605B87`: `7.69%`
   4. `0x00605BFB`: `22.22%`
   5. `0x00605CF5`: `42.86%`
6. Note:
   1. `just stats` aggregate metrics stayed flat (`aligned=91`, avg similarity `2.94%`).
   2. For this pass, authoritative per-function checkpoints are the targeted `just compare 0xADDR` results above.

### Shared-string field extraction pass (`0x00605B87` focus)

1. Scope:
   1. `src/game/string_shared.cpp`
   2. Target: `AssignSharedStringConcatRefAndCStr` (`0x00605B87`)
2. Changes:
   1. Added typed overlay struct:
      1. `SharedStringRefView { int data_ptr; }`
   2. Replaced raw `*int` ref accesses with field access through `SharedStringRefView` in:
      1. `InitializeSharedStringRefFromEmpty`
      2. `StringSharedRef_AssignFromPtr`
      3. `AssignSharedStringConcatRefAndRef`
      4. `AssignSharedStringConcatRefAndCStr`
      5. `AssignSharedStringConcatCStrAndRef`
   3. Kept `0x00605B87` length load as direct typed overlay read from `(data_ptr - 0x0C)->text_length` to preserve push/load shape.
3. Validation:
   1. `just format src/game/string_shared.cpp`
   2. `just build`
   3. `just compare 0x00605B87`
4. Result:
   1. Intermediate attempt with out-of-line helpers regressed heavily (17.95% / 8.33%) and was removed.
   2. Final field-overlay shape restored the prior checkpoint:
      1. `0x00605B87`: `35.82%`

### UI Amount Bar Class & Destructor Pass

1. Scope:
   - `src/game/TTraderAmtBar.cpp`
   - `src/game/TAmtBar.cpp`
   - `include/game/TEventHandler.h`
   - `config/function_name_overrides.csv`
   - `config/symbols.csv`
2. Changes:
   - Added forward declaration of `thunk_DestructTViewBaseState_0058AF60` in `TTraderAmtBar.cpp` to resolve build error.
   - Discovered that `TView`'s virtual destructor `~TView()` was at 96.67% because the base class `TEventHandler` vtable was unmatched. Added `// VTABLE: IMPERIALISM 0x0066FEC4` to `TEventHandler.h` to register it, bringing `TView::~TView()` (`0x0048a9d0`) to a **100%** match.
   - Identified that `TTraderAmtBar` and `TAmtBar` destructors (`0x0058af30`, `0x005885c0`) call incremental link table (ILT) thunks (`0x004064bf` and `0x00401e65`) in the original binary, which then jump to the actual helpers (`0x0058af60` and `0x005885f0`).
   - Mapped the helper functions in `symbols.csv` to their ILT thunk addresses (`0x004064bf` and `0x00401e65`) and updated the function markers in `TTraderAmtBar.cpp` and `TAmtBar.cpp` accordingly.
   - Added `#pragma optimize("y", on)` at the top of `TAmtBar.cpp` and `TTraderAmtBar.cpp` to enable Frame Pointer Optimization (FPO), matching the original call conventions and offsets.
   - Worked around the MSVC C++ `__thiscall` constraint on free functions by introducing a dummy event handler struct (`DummyEventHandler`) in `TTraderAmtBar.cpp` and calling the thunk using a member function pointer cast. This forced MSVC to pass the pointer in `ecx` (matching `__thiscall`) without generating `xor edx, edx` for the unused `edx` register.
   - Ran `sync_function_ownership` manually with `--prune-missing-manual` to clean up old helper ownerships and regenerated stubs.
3. Validation & Results:
   - Destructors matched perfectly:
     - `DestructTTraderAmtBarMaybeFree` (`0x0058af30`): **100%**
     - `DestructTAmtBarAndMaybeFree` (`0x005885c0`): **100%**
     - `TView::~TView` (`0x0048a9d0`): **100%**
     - `thunk_DestructTViewBaseState_0058AF60` (`0x004064bf`): **100%**
   - Aligned functions count increased by 4 to **95**.
   - Average similarity of compared functions increased to **3.01%**.
   - Canary targets verified and fully passing (`below_floor=0`).

### UI Amount Bar Member Method & Thunk Alignment Pass

1. **Thunk Parameter Cleanups (`TView*`)**:
   - Replaced custom `TradeAmountBarLayout*` types with `TView*` in `thunk_DestructTViewBaseState_0058AF60` and `thunk_DestructTViewBaseState_005885F0` signatures.
   - Updated declarations in `TTraderAmtBar.cpp`, `TAmtBar.cpp`, `symbols.csv`, and `function_name_overrides.csv`.
   - This eliminates compiler-mangled hashes with anonymous namespaces and prevents demangling crashes under Wine, keeping reccmp comparisons cleanly paired.
   - Simplified destructor calls to invoke `amountBar->~TView()` directly instead of using `DummyEventHandler` union hacks.

2. **`UiRuntimeContext::GetActiveNationId` Alignment**:
   - Mapped address `0x00403b16` to a standard member function `short UiRuntimeContext::GetActiveNationId(void)` in `symbols.csv` and `function_name_overrides.csv`.
   - Declared `UiRuntimeContext` struct in `include/game/ui_widget_shared.h` outside of the anonymous namespace, and defined `g_pUiRuntimeContext` with `extern "C"` linkage.
   - Updated `SelectTradeSpecialCommodityAndRecomputeBarLimits` (`0x0058abf0`) in `TShipAmtBar.cpp` to call `g_pUiRuntimeContext->GetActiveNationId()`. This forces MSVC to load `ecx` with the global context pointer before executing the relative call to `0x403b16`, matching the original assembly.
   - Mapped `thunk_NoOpUiLifecycleHook` (`0x00406ba9`) to a member method `TView::thunk_NoOpUiLifecycleHook` to preserve the `__thiscall` calling convention from callers, while maintaining a manual free function wrapper to preserve compiling for other widgets.
   - Registered `0x00406ba9` as manual-owned in `function_ownership.csv` and regenerated stubs to avoid double-definition linker errors.

3. **Validation & Results**:
   - Build is fully clean and all compiles succeed.
   - `SelectTradeSpecialCommodityAndRecomputeBarLimits` similarity rose to **93.33%** (was 87.27%).
   - Aligned functions count is at **100**, average similarity is **3.05%**.
   - Canary targets verified and fully passing (`below_floor=0`).

### QuickDraw Surface RAII Guard + EH-RAII Architecture Pass (2026-06-01)

1. Discovery (Ghidra evidence, via `imperialism_knowledge` pyghidra):
   - The amount-bar `DrawAmt` bodies were low (13-31%) because the original wraps
     them in an **MSVC C++ EH frame** (`push -1; push __ehhandler; mov fs:[0]`)
     around a **local RAII guard object**: a QuickDraw "reusable surface" whose
     thiscall ctor is `AcquireReusableQuickDrawSurface` (`0x00497320`) and thiscall
     dtor is `ReleaseOrCacheQuickDrawSurface` (`0x00497390`). The manual code called
     these as free `(void)` functions, so MSVC emitted no EH frame and no object.
   - Original callsites reach the ctor/dtor/helpers through **ILT thunks**
     (`0x4021c1->0x497320`, `0x409aac->0x497390`, `0x40232e->0x495920`).
   - `ApplyHitRegionToClipState` (`0x00495920`) takes the guard's surface-wrapper
     field as an `int` arg (push of `[esp+8]`).
2. Implementation (`src/game/trade_screen.cpp`):
   - Added `struct QuickDrawSurfaceGuard { int surfaceWrapper; ctor; dtor; };`.
   - Implemented ctor `0x00497320` and dtor `0x00497390` out-of-line (ported from
     Ghidra), owning those addresses (`just sync-ownership` + `regen-stubs`).
   - Added global `g_pReusableQuickDrawSurfaceListHead` (`0x6a1c98`) and
     `kQuickDrawCppPath` ("D:\Ambit\QuickDraw.cpp", assert string at `0x695168`).
   - Converted all 6 callers (4 `DrawAmt` siblings + 2 `RenderQuickDrawOverlay*`)
     from free Acquire/Release calls to a stack `QuickDrawSurfaceGuard surface;`
     plus `ApplyHitRegionToClipState(surface.surfaceWrapper)`; removed the trailing
     `ReleaseOrCacheQuickDrawSurface()` (dtor now runs implicitly => EH frame).
3. Results (targeted `just compare`):
   - NEW (previously 0%/unmatched stubs, now paired+scored): `0x00497320` ctor
     `0.00% -> 62.75%`; `0x00497390` dtor `0.00% -> 74.58%`. Not yet 100%, so the
     `aligned` 100%-match count stays 100; aggregate avg similarity `3.05% -> 3.08%`.
   - `0x00589340` TIndustryAmtBar::DrawAmt `31.21% -> 37.44%`.
   - `0x0058a1b0` TRailAmtBar::DrawAmt    `~25%   -> 33.33%`.
   - `0x0058ac80` TShipAmtBar::DrawAmt    `25.68% -> 40.22%`.
   - `0x0058b0f0` TTraderAmtBar::DrawAmt  `13.70% -> 21.84%`.
   - `just compare-canaries`: `below_floor=0` (no regressions).
4. Negative result: forcing FPO on `DrawAmt` via `#pragma optimize("y", on)`
   *lowered* the score (37.44% -> 33.33%): MSVC then promotes `ebx`/`ebp` as scratch
   (`xor ebx,ebx; cmp esi,ebx`), diverging more than the kept-frame build even though
   the original is FPO with only esi/edi. Reverted. Remaining DrawAmt gap is
   register-allocation / immediate-vs-zero-reg, not structural.
5. Architecture survey (saved to `tmp_decomp/eh_functions.json`):
   - **966** functions in the binary use the MSVC C++ EH prologue.
   - Clustered by the ctor called immediately after the prologue (leading RAII guard):
     - `InitializeSharedStringRefFromEmpty` (`0x605797`): **112** functions.
     - `ConstructSharedStringFromCStrOrResourceId` (`0x605950`): **26**.
     - `AcquireReusableQuickDrawSurface` (`0x497320`): **13** (6 now owned/converted).
     - smaller clusters: dialog-template inits, scoped map QuickDraw context, etc.
   - The shared-string clusters (138 fns) already carry their guard: the `StringShared`
     class has a non-trivial dtor, so those functions ALREADY emit the EH frame; their
     residual gaps are body-level (e.g. original keeps `this` in `esi`, we get `edi`;
     differing format-call signatures), not the structural EH gap. The architectural
     lever applies specifically to acquire/release pairs still modeled as **free
     functions** (QuickDraw was the live instance).

### QuickDrawSurfaceGuard shared + unowned-target survey (2026-06-01, cont.)

1. Refactor (enables cross-TU reuse):
   - Moved `struct QuickDrawSurfaceGuard` to `include/game/ui_widget_shared.h`
     (external linkage); ctor `0x00497320` / dtor `0x00497390` definitions and
     global `g_pReusableQuickDrawSurfaceListHead` (`0x6a1c98`) moved to file scope
     in `trade_screen.cpp` (out of the anonymous namespace).
   - `just build` clean; scores held / improved (ctor `62.75% -> 70.59%` with
     external linkage; DrawAmt unchanged).
2. Surveyed the 13 QuickDraw-guard functions: 6 owned+converted; 7 unowned, each a
   full new decompilation (Ghidra dumps captured). Classified by effort:
   - `0x00588690` `TAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache` (549) —
     set-up class (TAmtBar.cpp, FPO on); needs vtable slot `+0x128` facade + a
     two-pass styled-text block + RECT juggling.
   - `0x00596100` `RenderWrappedMapQuickDrawOverlayFromStridedRecords` (278, cdecl
     free fn) — needs a home file; FPO `unaff_*` regs + 1 unnamed thunk.
   - `0x004bc9b0` `TCityProductionView::RenderViewIntoPrimaryRenderContextWithTemporaryClip`
     (244) — autogen class only; 3 unnamed thunks.
   - `0x004a05c0` `TTransFocusAnimation::BlitTransientSurfaceToPrimaryRenderContextWithClip`
     (336) — NO manual class file; needs class scaffolding.
   - `0x004f6170` `TDiplomacyMapView::RenderDiplomacyLegendSurfaceAndPresent` (563).
   - `0x005d8cc0` `HandleTurnEventVtableSlotA0SyncStatusPanel` (206, cdecl free fn).
   - `0x005921c0` `TTransportPicture::RenderTransportPictureGaugeAndLabels` (1240) —
     largest; defer.
   - Common pattern confirmed: each begins `QuickDrawSurfaceGuard surface;` + the EH
     frame; bodies reuse the established QuickDraw helper vocabulary
     (`ApplyHitRegionToClipState`, `SetQuickDrawTextOriginWithContextOffset` 0x497c80,
     `DrawCenteredGuideLineOnMapDc` 0x497d10, `SetQuickDrawStylePair...` 0x495310,
     `ApplyRectClipRegionToGlobalClipState` 0x495a80, `BlitRectWithOptionalTransparency`,
     `SnapshotHitRegionToClipCache`) over globals `g_pPrimaryRenderSurfaceContext`
     (0x6a30a8), `g_pActiveQuickDrawSurfaceContext` (0x6a1d60).
   - Reusable Ghidra dump helper at `imperialism_knowledge/` scratch
     (`/tmp/dump_fn.py`): decompile + listing for any address list.

### QuickDraw shared-helper vocabulary pass (2026-06-01, cont.)

1. New file `src/game/quickdraw_surface.cpp` (added to CMake; `#pragma optimize("y", on)`
   file-wide because these helpers are FPO in the original). Hosts the shared QuickDraw
   stroke/clip-state primitives called by every UI DrawAmt/Render body.
2. Implemented:
   - `0x00495310` `SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty` (3 global writes) -> **100%**.
     Globals: `g_nQuickDrawStrokeStylePrimary` (0x6a1d08), `g_nQuickDrawStrokeStyleSecondary`
     (0x6a1d0c), `g_bQuickDrawStrokePairDirty` (0x6a1db4).
   - `0x00495a30` `SnapshotHitRegionToClipCache(int* clipDescriptor)` -> 0% -> **37.84%**
     (prologue + branch now match; residual is push scheduling). Global
     `g_pGlobalClipRegionHandleObject` (0x6a1da8); import `CombineRgn`. Aligned trade_screen's
     extern decl to the real `void(int*)` signature (callsites use fn-ptr casts, unaffected).
3. Findings (-> INSTRUCTIONS #38, expanded):
   - FPO is target-dependent: enabling it took the leaf helper 53% -> 100%, but it HURT the
     complex EH-RAII DrawAmt bodies. Decide per function class.
   - Mirror the compiler's pointer-offset reuse (`add eax,0x14` then `[eax+4]`) in C++ to
     avoid recompute drift (25% -> 37.84% on Snapshot).
4. `just stats`: aligned functions (100%) `100 -> 101`; avg similarity `3.08% -> 3.09%`.
   `just compare-canaries`: `below_floor=0`.

### Promote TAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache (2026-06-01, cont.)

1. `0x00588690` `TAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache` (549B) promoted into
   `src/game/TAmtBar.cpp` (FPO on), reusing `QuickDrawSurfaceGuard` and the established
   QuickDraw helper vocabulary: 0% -> **39.73%**.
2. Contract refinements (verified safe — all callers ignore returns / unused slot):
   - `TradeControl::RefreshSlotF8` void -> **char** (+ `Refresh()` returns char); this fn checks
     the slot-0xF8 draw flag directly (`if (IsActionable() && Refresh())`). DrawAmt callers
     use it as a statement -> unchanged (0x589340 37.44%, 0x58ac80 40.22%, 0x58b0f0 21.84%).
   - Renamed unused virtual `CtrlSlot74` (slot 0x128) -> `QueryContentBoundsSlot128(int*)` with
     `QueryContentBounds()` wrapper; slot 0x128 is a distinct bounds-capture used here.
   - Added `kAddrPrimaryRenderSurfaceContext` (0x6a30a8).
3. Known residual gaps (not chased): the original's overlapping-stack RECT aliasing, the
   `CtrlSlot78(&overlayParams)` buffer arg (kept no-arg to avoid changing 6 working callers),
   and `SetQuickDrawFillColor` arg form. Body is structurally faithful otherwise.
4. `just compare-canaries` below_floor=0; avg similarity 3.09% -> 3.10%.

### QuickDraw fill-color primitive + wrapped-map overlay slice (2026-06-01, cont.)

1. Ownership/hygiene:
   - Removed the stale duplicate `0x00588690` marker from `trade_screen.cpp`; the single owned
     implementation is now `TradeAmountBarLayout::RenderPrimarySurfaceOverlayPanelWithClipCache`
     in included `TAmtBar.cpp`.
   - Removed duplicate `0x66fec4` plain-global annotation from `TCapacityOrder.cpp`; the vtable
     annotation remains on `TEventHandler`.
2. Shared helper vocabulary:
   - Implemented `0x00495000` `SetQuickDrawFillColor(int)` in `quickdraw_surface.cpp`.
   - Added globals `g_Quick_Draw_Color_State_006950FC`, `g_uQuickDrawCurrentColor`, and
     `g_pActiveQuickDrawSurfaceContext`.
   - Updated manual callsites in `TAmtBar.cpp`, `TPlacard.cpp`, and `trade_screen.cpp` to pass the
     explicit fill color instead of no-arg casts.
   - Result: `just compare 0x00495000` -> **100%**. Amount-bar canary nudges:
     `0x00588690` **39.73% -> 40.00%**, `0x00589340` **37.44% -> 37.86%**,
     `0x0058a1b0` **33.33% -> 33.82%**; `0x0058ac80` and `0x0058b0f0` held.
3. New QuickDraw guard target:
   - Added `src/game/map_quickdraw_overlay.cpp` and promoted `0x00596100`
     `RenderWrappedMapQuickDrawOverlayFromStridedRecords`.
   - Added generated vcall facades for provisional `WrappedMapOverlayView` slots
     `0x1c0`, `0x1c4`, `0x1cc`, `0x1d0`, and `0x1d4`.
   - Modeled it as a `QuickDrawSurfaceGuard` EH-RAII body with FPO on. Signature is effectively
     thiscall-shaped (`__fastcall` bridge) with one stack arg; the stack arg is a record/context
     pointer and the mode branch reads `arg + 0x24`.
   - Result: `just compare 0x00596100` **0.00% -> 24.44%**. Residual gaps are register allocation
     (`ebp` for computed record, `edi` for vtable) and local layout, not missing architecture.
4. Validation:
   - `just build`: clean.
   - `just detect`: updated recompiled detection.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: aligned functions **102** (`+1`), avg similarity **3.11%**, paired globals
     `+4`, global coverage `+0.04 pp`.

### TTransFocusAnimation scoped QuickDraw slice (2026-06-01, cont.)

1. Added `src/game/TTransFocusAnimation.cpp` and promoted two functions out of stubs:
   - `0x004a05c0` `TTransFocusAnimation::BlitTransientSurfaceToPrimaryRenderContextWithClip`
     -> **29.85%**. This is the transient-surface-to-primary blit path: `QuickDrawSurfaceGuard`,
     hit-region clip state, destination/source RECT setup, palette/fill-color setup,
     y-flip adjustment from `g_pPrimaryRenderSurfaceContext` / `this+0x30`, then
     `BlitRectWithOptionalTransparency`.
   - `0x004a0770` `TTransFocusAnimation::RenderFocusAnimationFrameWithScopedQuickDraw`
     -> **71.19%**. This unlocked a second scoped QuickDraw RAII family using
     `thunk_ConstructScopedMapQuickDrawContext` / `thunk_DestroyScopedMapQuickDrawContext`.
2. Added generated provisional vcall facades:
   - `VCall_FocusAnimationView_RenderSlotF8` for the render target at `this+0x04`.
   - `VCall_TransFocusAnimation_CallSlot2C` for the completion/update callback on the
     `TTransFocusAnimation` object.
3. Layout evidence captured in a local typed view:
   - `this+0x04` is the scoped render target used by the map QuickDraw context and slot `0xf8`.
   - `this+0x1c..0x28` are source bounds.
   - `this+0x30` is the transient surface context used by the blit source.
   These labels remain provisional; do not infer inheritance from the current class name alone.
4. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - `just compare 0x004a05c0`: **29.85%**.
   - `just compare 0x004a0770`: **71.19%**.
   - `just compare 0x00596100`: held at **24.44%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: aligned functions **102**, avg similarity **3.12%**, paired globals **296**
     (`+1`), dropped duplicate addresses **0**.

### Scoped QuickDraw animation sweep (2026-06-01, cont.)

1. Moved `ScopedMapQuickDrawContextGuard` into `include/game/ui_widget_shared.h` so the
   scoped map QuickDraw RAII family is shared across animation/render wrappers instead of
   living only in `TTransFocusAnimation.cpp`.
2. Corrected the guard storage to 24 bytes (`int storage[6]`):
   - `0x004a0770` `TTransFocusAnimation::RenderFocusAnimationFrameWithScopedQuickDraw`
     improved **71.19% -> 84.75%**.
   - The common mismatch was stack size (`sub esp,0x20` / `sub esp,0x28`) rather than call
     ordering.
3. Added `src/game/TFocusAnimation.cpp` and promoted
   `0x004a0190` `TFocusAnimation::DestructTFocusAnimationAndMaybeFree`:
   - Shape: enabled flag at `this+0x2c`, scoped render target at `this+0x04`, render slot
     `0xf8`, self update slot `0x2c`, post-render slot `0xfc`.
   - Result: stub -> **81.69%**.
4. Added `src/game/TOneTimeAnimation.cpp` and promoted
   `0x0049fde0` `TOneTimeAnimation::DestructTOneTimeAnimationAndMaybeFree`:
   - Shape: completion flag at `this+0x2c`, frame tick at `this+0x10`, frame limit at
     `this+0x14`, invalidation/copy rect from `this+0x1c`, render slot `0xf8`, rect apply
     slot `0x110`.
   - Result: stub -> **75.86%**.
5. Added generated provisional vcall facades:
   - `VCall_FocusAnimation_CallSlot2C`
   - `VCall_FocusAnimationView_PostRenderSlotFC`
   - `VCall_FocusAnimationView_ApplyRectSlot110`
6. Naming caveat:
   - Current Ghidra names say `Destruct...AndMaybeFree`, but these bodies behave like
     animation tick/render callbacks. Do not treat the names as lifecycle evidence.
7. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - `just compare 0x004a0190`: **81.69%**.
   - `just compare 0x0049fde0`: **75.86%**.
   - `just compare 0x004a0770`: **84.75%**.
   - `just compare 0x004a05c0`: held at **29.85%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: aligned functions **102**, avg similarity **3.13%**, dropped duplicate
     addresses **0**.

### RECT consolidation + TOneTimeAnimation behavior rename (2026-06-01, cont.)

1. Confirmed `0x0049fde0` is not a real destructor despite the stale Ghidra/export name:
   - no free flag, no base/member teardown, no delete path;
   - advances `this+0x10` frame tick, checks `this+0x14` tick limit, invalidates the
     `this+0x1c` rect, renders via scoped QuickDraw slots, then advances `this+0x08`
     current frame or sets `this+0x2c` complete flag.
2. Renamed the manual implementation to
   `AdvanceOneTimeAnimationFrameAndInvalidateTargetRect`. Kept the `0x0049fde0` marker and
   left `symbols.csv`/autogen names unchanged as historical Ghidra evidence.
3. Consolidated repeated UI rect declarations:
   - Added shared `struct RECT`, `CopyRect`, and `OffsetRect` declarations to
     `include/game/ui_widget_shared.h`.
   - Removed local duplicate `RECT`/`tagRECT` definitions from `trade_screen.cpp`,
     `TPlacard.cpp`, `TTransFocusAnimation.cpp`, and `TOneTimeAnimation.cpp`.
4. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - `just compare 0x0049fde0`: held at **75.86%** under the behavioral name.
   - `just compare 0x004a0190`: held at **81.69%**.
   - `just compare 0x004a05c0`: held at **29.85%**.
   - `just compare 0x004a0770`: held at **84.75%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.13%**, dropped duplicate addresses **0**.

### TTwoPicSlider Mac-guided draw/track slice (2026-06-01, cont.)

1. Added `src/game/TTwoPicSlider.cpp` and promoted two Mac-guided methods:
   - `0x0056e370` as `DrawTwoPicSliderSplitOverlayAndCenteredStatusText`.
   - `0x0056e640` as `TrackTwoPicSliderMouseAndRefresh`.
   Mac CodeWarrior evidence names the family methods `Draw(const VRect&)` and
   `TrackMouse(TrackPhase, VPoint&, VPoint&, VPoint&, unsigned char)`, but the Windows
   implementation names stay behavioral until class layout is more certain.
2. Captured provisional `TTwoPicSlider` field evidence:
   - `this+0x34` / `this+0x38`: width/height.
   - `this+0x84`, `this+0x88`, `this+0x8c`: lower, upper, and composite QuickDraw surfaces.
   - `this+0x90`: split position.
   - `this+0x94`: mode controlling aux volume vs SFX playback update.
3. Reused the shared UI architecture from the earlier QuickDraw work:
   - shared `RECT`;
   - `BlitRectWithOptionalTransparency`;
   - `StringShared` text lifetime;
   - `ScopedMapQuickDrawContextGuard`;
   - generated slot `0xf8` and `0x110` facades.
4. Signature lesson:
   - `0x0056e640` is not the two-stack-arg shape implied by the stale Ghidra prototype.
     Matching the observed `ret 0x0c` requires a `__fastcall` bridge with three stack args:
     phase, unused/secondary param, and a point-record pointer read at `arg+4`.
5. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - `just compare 0x0056e370`: stub -> **46.84%**.
   - `just compare 0x0056e640`: stub -> **45.63%** with correct `ret 0x0c`.
   - `just compare 0x004a0770`: held at **84.75%** before this slice.
   - Adjacent constructor/destructor remain stubs for now:
     `0x0056e200` **0.00%**, `0x0056e2f0` **0.00%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.14%**, aligned functions **102**, dropped duplicate
     addresses **0**.

### TCityProductionView temporary primary-surface slice (2026-06-01, cont.)

1. Added `src/game/TCityProductionView.cpp` and promoted
   `0x004bc9b0` as
   `TCityProductionViewLayout::RenderViewIntoPrimaryRenderContextWithTemporaryClip(int,int)`.
2. Class/calling-convention correction:
   - Initial free-function bridge reached **42.25%** with FPO enabled, but the original body
     returns `ret 8`.
   - Converted it to a real provisional class method with two hidden stack args. Final score is
     **41.67%**, but the method shape is cleaner evidence for class recovery than a free bridge.
3. Added generated provisional vcall facades for reusable temporary render targets:
   - `VCall_QuickDrawTarget_QueryBoundsSlot12C`
   - `VCall_QuickDrawTarget_ApplyRectSlot110`
4. Captured reusable render-wrapper pattern:
   - `QuickDrawSurfaceGuard`;
   - slot `0x12c` bounds capture;
   - `ApplyHitRegionToClipState(0)`;
   - active QuickDraw context save/swap to `g_pPrimaryRenderSurfaceContext`;
   - rect clip apply;
   - dirty/refresh byte at `this+0xa6`;
   - slot `0x110` render/apply;
   - active context restore and `SnapshotHitRegionToClipCache`.
5. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - `just compare 0x004bc9b0`: stub -> **41.67%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.15%**, aligned functions **102**, dropped duplicate
     addresses **0**.

### TDiplomacyMapView legend/palette slice (2026-06-01, cont.)

1. Added `src/game/TDiplomacyMapView.cpp` and promoted three methods/subobject helpers:
   - `0x004f6170` as
     `TDiplomacyMapViewLayout::RenderDiplomacyLegendSurfaceAndPresent(const RECT*)`.
   - `0x004f64c0` as
     `TDiplomacyMapViewLayout::RebuildDiplomacyLegendPaletteMode4AndBlit(int,const RECT*)`.
   - `0x004f66c0` as provisional
     `DiplomacyMaskBufferRun::BlitMonochromeMaskBytePatternToSurface(int,int,int*,int)`.
2. Corrected generated vcall facade signatures from compare evidence:
   - slot `0x1e0`: terrain/minor draw takes `(terrainIndex, labelSelector)`.
   - slot `0x34`: UI/runtime legend split takes selector `0x3f`.
   - slot `0x98`: strategic-map frame-region query takes the short selector at `this+0x98`.
3. Captured provisional layout evidence:
   - `TDiplomacyMapViewLayout::frameRegionSelectorAt98`;
   - `TDiplomacyMapViewLayout::legendSurfaceModeAt524`;
   - `this+0x1eac`: repeated 0x14-byte mask-buffer runs used as `ecx` for `0x004f66c0`;
   - `this+0x2078`: repeated 0x30-byte packed-color runs used by
     `thunk_AppendPackedColorDwordToMaskBuffers`.
4. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - `just compare 0x004f6170`: stub -> **46.30%** after vcall signature fixes.
   - `just compare 0x004f64c0`: stub -> **31.33%**.
   - `just compare 0x004f66c0`: stub -> **15.02%** with correct `ret 0x10`.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.16%**, aligned functions **102**, dropped duplicate
     addresses **0**.

### TDiplomacyMapView event-palette mask blit (2026-06-01, cont.)

1. Promoted `0x004f6bd0` as
   `TDiplomacyMapViewLayout::BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex, int bmpId)`
   from a `0%` stub to **25.30%**.
   - Single-index variant of the mask-run blit family: instead of filling a solid
     palette byte (`DiplomacyMaskBufferRun::BlitMonochromeMaskBytePatternToSurface`),
     it copies pixels from a loaded BMP through the monochrome mask at
     `this+0x1eac + maskIndex*0x14`, then appends one packed color at
     `this+0x2078 + maskIndex*0x30`.
2. New architecture/layout evidence captured:
   - `ModuleLibraryCacheState` at global `g_pModuleLibraryCacheState` (`0x6a134c`):
     hash-indexed BMP record cache with `LoadBmpResourceById(id)` (thunk `0x403224`)
     and `ReleaseRecordByHandle(handle)` (thunk `0x4020fe`), both real thiscall methods.
   - `DiplomacyPackedColorRun` subobject (`0x30`-byte stride) with thiscall
     `AppendPackedColorDword(surface, packedColor)` (thunk `0x404a25`) — same target as
     the sibling mode-1/mode-4 packed-color append, now modeled as a real method call
     (ecx = packed-color run) matching the original thiscall shape.
   - BMP record layout: row width at `*(*(bmp+0x10)+4)`, pixel source at `*(bmp+0xc)`.
   - Active context surface object reached via `*(context+4)` anchor: height at
     `*(*(*(context+0x20)+0x10)+8)`, row stride `(short)*(context+8)`, base `*(context+4)`.
3. Residual gap is register allocation: original binds `context+4`->esi and `this`->edi;
   MSVC500 swaps them here, which cascades through the pixel loop. Branch/loop shape and
   pointer-advance math match; the swap is the dominant remaining mismatch.
4. Decompiler caveat: Ghidra modeled the tail `AppendPackedColorDword` call as a 2-arg
   cdecl thunk; the listing shows it is thiscall (ecx = packed-color cursor, then
   `push palette; push surface`). The instruction listing was authoritative.
5. Validation:
   - `just sync-ownership` (ownership updates: 1), `just regen-stubs`, `just build`,
     `just detect`: clean.
   - `just compare 0x004f6bd0`: stub -> **25.30%**.
   - Adjacent diplomacy functions unchanged: `0x004f6170` **45.06%** (control-plane's
     prior `46.30%` was stale; verified identical at committed HEAD with my changes
     stashed), `0x004f64c0` **37.74%**, `0x004f66c0` **15.02%**, `0x004f6840` **35.53%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.17%**, aligned functions **102** (delta 0), paired
     global count increased, dropped duplicate addresses **0**.

### TDiplomacyMapView turn-event mask-run render (2026-06-01, cont.)

1. Promoted `0x004f6b10` as
   `TDiplomacyMapViewLayout::BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode)`
   from a `0%` stub to **43.04%**. This is the standalone single-run sibling of the
   mode-1/mode-4 inner loop body and validates the producer side of the mask-run /
   packed-color layout (`this+0x1eac + idx*0x14`, `this+0x2078 + idx*0x30`).
2. Confirmed arg order from the compare: `maskIndex` is arg1 (`esi*5`/`esi*3` index math),
   `eventCode` is arg2 (fed to `MapTurnEventCodeToPaletteIndex`). `ret 8`.
3. Helper arities resolved via pyghidra (thunk -> thunked impl):
   - `MapTurnEventCodeToPaletteIndex` (`0x5d5270`) is `__cdecl(short)`; the member-call
     form `g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(...)` emits the matching
     `mov ecx,[uiRuntime]; push code; call`.
   - `SetUiResourceContextTagWord` (`0x4270e0`) is `__thiscall(int* slot, value)` doing
     `*slot = value`. In context it fills the stack slot that is then passed as
     `BlitMonochrome`'s `paletteByte` arg (palette sign-extended via `movsx edx,ax`).
     The current no-arg model loses that `movsx`/stack-slot idiom — same gap exists in
     mode-1/mode-4, so modeling it as a typed tag-slot helper is the next deeper unlock.
4. Validation: `just build`/`detect` clean; `just compare 0x004f6b10` stub -> **43.04%**;
   adjacent diplomacy functions unchanged (present **46.30%**, mode4 **37.74%**,
   mask **15.02%**, mode1 **35.53%**, event-palette **25.30%**); canaries `below_floor=0`.

### TDiplomacyMapView combined terrain-region clip build (2026-06-01, cont.)

1. Promoted `0x004f6440` as
   `TDiplomacyMapViewLayout::BuildCombinedTerrainTypeRegionMaskAndDispatch()`
   (thiscall, `ret 0`) from a `0%` stub to **38.10%**. It builds a combined clip
   region by unioning per-terrain-type frame regions, applies it to the view, and
   frees it.
2. New facade + helper vocabulary:
   - `VCall_DiplomacyMapView_ApplyClipRegionSlotC4` (slot `0xc4`, applies the region
     to the diplomacy map view) added to `config/vtable_slots.csv` and generated.
   - Clip-region wrapper lifecycle (`__cdecl`): `CreateClipStateRegionWrapperObject`,
     `CombineTwoRegionsIntoDestinationAndUpdateBox(dest, src, dest)`,
     `DestroyClipStateRegionWrapperObject`.
   - Confirms strategic-map slot `0x98` is single-arg `(index)` here too (consistent
     with `RenderDiplomacyLegendSurfaceAndPresent`); the early `push region` is the
     pre-staged `Combine` destination arg, not a slot-`0x98` arg.
3. Residual gap is register allocation: original keeps `this` in `ebp` with an
   index-compare loop (`cmp si,0x17`); register pressure from the live `region`
   pushes MSVC500 to spill `this` and emit a `dec ebp` downcounter instead.
4. Validation: `just build`/`detect`/`vtable-gate` clean; `just compare 0x004f6440`
   stub -> **38.10%**; adjacent diplomacy functions unchanged; canaries
   `below_floor=0`.

### TDiplomacyMapView pending-policy icon/frame renderer (2026-06-01, cont.)

1. Promoted `0x004f71a0` as
   `TDiplomacyMapViewLayout::RenderDiplomacyPendingPolicyIconsAndFrames()`
   (thiscall, `ret 0`) from a `0%` stub to **31.97%**. Per-policy loop that blits a
   policy icon from the strategic-map icon strip into each pending-policy RECT, then
   draws a 1px highlight frame (legend-split color for the selected tier, else white)
   with corner guide lines.
2. Reuses established vocabulary: `BlitRectWithOptionalTransparency`, the active-context
   surface-height vertical-flip idiom (identical to `0x4f6bd0`), `SetQuickDrawFillColor`,
   slot `0x34` (`VCall_UiRuntime_ApplyLegendSplitSlot34`), `OffsetRect`.
3. New facade + helpers: `VCall_GlobalMapState_QueryIconStripXSlot110` (slot `0x110`,
   returns icon strip x by policy code; global `g_pGlobalMapState` `0x6a43d4`);
   `ResetQuickDrawStrokeState`, `UpdatePaletteIndexWithDefaultFallback`,
   `DrawFrameRectOrUpdateClipRegion`, `SetQuickDrawTextOriginWithContextOffset`,
   `DrawCenteredGuideLineOnMapDc`.
4. New layout evidence: icon-position RECT array at `this+0x6ac` (stride `0x10`),
   per-policy enable flags at `this+0x52c`, selected-tier short at `this+0x528`; the
   diplomacy turn-state manager (`0x6a43d0`) holds a per-policy byte array at `+0x304`
   and a parallel short (tier) array at `+0x484`.
5. MSVC500 ICE note: the original three parallel induction cursors
   (policyIndex / tier-short cursor / icon-RECT cursor) under FPO (`optimize("y")`)
   triggers `fatal error C1001`. Rewrote with a single `policyIndex` induction and
   computed offsets inline (`+0x484+i*2`, `+0x304+i`, `+0x6ac+i*0x10`); MSVC500
   re-derives the strength-reduced cursors and compiles. Keeping the `manager` reload
   *inside* the loop matched the original (per-taken-iteration reload) better than
   hoisting it (31.97% vs 28.68%).
6. Validation: `just build`/`detect` clean; `just compare 0x004f71a0` stub -> **31.97%**;
   adjacent diplomacy functions unchanged; canaries `below_floor=0`.

### TDiplomacyMapView click hit-test / action resolve (2026-06-01, cont.)

1. Promoted `0x004f5e00` as
   `TDiplomacyMapViewLayout::ResolveDiplomacyActionFromClickAndUpdateTarget(Point32*)`
   (thiscall, `ret 4`) from a `0%` stub to **43.27%**. Lazy-inits the nation-matrix hit
   RECT, PtInRect-gates the click, transforms it to view-local coords (slot `0x148`),
   hit-tests each terrain region (strategic-map slot `0x90`), and updates the hovered
   target, returning the pending action code.
2. Architectural finding: Ghidra assigns `0x4f5e00` to `TCountry`, but `this` is the
   diplomacy map view (fields `+0x90` selected-target short, `+0x94` mode, `+0xbc`
   action code, `+0xc2` hovered-target short; vtable slot `0x148`). Modeled as a
   `TDiplomacyMapViewLayout` method with offset access for the interaction fields; kept
   the stale owned symbol name.
3. New facades: `VCall_DiplomacyMapView_TransformPointToLocalSlot148` (slot `0x148`),
   `VCall_StrategicMap_HitTestPointSlot90` (slot `0x90`). New globals:
   `g_fDiplomacyNationMatrixRectInitialized` (`0x6a2fbc`),
   `g_rcDiplomacyNationMatrixHitBounds` (`0x6a3008`).
4. Tuning: reading the init flag once into a local and writing the modified value back
   to the literal address (instead of caching a pointer) restored the direct
   `mov al,[0x6a2fbc]` shape and lifted 38.37% -> 43.27%.
5. Validation: `just build`/`detect`/`vtable-gate` clean; `just compare 0x004f5e00`
   stub -> **43.27%**; canaries `below_floor=0`; stats avg **3.18%**, aligned **102**.
   Note: `0x4f6bd0` reads 21.05% (was 25.30%) with no source change — reccmp re-pairing
   noise from added functions in the TU (same effect seen earlier on `0x4f6170`).

### TDiplomacyMapView hover-cursor update (2026-06-01, cont.)

1. Promoted `0x004f5fb0` as
   `TDiplomacyMapViewLayout::UpdateDiplomacyMapHoverCursorFromActionSelection(Point32*, void*)`
   (thiscall, `ret 8`) from a `0%` stub to **40.59%**. Hit-tests the hovered terrain
   region, resolves the pending action by calling the just-ported `0x4f5e00`, validates
   the (selected, hovered, action) triple via the turn-state manager's slot `0x5c`, maps
   the action to a cursor id through a 16-entry stack table (with a `this+0xc0` adjust for
   actions 7/8/9), sets the cursor from the UI-runtime cursor table, and forwards to the
   base `TControl::HandleCursorHoverSelectionByChildHitTestAndFallback`.
2. Completes the interaction pair: `0x4f5fb0` -> `0x4f5e00` is a real intra-slice call
   (reccmp pairs my method through the ILT thunk). Confirms the shared interaction fields
   `+0x90`/`+0xc2` and adds `+0xc0` (cursor adjust short) and `+0x52a` (current cursor id).
3. New facade `VCall_DiplomacyTurnState_ValidateActionSlot5C` (slot `0x5c` on the
   `0x6a43d0` manager). Cursor handle table at `g_pUiRuntimeContext - 0xf8c + id*4`
   (default `0x41b` -> `+0xe0`). Declared Win32 `SetCursor`.
4. Validation: `just build`/`detect`/`vtable-gate` clean; `just compare 0x004f5fb0`
   stub -> **40.59%**; adjacent diplomacy functions unchanged; canaries `below_floor=0`.

### TDiplomacyMapView control-tag command dispatcher (2026-06-01, cont.)

1. Promoted `0x004f70c0` as free `__stdcall HandleDiplomacyMapControlTagToggleOrForward`
   `(int commandId, int panelEvent, void* extra)` (`ret 0xc`) from a `0%` stub to
   **40.00%**. For command `0x14` it looks up the panel event's control tag
   (`*(panelEvent+0x1c)`) in the 6-entry table at `0x696978` and forwards the matched
   tab index to the tab invalidator (`0x4f6d90`); otherwise forwards to
   `thunk_HandleCityDialogToggleCommandOrForward`.
2. Architectural note: Ghidra owns this as `TDiplomacyMapView::Handle...` (`__thiscall`),
   but the body has no `this` (3 stack args, `ret 0xc`) — modeled as a free `__stdcall`
   function. Residual gap is index-counter register allocation (`ecx` vs `edx`).
3. Validation: `just build`/`detect` clean; `just compare 0x004f70c0` stub -> **40.00%**;
   canaries `below_floor=0`; stats avg **3.19%**, aligned **102**.

### TDiplomacyMapView active-child param forward (2026-06-01, cont.)

1. Promoted `0x004f7130` as
   `TDiplomacyMapViewLayout::ForwardCityDialogParamToActiveChildOrBase(void*)`
   (thiscall, `ret 4`) from a `0%` stub to **64.00%** (cleanest match of the session).
   When the view is in child mode (`this+0xb8 == 5`) it forwards the param to the
   active child control (`this+0xb4`) via slot `0x48`; otherwise forwards to the base
   `TControl::ForwardCityDialogParamToChildSlot48`.
2. New layout: `this+0xb4` active child control pointer, `this+0xb8` child mode flag
   (shared by the sibling tab-switch wrappers `0x4f7040`/`0x4f7080`). Added
   `VCall_DiplomacyChildControl_ForwardParamSlot48` (slot `0x48`).
3. Validation: `just build`/`detect`/`vtable-gate` clean; `just compare 0x004f7130`
   stub -> **64.00%**; canaries `below_floor=0`; stats avg **3.20%**, aligned **102**.

### TDiplomacyMapView tab-switch child forward (2026-06-01, cont.)

1. Promoted `0x004f7080` as
   `TDiplomacyMapViewLayout::InvalidateAndForwardTabSwitchToChild(void*, void*, void*)`
   (thiscall, `ret 0xc`) from a `0%` stub to **92.86%** (near-exact; only a tail
   diff-alignment artifact remains). Invalidates tab 5 then forwards the tab-switch
   command to the active child control (`this+0xb4`) via slot `0x1a4`.
2. Added `VCall_DiplomacyChildControl_SwitchTabSlot1A4` (slot `0x1a4`, 3 args). Reuses
   the `this+0xb4` child-control layout and the invalidate thunk.
3. Validation: `just build`/`detect`/`vtable-gate` clean; `just compare 0x004f7080`
   stub -> **92.86%**; canaries `below_floor=0`.

### TDiplomacyMapView child wait-sheet forward (2026-06-01, cont.)

1. Promoted `0x004f7040` as
   `TDiplomacyMapViewLayout::InvalidateAndRunChildWaitSheet(void*, void*, void*, void*)`
   (thiscall, `ret 0x10`) from a `0%` stub to **85.71%**, completing the
   `+0xb4` child tab-switch wrapper cluster (`0x4f7040`/`0x4f7080`/`0x4f7130`).
   Invalidates tab 5 then forwards 4 args to the child's
   `RunDiplomacyWaitSheetPopupAndAwaitResponse`. The only residual is the
   `xor edx,edx` from the `__fastcall` thiscall bridge (4 stack args, can't be a
   pure facade call).
2. Validation: `just build`/`detect`/`vtable-gate` clean; `just compare 0x004f7040`
   stub -> **85.71%**; canaries `below_floor=0`; stats avg **3.21%**, aligned **102**.

### Session summary (2026-06-01)
Grew `src/game/TDiplomacyMapView.cpp` from 4 to 13 promoted functions. New this
session (all from `0%` stubs): `0x4f6bd0` (25.30), `0x4f6b10` (43.04), `0x4f6440`
(38.10), `0x4f71a0` (31.97), `0x4f5e00` (43.27), `0x4f5fb0` (40.59), `0x4f70c0`
(40.00), `0x4f7130` (64.00), `0x4f7080` (92.86), `0x4f7040` (85.71). Established the `DiplomacyMaskBufferRun` /
`DiplomacyPackedColorRun` / `ModuleLibraryCacheState` subobjects, the diplomacy
interaction-state field map (`+0x90`/`+0x94`/`+0xb4`/`+0xb8`/`+0xbc`/`+0xc0`/`+0xc2`/
`+0x52a`), and 7 new vtable facades. Remaining slice tail: `0x4f6d90` (513-byte invalidator) and `0x4f7400`
(EH-framed localized notice) — both larger/EH-heavy targets for a later pass.

### DiplomacyTurnStateManager backend seed (2026-06-01, cont.)

1. Added `src/game/diplomacy_state.cpp` and seeded the diplomacy game-logic backend consumed by `TDiplomacyMapView` and `TGreatPower`.
2. Added `tools/ghidra/listing_one.py` plus `just ghidra-listing` for read-only listing-level evidence. This was needed because Ghidra decompiled these exports as free functions with `in_ECX`, while the listing proves they are `ecx=this` methods.
3. Promoted five backend anchors:
   - `0x004ee6c0` `DiplomacyTurnStateManager::ConstructDiplomacyTurnStateManager_Vtbl00654d90`: owned, vtable `0x00654d90`, fields `+0x78e`, `+0x790`, `+0x794`, `+0x798`; still **0.00%** due register-order mismatch.
   - `0x004ef540` `IsNationPairAtWar(int,int)`: stub -> **75.47%**, `ret 8`.
   - `0x004ef600` `HasAnyWarRelationForNation(int)`: stub -> **37.33%**, `ret 4`.
   - `0x004ef650` `HasAnyWarRelationTurnStampOutOfDateForNation(int)`: stub -> **37.33%**, `ret 4`.
   - `0x004f09c0` `QueueNationPairWarTransition(int,int)`: stub -> **77.78%**, confirms pending-war queue pointer at `this+0x18d4`.
4. Added provisional facades:
   - `VCall_Diplomacy_HasOutdatedWarRelationSlot48`
   - `VCall_WarTransitionQueue_PushPairSlot40`
   - `VCall_Diplomacy_SetRelationCodeSlot74WithMode`
5. Validation:
   - `just build`, `just detect`, `just vtable-gate`: clean.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.24%**, aligned functions **102**, dropped duplicate addresses **0**.

### Diplomacy queued-war backend processor (2026-06-01, cont.)

1. Promoted the queued-war processor chain in `src/game/diplomacy_state.cpp`:
   - `0x004f0a10` `DiplomacyTurnStateManager::ProcessQueuedWarTransitions`: stub -> **41.82%**.
   - `0x00406aaf` `DiplomacyTurnStateManager::thunk_ProcessQueuedWarTransitions`: **100%**.
   - `0x004f0db0` `DispatchProcessQueuedWarTransitions`: **100%**.
2. Corrected the calling-convention model after listing evidence: `0x004f0db0` is not a `__fastcall` method body; it is a global wrapper that loads `g_pDiplomacyTurnStateManager` from `0x006a43d0` into `ecx` and jumps to the method-style thunk at `0x00406aaf`.
3. Added provisional facades for the connected backend:
   - `VCall_WarTransitionQueue_PeekFirstPairSlot34`
   - `VCall_WarTransitionQueue_RemoveFirstPairSlot30`
   - `VCall_Diplomacy_SetRelationCodeSlot94`
   - `VCall_NationState_CheckTransitionSlot27C`
   - `VCall_NationState_PropagateWarTransitionSlot280`
   - `VCall_TurnEventQueue_EnqueueSlot38`
   - `VCall_LocalizationTable_CallSlot44`
4. New evidence: the processor drains `pendingWarTransitionQueue18d4`, mutates relation slot `0x74`, queues bidirectional inter-nation event records through `0x00406758`, propagates alliance/war effects through nation-state slots `0x27c`/`0x280`, and enqueues a `NeXT` turn-event packet (`vtable 0x00654e50`) when propagation did not consume the transition.

### DiplomacyTurnStateManager class shape pass (2026-06-01, cont.)

1. Expanded `src/game/diplomacy_state.cpp` from pad-heavy manager fields to a provisional, evidence-backed layout:
   - `+0x004`: `relationCodeMatrix04[0x180]` (`short`)
   - `+0x304`: `pendingPolicyCodeMatrix304[0x180]` (`byte`)
   - `+0x484`: `pendingPolicyTierMatrix484[0x180]` (`short`)
   - `+0x784..+0x798`: selection/proposal/queued-war state
   - `+0x79c`: `relationStandingScoreMatrix79c[23*23]` (`short`)
   - `+0xbbe`: `relationPropagationMatrixBbe[23*23]` (`short`)
   - `+0xfe0`: `relationTurnStampMatrixFe0[23*23]` (`short`)
   - `+0x1402`: `relationSideEffectMatrix1402[23*23]` (`short`)
   - `+0x18d4`: pending-war transition queue pointer
   - `+0x18d8`: proposal-array mode/state short
2. Moved the misattributed default initializer into the manager:
   - `0x004ee7a0` `DiplomacyTurnStateManager::InitializeDiplomacyTurnStateManagerDefaults`: stub -> **23.16%**. It allocates a `0x18` TPtrList/CObArray-like queue (`vtable 0x00649068`), clears `+0x04/+0x304`, initializes selection sentinels, and fills the `+0xfe0` 23x23 turn-stamp matrix with `-1`.
   - `0x00403837` initializer thunk: **100%**.
   - `0x00409944` constructor thunk: **100%**.
3. Dumped `vtbl_DiplomacyTurnStateManager_00654d90` and resolved the important ILT slots:
   - slot `0x44` -> `0x004ef540`
   - slot `0x48` -> `0x004ef590`
   - slot `0x4c` -> `0x004ef600`
   - slot `0x5c` -> `0x004ef700`
   - slot `0x60` -> `0x004efc30`
   - slot `0x68` -> `0x004f19c0`
   - slot `0x70` -> `0x004f1b10`
   - slot `0x74` -> `0x004f1b70`
   - slot `0x84` -> `0x004f1f50`
   - slot `0x94` -> `0x004f21f0`
   - slot `0x98` -> `0x004f2100`
4. Promoted three cheap vtable slot bodies:
   - `0x004f19c0` `GetNationPairDiplomacyStandingTierCode(int,int)`: stub -> **100%**; proves slot `0x68` returns full `EAX` and reads the `+0x79c` standing-score matrix.
   - `0x004f1b10` `GetNationPairDiplomacyRelationCode(int,int)`: stub -> **53.33%**; proves slot `0x70` returns `AX` from the `+0xbbe` relation-code matrix.
   - `0x004f1f50` `IsPrimaryNationSlotIndex(int)`: stub -> **66.67%**; tiny slot `0x84` nation-slot gate (`slot < 7`).
5. Updated `VCall_Diplomacy_GetRelationTypeSlot68` return type from `short` to `int` after the exact `0x004f19c0` match showed the old facade return width was wrong.
6. Validation:
   - `just build`, `just detect`, `just vtable-gate`: clean.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.30%**, aligned functions **107** (`+3`).

### Diplomacy relation-transition slot pass (2026-06-01, cont.)

1. Promoted two more `DiplomacyTurnStateManager` vtable-slot bodies:
   - `0x004ef590` `IsNationPairRelationTurnStampOutOfDate(int,int)`: stub -> **58.33%**. This confirms slot `0x48` gates through slot `0x44`, reads the current turn from localization slot `0x3c`, and compares the `+0xfe0` 23x23 relation turn-stamp matrix.
   - `0x004f1b70` `SetNationPairDiplomacyRelationCode(int,int,int,int)`: stub -> **9.31%** as a first shape pass. Similarity is intentionally low for now, but the body is class-shape-rich: it writes `+0xbbe` symmetrically, updates `+0xfe0` stamps, notifies nation-state slot `0x2a8`, dispatches relation cases 2/3/4/5/6, adjusts standing score via slot `0x28`, updates `+0x1402` side-effect state, calls terrain descriptor slot `0x48`, and optionally propagates through manager slot `0x80`.
2. Added provisional facades for the connected virtual calls discovered in the relation setter:
   - `VCall_Diplomacy_SetStandingScoreSlot28`
   - `VCall_Diplomacy_PropagateRelationSideEffectSlot80`
   - `VCall_NationState_NotifyRelationCodeSlot2A8`
   - `VCall_NationState_NotifyAllianceSlot214`
   - `VCall_NationState_NotifyWarResetSlot290`
   - `VCall_TerrainDescriptor_SetDiplomacyStandingSlot48`
3. Validation:
   - `just build`, `just detect`: clean.
   - Target compares: `0x004ef590` **58.33%**, `0x004f1b70` **9.31%**, `0x004f09c0` **77.78%**, `0x004f0a10` **41.82%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.
   - `just stats`: avg similarity **3.31%**, aligned functions **107**.

### Diplomacy action validator backend slot (2026-06-01, cont.)

1. Promoted `0x004ef700` as `DiplomacyTurnStateManager::ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(int,int,int)`: stub -> **55.42%**.
2. Corrected the old Ghidra model: the current project no longer has a function boundary at `0x004ef700`, and the stale autogen prototype says `void`, but bounded disassembly of the original shows an intentional `AL` contract. Failure exits write `proposalArrayMode18d8` reject codes and return `0`; the shared success exit returns `1`.
3. Confirmed validator dependencies:
   - target terrain descriptor owner/state at `g_apTerrainTypeDescriptorTable[target]+0x0e`
   - relation side-effect matrix at `this+0x1402`
   - manager slots `0x44`, `0x48`, `0x70`
   - nation-state economy/treasury-like field at `g_apNationStates[source]+0x10`
4. Moved `VCall_DiplomacyTurnState_ValidateActionSlot5C` ownership from `TDiplomacyMapView.cpp` to `diplomacy_state.cpp` in `config/vtable_slots.csv`.
5. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - `just compare 0x004ef700`: **55.42%**.
   - UI caller guard: `just compare 0x004f5fb0` stayed **40.59%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just stats`: avg similarity **3.31%**, aligned functions **107**.

### Diplomacy alliance-guard slot (2026-06-02)

1. Promoted `0x004efc30` as `DiplomacyTurnStateManager::HasAllianceGuardSlot60(int,int)`: stub -> **86.02%**.
2. Corrected two stale Ghidra assumptions:
   - the old bucket/name `TSortedByRelationshipList::HasAsymmetricWarRelationForPrimaryNation` is misleading for this Windows body; `ECX` is the diplomacy turn-state manager and the function returns `AL`;
   - the method is not no-arg/`void`; listing evidence shows `ret 8` and two stack args, with the caller in `TGreatPower::QueueDiplomacyProposalCodeWithAllianceGuards`.
3. Promoted manager vtable slot `0x4c` from anonymous `slot_4c()` to `HasAnyWarRelationForNation(int)`. This was necessary to reproduce the original `mov ecx,[g_pDiplomacyTurnStateManager]; push arg; call [vftable+0x4c]` shape inside slot `0x60`.
4. Validation:
   - `just build`, `just detect`: clean.
   - `just compare 0x004efc30`: **86.02%**.
   - Caller guard `just compare 0x004e7b50`: **51.69%** unchanged.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.

### Diplomacy relationship-list selectors (2026-06-02)

1. Promoted three connected `DiplomacyTurnStateManager` vtable-slot bodies:
   - `0x004f1f70` `BuildRelationshipListSlot88(int,int,void*)`: stub -> **64.15%**. This fills a sorted relationship candidate list with `{nationSlot, standingScore}` pairs, using `g_apTerrainTypeDescriptorTable[n]+0x0e == -1` as the unowned/minor filter and reading standing scores from `this+0x79c`.
   - `0x004f2100` `SelectNationSlotFromCollectedStandingEntriesSlot98(int,int)`: stub -> **73.77%**. This constructs the `TSortedByRelationshipList` (`vtable 0x00654d38`), sets `relationType=4`, calls slot `0x88`, and returns the nation slot from the last one-based list entry or `-1`.
   - `0x004f21f0` `SelectDiplomacyTargetNationFromCandidateSetSlot94(int,int,int)`: stub -> **30.06%** first shape pass. If the side-effect arg is zero it delegates through slot `0x98`; otherwise it scans the sorted list backward and returns the first candidate whose `+0x1402` side-effect matrix value matches.
2. Added generated facades for `TSortedByRelationshipList` slots `0x24`, `0x2c`, and `0x38`, avoiding raw list vtable calls inside the manager methods.
3. Corrected the provisional manager slot `0x94` name from relation-code setter wording to side-effect target selection, and added the missing slot `0x98`.
4. Connectivity result: `ProcessQueuedWarTransitions` (`0x004f0a10`) improved from **41.82%** to **89.85%** because the slot `0x94` call now resolves to a real method signature and vtable slot.
5. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - Target compares: `0x004f1f70` **64.15%**, `0x004f2100` **73.77%**, `0x004f21f0` **30.06%**, `0x004f0a10` **89.85%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.

### Diplomacy standing-score setter (2026-06-02)

1. Promoted manager slot `0x28`, `0x004efcb0` `SetStandingScoreSlot28(int,int,int)`: stub -> **34.55%** first shape pass.
2. Behavior recovered:
   - clamps negative scores to zero;
   - clamps non-self scores above `0xff` to `0xff`;
   - raises very low scores to `0x32` unless slot `0x44` says the pair already has the relevant policy/relation;
   - writes the standing-score matrix symmetrically at `this+0x79c`;
   - if either endpoint is a primary nation (`slot 0x84`), scans minor terrain descriptors `7..22`, checks terrain slot `0x5c`, and calls manager slot `0x2c` to propagate minor standing updates.
3. Added class-shape names:
   - manager slot `0x2c` -> `UpdateMinorStandingFromMajorPairSlot2c(int,int)`;
   - terrain descriptor slot `0x5c` -> `HasMinorStandingLinkSlot5C(int)`.
4. Connectivity result: broad relation setter `0x004f1b70` improved from **9.31%** earlier in the slice to **24.84%** with the real slot `0x28` body in place. `ProcessQueuedWarTransitions` stayed **89.85%**.
5. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - Target compares: `0x004efcb0` **34.55%**, `0x004f1b70` **24.84%**, `0x004f0a10` **89.85%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.

### Diplomacy standing row/column copy slot (2026-06-02, cont.)

1. Promoted manager slot `0x2c`, `0x004efe30` `CopyDiplomacyStandingMatrixRowAndColumnSlot2c(int,int)`: stub -> **36.07%** first shape pass.
2. Corrected the provisional slot `0x2c` name from "minor standing propagation" to the concrete matrix operation. The method copies both a full row and matching column inside the `+0x79c` standing-score matrix, using 23 entries and `ret 8`.
3. Updated slot `0x28` callsites to call the real virtual `CopyDiplomacyStandingMatrixRowAndColumnSlot2c(minorNation, sourceNation)` when a minor terrain descriptor links to a primary nation through terrain slot `0x5c`.
4. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - Target compares: `0x004efe30` **36.07%**, `0x004efcb0` **34.55%**, `0x004f1b70` **24.84%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.

### Diplomacy relation side-effect propagation slot (2026-06-02, cont.)

1. Promoted manager slot `0x80`, `0x004eff40` `PropagateRelationSideEffectSlot80(int,int,int)`: stub -> **27.33%** first shape pass.
2. Corrected the old class bucket: this body is a `DiplomacyTurnStateManager` method reached through relation setter slot `0x74`, not a free `TSortedByRelationshipList` helper. The current live Ghidra project does not expose `0x004eff40` as a function boundary, but `config/symbols.csv`, `src/ghidra_autogen/index.csv`, and reccmp pairing confirm the original body.
3. Behavior recovered:
   - reads and updates the `+0x79c` standing-score matrix through slot `0x28`;
   - branches on the byte form of the third argument for direct relation side effects;
   - scans all 23 nation slots, gated by `thunk_IsNationSlotEligibleForEventProcessing`;
   - skips the source/target nations and requires terrain descriptor owner/state `+0x0e == -1`;
   - uses manager slot `0x84` and terrain descriptor slot `0x90` to choose the propagation divisor before clamping the related standing update.
4. Connectivity checks stayed stable:
   - `SetNationPairDiplomacyRelationCode` (`0x004f1b70`) stayed **24.84%** with the real slot `0x80` callsite.
   - `SetStandingScoreSlot28` (`0x004efcb0`) stayed **34.55%**.
5. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - Target compares: `0x004eff40` **27.33%**, `0x004f1b70` **24.84%**, `0x004efcb0` **34.55%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.
   - `just stats`: aligned functions **128**, average similarity **9.50%**.

### Diplomacy relation/alliance vtable slots (2026-06-02, cont.)

1. Promoted three more `DiplomacyTurnStateManager` vtable-slot methods from the stale `TSortedByRelationshipList` bucket:
   - `0x004f1b40` slot `0x78` `SetNationPairDiplomacyRelationCodeFinal(int,int,int)`: stub -> **100.00%**. This is the thin `ret 0xc` wrapper that delegates to slot `0x74` with final/update flag `1`.
   - `0x004f2050` slot `0x8c` `CountMajorAllianceRelationsForNation(int)`: stub -> **100.00%**. This counts relation-code `2` entries across the seven major-nation columns in the `+0xbbe` relation-code matrix.
   - `0x004f2090` slot `0x90` `GetNthAlliedMajorNationSlotForNation(int,int)`: stub -> **35.71%** first shape pass. It scans major-nation relation-code entries and returns `candidate - 1` when the requested allied ordinal is reached; the signature and return contract are now explicit even though the local register shape still differs.
2. Added generated facade rows for manager slots `0x78`, `0x8c`, and `0x90`, so future `TGreatPower`/AI caller migrations can use typed manager calls instead of raw vtable offsets.
3. Validation:
   - `just regen-stubs`, `just build`, `just detect`: clean.
   - Target compares: `0x004f1b40` **100.00%**, `0x004f2050` **100.00%**, `0x004f2090` **35.71%**, `0x004f1b70` **24.84%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.
   - `just stats`: aligned functions **130**, average similarity **9.52%**.

### Diplomacy relation-code-4 slot (2026-06-02, cont.)

1. Promoted manager slot `0x7c`, `0x004efeb0` `ApplyRelationCode4AndQueueEvent18ForTargetNation(int,int,int)`: stub -> **92.31%**.
2. Corrected the Ghidra prototype: the autogen bucket says two args and misreads the third stack arg as `unaff_retaddr`, but caller evidence from `TGreatPower`/`TCountry` and the body shape show a real `ret 0xc` manager method taking `(sourceNation, targetNation, updateMode)`.
3. Behavior recovered:
   - delegates to confirmed slot `0x78` with relation code `4`;
   - when `updateMode` byte is `1`, delegates to slot `0x80` with propagation mode `0`;
   - if the target terrain descriptor exists, calls terrain slot `0x94` with action code `0x139`;
   - queues inter-nation event `0x18` as `(target, source)`.
4. Added generated facade rows for manager slot `0x7c` and terrain descriptor slot `0x94`.
5. Validation:
   - `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`: clean.
   - Target compares: `0x004efeb0` **92.31%**, `0x004f1b40` **100.00%**, `0x004eff40` **27.91%**.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: clean.
   - `just stats`: aligned functions **130**, average similarity **9.53%**.

### Diplomacy list-struct migration to real foundation classes (2026-06-02, cont.)

1. Removed the two misnamed local raw structs in `src/game/diplomacy_state.cpp` and replaced them with the grounded foundation classes:
   - local `struct TSortedByRelationshipList` (installed vtable `0x00649068`) was really a `TSortedPtrList`; the pending-war-transition queue (`slot 0x18d4`) now uses `new TSortedPtrList()`.
   - local `struct RelationshipCandidateList` (installed vtable `0x00654d38`) was really the `TSortedByRelationshipList`; the candidate lists in slots `0x94`/`0x98` now use `new TSortedByRelationshipList()`.
2. Deleted the transitional scaffolding: the `ConstructTPtrListObject` placement-new helper, the `kVtableTPtrList` constant, and the per-struct manual vtable assignments. `relationType` is now reached through the real `TSortedPtrList` union member (`->rel.relationType`); `operator new` is inherited from `TSortedPtrList` (`AllocateWithFallbackHandler`).
3. Score deltas: `0x004ee7a0` (`InitializeDiplomacyTurnStateManagerDefaults`) **67.72% -> 69.29%**; neighbors held at `0x004f2100` **73.77%**, `0x004f21f0` **30.06%**, `0x004f1f70` **64.15%**; ctors `0x004ee4b0`/`0x004ee540` stayed **100%**.
4. Validation:
   - `just build`, `just detect`: clean.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: passed (41 baseline-tracked matches across 5 files).
   - `just stats`: aligned functions **141** (delta 0), average similarity **9.63%** (delta +0.00 pp).
5. Lesson recorded in `INSTRUCTIONS.md` note 74: ground list-struct type by the installed vtable + field layout, not the struct name; prefer the real two-write `TSortedByRelationshipList` ctor over a one-write local shim.

### TEventHandler VTABLE annotation correction (2026-06-02, cont.)

1. `include/game/TEventHandler.h` annotated `TEventHandler` with `// VTABLE: IMPERIALISM 0x0066FEC4`, which is the CObject root vtable. This collided with the legitimate `CObject` annotation in `cobject.h`, so reccmp emitted `Dropped duplicate address 0x66fec4 on VTABLE annotation` on every compare and silently discarded one entry.
2. TEventHandler's real vtable is `0x006497a0` (`PTR_thunk_GetTEventHandlerClassNamePointer_006497a0`, confirmed by the ctor/dtor vtable writes in `TView.cpp`, `TCityDialogModalState_00649A50.cpp`, and `global_part005.cpp`). Corrected the annotation to `0x006497a0`.
3. Validation:
   - `just stats`: `dropped duplicate addresses: 0` (was non-zero), aligned functions **141** (delta 0), average similarity **9.63%**.
   - `just compare-canaries`: `below_floor=0`; `just vtable-gate`: passed.

### TView base-state ctor: return-this + DATA vtable symbol (2026-06-02, cont.)

1. Applied INSTRUCTIONS note 61 to `TView::ConstructUiResourceEntryBase` (`0x0048a8e0`): declared it returning `TView*` with `return this;` (matches the original `mov eax, esi`), and referenced the final vptr write through the `g_vtblTView` DATA symbol (`extern "C" char g_vtblTView = 0;`) instead of the raw `0x00649858` literal so reccmp pairs it as `(DATA)`.
2. Score: `0x0048a8e0` **67.65% -> 69.57%**; dtor `0x0048a9d0` held **93.33%**, thunk `0x004064e2` held **100%**.
3. Remaining gap is entirely the MSVC C++ EH cleanup frame (`push -1; push __ehhandler; fs:[0]` setup/teardown + `[esp+0x14]` ehstate var) emitted because the `StringShared sharedStringRef` member at `+0x58` has a non-trivial destructor. This is the strong signal that the original `0x0048a8e0` is a real constructor, not a plain method (see investigation note below).
4. Validation: `just build`/`detect` clean; `compare-canaries` `below_floor=0`; `vtable-gate` passed; `stats` aligned **141** (delta 0), `dropped duplicate addresses: 0`.

### Diplomacy turn-application reconstruction: ApplyDiplomacyInterNationStatesForTurn (2026-06-02, cont.)

1. Promoted `0x004f01e0` (739 bytes) from a 0% stub to **47.62%** first shape+data pass, and its thunk `0x004020b8` to **100%** (+1 aligned function, 141 -> 142). Modeled as a `DiplomacyTurnStateManager` method, correcting Ghidra's stale `TSortedByRelationshipList` bucket (proven by `this->field00[0x21]`=slot 0x84 and `field00[0x11]`=slot 0x44, both manager slots).
2. Structure recovered:
   - localization-phase gate (`g_pLocalizationTable[0x11]`): phase-2 path runs nation slot `0x1cc` over the 7 majors descending; non-phase-2 runs a `0x1c8` eligibility pre-pass (gated on nation `+0xa0` byte), then `0x1e0`, then the nation×terrain relation loop.
   - the nested loop (7 majors × 23 minor/terrain rows, running field offset `0xb2` step 2): reads the per-pair flag (`+0x2e`) and relation code, gates `NotifyActionSlot94(0, flag)` on manager slot `0x84`, always calls nation `0x1d8`, and branches relation codes `0x133`/`0x134` (symmetric `relationSideEffectMatrix1402[row*23+col]`/`[row+col*23]` = 1/2 + queue events `0x12`/`0x14`), `0x131` (nation `0x284` unless manager `0x44`), else terrain `0x8c`.
3. New grounded slot names (autogen-comment grounded where noted): NationState `0x1d8` `RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8`, `0x284` `ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284`, plus provisional `0x1c8`/`0x1cc`/`0x1e0`; TerrainDescriptor `0x8c` `ApplyTerrainDiplomacyRelationFlagSlot8c`. Confirmed Ghidra `specialRelationFlagsMatrix17x17` (offset `0x1402`) is the existing `relationSideEffectMatrix1402`.
4. EH-RAII: four scratch `StringShared` locals modeled via a `ScratchSharedString` helper (ctor calls thiscall `InitFromEmpty`) reproduce the `push -1; push __ehhandler` frame and the four init/release calls. Residual: the wrapper adds a member-cleanup EH sub-level so the ehstate encoding differs from the original's flat 0/1/2/3; not chased (would require shared `StringShared` header surgery).
5. Remaining gap is loop-induction register/stack allocation + the ehstate encoding — compiler-internal residuals, not chased per the loop.
6. Validation: `just sync-ownership` (2 updates), `just regen-stubs`, `just build`, `just detect` clean. Neighbors held exactly: `0x004f0a10` **89.85%**, `0x004f1b70` **24.84%**, `0x004efcb0` **34.55%**, `0x004f1f70` **64.15%**. `just compare-canaries` `below_floor=0`; `just vtable-gate` passed; `just stats` aligned **142** (+1), avg similarity **9.64%**, `dropped duplicate addresses: 0`.

### TGreatPower::ApplyAcceptedDiplomacyProposalCode codegen-shape fixes (2026-06-02, cont.)

Reviewer-guided structural rewrite of `0x004df010`, **20.48% -> 44.49%**:
1. Steps 1-2 (-> 34.13%): replaced the `SharedRefTripleScope` aggregate with three independent `StringShared` locals + explicit `InitFromEmpty`, and stopped caching `proposalCode`/`targetNation`/`sourceNation`/`diplomacyManager` (read through a typed `DiplomacyProposalRecord*` and `this->nationSlot`). Restored `this`->esi / proposal->edi and `sub esp,0xc`.
2. Step 5a (-> 42.98%): converted the manager/terrain/nation calls from `VCall_*` facades to real thiscall virtual dispatch via local typed vtable-view structs (`DiplomacyManagerVtbl` slots 0x44/0x70/0x78/0x7c/0x84, `TerrainDescriptorVtbl` 0x4c, `NationStateVtbl` 0x94). The facades carry a spurious `edx=0`; real virtuals do not.
3. Step 5b (-> 44.49%): the two TGreatPower self-slots (0x4c `CallSlot13`, 0x284 `ApplyPolicyForNationSlotA1`) via a `GreatPowerSelfVtbl` struct cast over `this` (vptr at offset 0) — no need to make TGreatPower itself polymorphic. Case 0 now matches the original exactly (`mov eax,[esi]; push 1; push ecx; mov ecx,esi; call [eax+0x4c]`).
4. Residual: the three string locals still register one combined ehstate (=2) instead of the original progressive 0/1/2, and carry extra `ebx` register pressure. Reproducing the progressive states needs `StringShared`'s ctor to BE `InitFromEmpty` (would affect other string sites) — left as the remaining compiler-internal residual.
5. Validation: build clean; neighbors held (`0x004ddfc0` 20.57%, `0x004dedf0` 29.37%, `0x004e2330` 34.98%); `compare-canaries` below_floor=0; `vtable-gate` passed; `stats` aligned **142**.

### TGreatPower vtable skeleton and first real self-virtuals (2026-06-02, cont.)

1. Added `tools/ghidra/vtable_dump.py` plus `just ghidra-vtable-dump` to dump MSVC vtable evidence as CSV: index, byte offset, entry address, current symbol, entry xrefs, and vtable-slot xrefs. This is the repeatable path for separating class descriptors from vtable anchors.
2. Corrected the anchor model for `TGreatPower`: `0x00653688` is the class descriptor, while the real vtable starts at `0x00653938`. Added `docs/tgreatpower_vtable_evidence.csv` with the initial grounded rows.
3. Converted `TGreatPower` from an explicit `void** vftable` layout to a real polymorphic skeleton annotated `// VTABLE: IMPERIALISM 0x00653938`. Added placeholder slots through index `0xA1`, then promoted known slots:
   - index `0x13` / byte `0x04c`: `VTableSlot13_Provisional(int,int)`, used by `0x004df010`.
   - index `0x84` / byte `0x210`: `VTableSlot84_Provisional(int)`, used by `0x004e9ed0`.
   - index `0xA1` / byte `0x284`: `VTableSlotA1_Provisional(int,int,int)`, vtable entry `0x00406fe1` thunking to body `0x004e27f0`.
4. Replaced the temporary `GreatPowerSelfVtbl` cast block in `0x004df010` with real virtual calls on `this`. The accepted-proposal path still scores **44.49%**, but the two GreatPower self-calls now compile as true `thiscall` virtual dispatch (`mov ecx, esi; call [eax+0x4c/0x284]`) without the bridge struct.
5. Fixed the stale `0x004e9ed0` signature from two stack args to three and migrated its slot `0x84` call to the real virtual. Result: `TGreatPower::QueueWarTransitionFromAdvisoryAction` (`0x004e9ed0`) is now **100.00%** (+1 aligned function).
6. Corrected the `0x004e27f0` body signature to the real three-arg `thiscall` shape (`ret 0x0c`) and made it read `g_pDiplomacyTurnStateManager` directly for the war-transition queue. It remains a first-pass body at **32.91%**; the residual is prologue/register layout, not signature.
7. The vtable thunk `0x00406fe1` still compiles as a small call/ret wrapper rather than the original single `jmp 0x004e27f0`; left for later because the important class/slot/call-convention model is now established.
8. Validation:
   - `just gen-vcall-facades`, `just build`, `just detect`: clean.
   - Target compares: `0x004df010` **44.49%**, `0x004e9ed0` **100.00%**, `0x004e27f0` **32.91%**, `0x00406fe1` **0.00%** thunk-shape residual.
   - `just compare-canaries`: `below_floor=0`.
   - `just vtable-gate`: passed.
   - `just stats`: aligned functions **143** (+1), average similarity **9.65%**.

### TGreatPower self-facade batch migration (2026-06-02, cont.)

1. Replaced a broader batch of known-`TGreatPower*` `VCall_GreatPower_*` helper/direct calls with real virtual declarations on the `TGreatPower` skeleton. Converted slots through the grounded table range: delete-self `0x01`, treasury `0x0e`, diplomacy reset `0x12`, counters/needs `0x1d`/`0x1f`, gates `0x21`/`0x28`, event dispatch `0x2e`, need/resource/budget slots `0x45`/`0x5c`/`0x5f`/`0x64`/`0x66`/`0x69`/`0x6a`/`0x6c`, proposal slots `0x73`/`0x74`/`0x75`/`0x77`/`0x7a`/`0x7b`/`0x7c`, and one-arg slot `0x85`.
2. Intentionally left the ambiguous `A1_NoArgs` facade, byte-offset `GetNodeContextSlot40`, and slots beyond the current A1 skeleton (`A5`/`A8`/`A9`/`B3`) on generated facades until their receiver/signature/vtable entries are grounded.
3. Validation batched once for the chunk: `just build` and `just detect` clean; `0x004df010` held **44.49%**, `0x004e9ed0` held **100.00%**; `just compare-canaries` `below_floor=0`; `just stats` aligned **143**, average similarity **9.66%**.

### TGreatPower virtual-call cleanup: remove pass-through shims (2026-06-02, cont.)

1. Removed the redundant `static __inline GreatPower_*` pass-through layer for class-owned slots. Known `TGreatPower*` receivers now call `this->..._Provisional(...)` or `self->..._Provisional(...)` directly.
2. Extended the provisional skeleton for slots `0xA5`, `0xA8`, `0xA9`, and `0xB3`; migrated their typed callsites directly. `0xA9` is modeled with the same one-arg shape as `0xA8` based on the `0x004e27b0` listing.
3. Left only two direct `VCall_GreatPower_*` usages in `TGreatPower.cpp`: `GetNodeContextSlot40` (registry byte-offset/name issue) and `CallSlotA1_NoArgs` in `0x004e1d50` (known bad signature/function-shape issue). These are now intentionally visible as follow-up targets, not hidden behind local shims.
4. Validation batched for the cleanup: `just build` and `just detect` clean; `0x004e27b0` improved **27.27% -> 36.36%**, `0x004ea150` improved **73.91% -> 78.26%**, and `0x004df010` held **44.49%**.

### TGreatPower remaining self-facade cleanup (2026-06-02, cont.)

1. Removed the final two `VCall_GreatPower_*` usages from `TGreatPower.cpp`.
   - `GetNodeContextSlot40` became real virtual slot index `0x10` / byte `0x040`: `this->GetNodeContextSlot10_Provisional()`.
   - `CallSlotA1_NoArgs` in `0x004e1d50` was replaced with the grounded three-arg `this->VTableSlotA1_Provisional(arg2, 1, arg1)` call.
2. Promoted `0x004e1d50` from a free `__fastcall` shim to `TGreatPower::ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2)`. Its thunk `0x00403c15` now forwards the two stack args from caller `0x005416b0`; the original thunk is a single jump and remains a thunk-shape residual.
3. Added local vtable-view structs only for non-`TGreatPower` receivers used inside the method (`TDiplomacyManagerAdvisoryVtbl` slot `0x44`, `TUiRuntimeDecisionPromptVtbl` slot `0x94`). These are not pass-through shims; they let the method call other recovered objects with normal virtual syntax.
4. Validation batched for the cleanup: `just build` and `just detect` clean; `rg "VCall_GreatPower|GreatPower_CallSlot" src/game/TGreatPower.cpp` returns no matches; `0x004e1d50` improved **33.71% -> 40.24%** after dropping false null checks; `0x004dc540` held **72.73%**; `0x005416b0` remains **23.08%**.

### TGreatPower non-self receivers: typed view-class dispatch + TUnitOrderState recovery (2026-06-02, cont.)

Landed the in-flight class-recovery pass that moves `TGreatPower.cpp` off generic
`vcall_runtime` / `Obj_*AtSlot` helpers for **grounded non-`TGreatPower` receivers**, and
recovered the `TUnitOrderState` -> `TCivWorkOrderState` hierarchy. Net **+2 aligned (143 -> 145
by reccmp function metric), 0 regressions** (verified by full HEAD-vs-WIP 100%-set diff).

1. **Typed view-class dispatch.** Replaced the `vcall_runtime`/`Obj_QueryIntAtSlot`/
   `Obj_CallNoArgAtSlot`/`Obj_CallIntArgAtSlot`/`Obj_CallPtrArgAtSlot`/`Obj_ReleaseAndClearSlot`
   helper family with `static_cast<View*>(...)->Method()` calls over local abstract view
   classes: `TStreamView`, `TListObject`, `TQueueObject`, `TMinisterObject`,
   `TRelationManagerObject`, `TDiplomacyTurnStateManagerView`, `TUiRuntimeContextView`,
   `TTerrainDescriptorView`, `TSecondaryNationStateView`, `TTrackedObjectView`,
   `TNationInteractionStateManagerView`. Object release/clear now goes through small typed
   `ReleaseAndClear1C/24/58<T>` templates. These give the recovered objects normal virtual
   syntax and supersede Active Constraint #4 for **grounded** receivers (facades still stand
   in for unknown/unstable receivers).
2. **TUnitOrderState / TCivWorkOrderState.** Recovered the order-state hierarchy and
   reassigned ownership in `config/symbols.csv` + `config/function_ownership.csv`:
   - `0x005c2530` `TUnitOrderState::RegisterUnitOrderWithOwnerManager` (4-arg `thiscall`):
     **0% stub -> 89.13%** as a real method that resolves the owner manager from
     `g_apTerrainTypeDescriptorTable[+0x44]` or `g_apNationStates[+0x89c]`, dispatches
     `TUnitOrderOwnerManagerView::VTableSlot12`, and stamps a unique id off
     `g_pLocalizationTable[25]`.
   - `0x005c2940` `TCivWorkOrderState::InitializeCivWorkOrderState`: **96.77% -> 100.00%**
     (now calls the real base `RegisterUnitOrderWithOwnerManager` instead of a
     `reinterpret_cast` thunk); callsites in `CommitCityRecruitmentOrderDelta` /
     `HandleTurnInstruction_Civi_*` cast the order object to `TCivWorkOrderState*`.
   - Removed the two stubs (`0x00402eeb`, `0x005c2530`) from `stubs_part002/020`. Their ILT
     thunks (`0x00402eeb`, `0x00404b33`) stay at 0% as the known single-`jmp`-vs-call/ret
     thunk-shape residual.
3. **g_pLocalizationTable direct read.** `ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`
   (`0x004dd470`) now reads `g_pLocalizationTable` directly (dropping the
   `ReadLocalizationRuntimeView()` null guard the original does not emit): **-> 100.00%**.
4. **TSortedPtrList layout.** Flattened the `reserved14` union to `short relationType; short pad16;`
   and updated `diplomacy_state.cpp` callsites (`->rel.relationType` -> `->relationType`).
5. **Pass completion fixes (this session).** The handed-off tree did not build: re-added the
   missed `missionQueue` conversions (`GetCountSlot48`/`Call54`/`Call18`/`AddTail30`) in
   `InitializeMapActionCandidateStateAndQueueMission` and `QueueMapActionMissionFromCandidateAndMarkState`,
   retyped `pad_44_ptr` to `TListObject*` (same 4-byte size, no layout change), and
   `#include "game/TIndexAndRankList.h"` so the `relationshipList->slot24()` (byte `0x24`) call
   resolves to the real foundation class.
6. **Validation.** `just normalize-markers` + `just build` + `just detect` clean. Targets:
   `0x004df010` **44.49% -> 45.13%**, `0x004e9ed0` **100%** held, `0x004dd470` **100%**,
   `0x005c2940` **100%**, `0x005c2530` **89.13%**, `0x004dc540` **72.73%** held. Full
   HEAD-vs-WIP 100%-set diff: gained `0x004dd470` + `0x005c2940`, **lost none**.
   `just compare-canaries` `below_floor=0` (all stretch_met); `just vtable-gate` passed;
   `just stats` aligned **145**, avg similarity **9.67%**, `dropped duplicate addresses: 0`.
   `just sync-ownership` (0 updates) + `just regen-stubs` re-run clean.

### TGreatPower vtable map stabilization: full shared-vs-override survey (2026-06-02, cont.)

Stabilized the `TGreatPower` vtable map before any slot renames. Evidence work only; no
source changes.

1. **Full vtable dumps.** `just ghidra-vtable-dump TGreatPower 0x00653938` and
   `... TAutoGreatPower 0x00654088` (184 slots each). Joined the two dumps on slot index to
   determine, per slot, whether `TAutoGreatPower` shares the `TGreatPower` entry or overrides
   it (same entry address = shared; different = override).
2. **Rewrote `docs/tgreatpower_vtable_evidence.csv`** (8 -> 38 rows, now with quoted args and
   two new columns `autogp_entry_addr` + `autogp_relation`). Covers every provisional slot the
   skeleton declares. Findings across the priority slots:
   - **Shared** (TAutoGreatPower uses the TGreatPower entry): `0x0e 0x10 0x12 0x13 0x1d 0x1f
     0x21 0x28 0x2e 0x45 0x5c 0x5f 0x64 0x66 0x69 0x6c 0x73 0x75 0x77 0x7a 0x7b 0x7c 0xa5 0xa8
     0xa9`.
   - **Overridden** by TAutoGreatPower: `0x01` (scalar-deleting dtor, expected),
     `0x6a` (GP `0x00405efc` / AGP `0x00407211`), `0x74` (GP body `0x004ddfc0` / AGP
     `0x00405b78`), `0x84` (GP `0x00405a9c` / AGP `0x00407b9e`), `0x85` (GP `0x004090b1` / AGP
     `0x004051ff`), `0xa1` (GP body `0x004e27f0` / AGP `0x00408bcf`). These get a paired
     `TAutoGreatPower` row.
   - **Caution flag:** slot `0xb3` is **NULL in the TGreatPower vtable** (`0x00000000`) but
     implemented in TAutoGreatPower (`0x0040360c`). Yet `TGreatPower::ApplyJoinEmpireResetAndClearDiplomacyCaches`
     calls `this->CallSlotB3_Provisional()`. Either that callsite's receiver is actually a
     `TAutoGreatPower`, or `0xb3` is past the true end of TGreatPower's own vtable. Do NOT
     promote `0xb3` until resolved.
3. **`just class-discovery "TGreatPower,TAutoGreatPower"`** cross-check:
   - Confirmed anchors (accepted, score 1): vtable `0x00653938` -> TGreatPower,
     `0x00654088` -> TAutoGreatPower. New: TAutoGreatPower classdesc `0x00653f90`
     (TGreatPower classdesc `0x00653688`).
   - Constructor report shows TAutoGreatPower's constructor (`0x004d89f0`) installs the
     **TGreatPower base vtable `0x653938`** first, grounding the
     `TAutoGreatPower : TGreatPower` inheritance edge by MSVC ctor-order ABI.
   - 24 high-confidence (P0, 5-lane: callers/decomp/this-passing/indirect/static) candidate
     `TAutoGreatPower::*` methods identified (e.g. `0x004e6b10 CreateTAutoGreatPowerInstance`,
     `0x004e6b80 DestructTAutoGreatPowerAndMaybeFree`, advisory/AI bodies `0x004e7cc0`,
     `0x004e7ec0`, `0x004e8040`). Saved for Phase 2 (override modeling) / Phase 4.
4. No build/score impact (evidence-only). Next: promote evidenced **shared** provisional slots
   to grounded names one at a time, model the six overrides on a `TAutoGreatPower` subclass,
   and resolve the `0xb3` null/receiver question.

### TGreatPower proposal-queue cluster: slot bodies resolved + slot 0x73 wired (2026-06-02, cont.)

1. **Tooling:** extended `tools/ghidra/listing_one.py` (`just ghidra-listing`) to print the raw
   instruction and follow unconditional `jmp` flow when an address is not inside a defined
   function, so an ILT vtable-entry thunk resolves to its real method body.
2. **Resolved the proposal cluster slot -> body map** (entry thunk -> body, all bodies already
   owned with grounded names):
   - `0x73` `0x00404c50 -> 0x004de2d0` `ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants`
   - `0x74` `0x004070e5 -> 0x004ddfc0` `ApplyDiplomacyPolicyStateForTargetWithCostChecks(int,int)` (AGP override `0x00405b78`)
   - `0x75` `0x004042ff -> 0x004de340` `SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int,int)`
   - `0x7a` `0x0040658c -> 0x004de790` `CanAffordAdditionalDiplomacyCostAfterCommitments(short)->bool`
   - `0x7b` `0x00403909 -> 0x004df010` `ApplyAcceptedDiplomacyProposalCode(short)` (canary)
   - `0x7c` `0x00404ea3 -> 0x004df370` `QueueInterNationEventForProposalCode12D_130(unsigned short)`
   Recorded in `docs/tgreatpower_vtable_evidence.csv` (current_name + status `body_identified`).
3. **Wired slot 0x73** (the clean case: real method had no direct callers and a matching
   void/void signature). Replaced the pure-virtual `FinalizeProposalQueueSlot73_Provisional`
   placeholder with the real method declared virtual at the slot position, removed its redundant
   non-virtual declaration, and pointed the caller (`0x004df5f0`) at it. Removed the now-dead
   `VCall_GreatPower_FinalizeProposalQueueSlot73` facade row and regenerated facades (135 -> 134).
   Zero codegen impact: body `0x004de2d0` held **63.33%**, caller `0x004df5f0` held **18.77%**;
   `compare-canaries` `below_floor=0`; `vtable-gate` passed; `stats` aligned **145** (delta 0).
4. **Blocker for 0x74/0x75/0x7a/0x7b/0x7c:** each real body is reached by its own ILT thunk via a
   *direct* (non-virtual) call (e.g. `thunk_...At004070e5` calls the body). Promoting the slot to a
   real virtual would turn that thunk call into a re-dispatch through the same slot (recursion), so
   each needs its thunk call qualified (`this->TGreatPower::Method(...)`) plus provisional-callsite
   signature reconciliation (0x7a/0x7b/0x7c are provisional `(int)` vs real `(short)/(word)`).
   Deferred to per-slot passes.
5. **Wired four more cluster slots in one batch** (0x75/0x7a/0x7b/0x7c). A direct-callsite sweep
   showed only `0x74` is entangled (its ILT thunk `0x004070e5` is an owned function doing a direct
   call); the other four thunks were never defined as functions, so the bodies had **no direct
   callers** and wire cleanly like 0x73. Replaced each provisional slot decl with the real method
   declared virtual at the slot position (real signatures: `0x7a (short)->bool`, `0x7b (short)`,
   `0x7c (unsigned short)`), removed the redundant non-virtual decls, renamed the virtual callsites
   to the real method names, and dropped the four now-dead facades (regen 134 -> 130). Single
   aggregate check: build/detect clean, `stats` aligned **145** (delta 0), `compare-canaries`
   `below_floor=0` (incl. `0x004df010` still floor_met). Only `0x74` remains (needs thunk
   qualification).
6. **Wired the last cluster slot 0x74.** Replaced the provisional slot decl with the real virtual
   `ApplyDiplomacyPolicyStateForTargetWithCostChecks(int,int)`, removed the redundant non-virtual
   decl plus a stale orphan free decl, and qualified the slot-0x74 ILT thunk's body call
   (`this->TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(...)`) so it stays a direct
   call instead of re-dispatching through the now-real slot. Dropped the last cluster facade (regen
   130 -> 129). The **whole proposal cluster (0x73/0x74/0x75/0x7a/0x7b/0x7c) is now wired to real
   virtuals.** build/detect clean; body `0x004ddfc0` held **23.15%**, thunk `0x004070e5` 0%
   (thunk-shape residual); `stats` aligned **145** (delta 0); `compare-canaries` `below_floor=0`.

### TGreatPower slots 0x1d/0x1f/0x2e: decompiled stubs + wired (2026-06-02, cont.)

Batch-decompiled three 0% stubs into real `TGreatPower` virtual methods at their slots
(the slot bodies were `stubs_part013.cpp` stubs, not free functions as first thought):
1. `0x1d` `0x004d8c00` `GetDiplomacyCounterA2()` -> `return this->diplomacyCounterA2;` **100%**.
2. `0x1f` `0x004ddb20` `GetDiplomacyState1C6ByTarget(short)` -> `return this->diplomacyState1c6[idx];`
   **100%** after a `#pragma optimize("y", on)` FPO wrap (original omits the frame pointer; build is `/Oy-`).
3. `0x2e` `0x004daa10` `SetNationPendingActionStateAndPayload(int index, short payload)` -> gated on
   `g_AdvanceTurnMachineState != -3`, writes `serializedStatusFlags[index]=0x32` and
   `field8d6[index]=payload`. **0% -> 71%** (also FPO-wrapped). Residual: the struct places the
   `field8d6` short array ~6 bytes too high (real base `0x8d6`); deferred since other field8d6
   users depend on the current layout.
For each: replaced the provisional pure-virtual decl with the real virtual at the slot position,
renamed callsites, updated `config/symbols.csv` to the real `__thiscall` prototype, removed the
stub (sync-ownership +3, regen-stubs), and dropped the dead facade (regen 127 -> 124).
Aggregate: build/detect clean, `stats` aligned **145 -> 147** (+2), `compare-canaries`
`below_floor=0`, `vtable-gate` passed. Lever: small leaf/getter slot bodies that read a single
field are quick 100%s once FPO-wrapped to match the original's frame-pointer omission.

### TGreatPower slots 0x21/0x77: wired owned bodies + reconciled signatures (2026-06-02, cont.)

Wired the two remaining sig-mismatch cluster-adjacent slots whose bodies were already owned but
dead/unwired:
1. `0x21` `0x004ddd50` `IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short)->bool` =
   `GetDiplomacyCounterA2()>0 && diplomacyState1c6[t]<0`. Fixed the stale `symbols.csv` prototype
   (`void/void` -> `bool/short`), switched the body to a `bool` result (so the return is `mov al,bl`
   not `test/setne`) and FPO-wrapped it: **0% slot / 70% body -> 100%**.
2. `0x77` `0x004de700` `CanAffordDiplomacyGrantEntryForTarget(short targetNationId, unsigned short
   proposedGrantEntry)->bool`. The provisional was 1-arg; the real method takes 2, so the callsite
   in slot 0x75's body `0x004de340` now passes `(targetNation, newGrantRaw)`. Body **62%**
   (model-correct first pass).
For both: replaced provisional decls with real virtuals at slot positions, removed redundant
non-virtual decls, dropped the two dead facades (regen 124 -> 122). Aggregate: build/detect clean,
`stats` aligned **147 -> 148** (+1, from 0x21), `compare-canaries` `below_floor=0`.

### TGreatPower slot 0x0e: decompiled + wired AddToNationMetricAtField10 (2026-06-02, cont.)

`0x0e` `0x004d7ae0` was a 0% stub: `void AddToNationMetricAtField10(int amount)` =
`this->pressureScore += amount` (field `0x10`). Decompiled + wired to slot 0x0e (11 callsites
renamed from the provisional `AdjustTreasurySlot0E`), real `__thiscall` prototype in symbols.csv,
stub removed (sync-ownership +1), facade dropped (regen 122 -> 121). FPO-wrapped -> **100%**.
`stats` aligned **148 -> 149**, `compare-canaries` `below_floor=0`.

Note (calling convention): the slot bodies decompiled in this run were all `__thiscall` methods
mislabeled `__cdecl` in the Ghidra autogen / symbols (they read `this` in ECX). True `__cdecl` in
this class are the static factories/helpers (e.g. `CreateTGreatPowerInstance` `void* __cdecl`).

### THandleStream constructor field-order fix (2026-06-03 00:30 CEST)

Reordered `THandleStream` fields so `position` is the dword at `this+0x10` and the byte flag stays
at `this+0x14`, then changed `THandleStream::THandleStream()` to use a plain body in the observed
write order instead of an initializer-list byte write. This fixes the constructor's pre-vtable
write mismatch.

Commands:
1. `just build` — passed; regenerated vcall facades unchanged, vtable gate passed, MSVC500 build
   completed.
2. `just compare 0x004895e0` — `THandleStream::ConstructTHandleStreamBaseState` **100%**.
3. Adjacent checks: `0x004895c0` **100%**, `0x00489640` **100%**, `0x00489610` still **90.91%**
   with only the existing call-target pairing residual (`<OFFSET1>` vs
   `DestructTHandleStreamAndMaybeFree_Impl`).<<<<<<< ours

### TGreatPower vtable programmatic mapping & candidate discovery (2026-06-03)

Analyzed the vtables of `TGreatPower` (`0x00653938`) and `TAutoGreatPower` (`0x00654088`) in Ghidra by tracking `this` register propagation to distinguish base-class `TGreatPower` state fields (offsets `< 0x964`) from subclass `TAutoGreatPower` overrides (offsets `>= 0x964`).
Key outcomes:
1. Programmatically resolved Ghidra's defined function thunks as well as raw jump assembly thunk structures (e.g. `jmp` / `jmpn`) via `Instruction.getFlows()`.
2. Discovered 19 unique unowned functions in `TGreatPower`'s vtable that belong physically to the base `TGreatPower` class state. Notable examples:
   - `0x004D9C70`: Misnamed `TCountry::HandleCityDialogHintClusterUpdate` in Ghidra but operates directly on base offsets up to `0x918`.
   - `0x004DF810` (`RebuildPrimaryNationStateForSlot_Impl`): Operates on `this` offsets `0x014` and `0x0A0` but was annotated as a free `__cdecl` function.
   - `0x004E1E40` (`ExecuteAdvisoryPromptAndApplyActionType2OrFallback`): Accesses offset `0x284` but was labeled as a free function.
   - `0x004DD040` (`SetDiplomacyTradePolicyValueForTargetAndMaybeClearGrant`), `0x004DDF90` (`ClearFieldBlock1c6`), `0x004E2270` (`RemoveRegionIdAndRunTrackedObjectCleanup`), `0x004E25C0` (`ResetNationDiplomacySlotsAndMarkRelatedNations`), and others.
3. The candidate list was recorded in these session notes; no separate `research_notes.md` file was
   left in the repo.

### TGreatPower cleanup after broken vtable-promotion batch (2026-06-03)

Cleaned up the prior in-progress `TGreatPower` attempt that had pasted raw Ghidra output into
manual source (`__thiscall` definitions, `undefined` temporaries, raw vtable indexing, and
unverified ownership/stub removals). Restored the source/stub/ownership state to a buildable
baseline and kept the vtable scan as candidate evidence only.

Then promoted the three small, grounded minister-field dispatch callbacks in repo style:
1. `0x004e78d0` `DispatchNationField98CallbackD4`: `this+0x98` / `interiorMinister->CallD4()` —
   **100%**.
2. `0x004e78f0` `DispatchNationField9CCallback4C`: `this+0x9c` / `defenseMinister->Call4C()` —
   **100%**.
3. `0x004e7990` `DispatchNationField94Callbacks90And94`: `this+0x94` /
   `foreignMinister->Call90(); Call94()` — **100%**.

Commands: `just build`, `just detect`, targeted `just compare` for all three addresses.

### TGreatPower vtable programmatic mapping & candidate discovery (2026-06-03)

Analyzed the vtables of `TGreatPower` (`0x00653938`) and `TAutoGreatPower` (`0x00654088`) in Ghidra by tracking `this` register propagation to distinguish base-class `TGreatPower` state fields (offsets `< 0x964`) from subclass `TAutoGreatPower` overrides (offsets `>= 0x964`).
Key outcomes:
1. Programmatically resolved Ghidra's defined function thunks as well as raw jump assembly thunk structures (e.g. `jmp` / `jmpn`) via `Instruction.getFlows()`.
2. Discovered 19 unique unowned functions in `TGreatPower`'s vtable that belong physically to the base `TGreatPower` class state. Notable examples:
   - `0x004D9C70`: Misnamed `TCountry::HandleCityDialogHintClusterUpdate` in Ghidra but operates directly on base offsets up to `0x918`.
   - `0x004DF810` (`RebuildPrimaryNationStateForSlot_Impl`): Operates on `this` offsets `0x014` and `0x0A0` but was annotated as a free `__cdecl` function.
   - `0x004E1E40` (`ExecuteAdvisoryPromptAndApplyActionType2OrFallback`): Accesses offset `0x284` but was labeled as a free function.
   - `0x004DD040` (`SetDiplomacyTradePolicyValueForTargetAndMaybeClearGrant`), `0x004DDF90` (`ClearFieldBlock1c6`), `0x004E2270` (`RemoveRegionIdAndRunTrackedObjectCleanup`), `0x004E25C0` (`ResetNationDiplomacySlotsAndMarkRelatedNations`), and others.
3. The candidate list was recorded in these session notes; no separate `research_notes.md` file was
   left in the repo.

### TGreatPower cleanup after broken vtable-promotion batch (2026-06-03)

Cleaned up the prior in-progress `TGreatPower` attempt that had pasted raw Ghidra output into
manual source (`__thiscall` definitions, `undefined` temporaries, raw vtable indexing, and
unverified ownership/stub removals). Restored the source/stub/ownership state to a buildable
baseline and kept the vtable scan as candidate evidence only.

Then promoted the three small, grounded minister-field dispatch callbacks in repo style:
1. `0x004e78d0` `DispatchNationField98CallbackD4`: `this+0x98` / `interiorMinister->CallD4()` —
   **100%**.
2. `0x004e78f0` `DispatchNationField9CCallback4C`: `this+0x9c` / `defenseMinister->Call4C()` —
   **100%**.
3. `0x004e7990` `DispatchNationField94Callbacks90And94`: `this+0x94` /
   `foreignMinister->Call90(); Call94()` — **100%**.

Commands: `just build`, `just detect`, targeted `just compare` for all three addresses.

### TGreatPower diplomacy need-score reset slice (2026-06-03 06:50 CEST)

Promoted three adjacent `TGreatPower` diplomacy/aid-budget methods from stubs into the real class
model:
1. `0x004dd140` `RecomputeDiplomacyAidBudgetScoreFromResourceWeights` — **84.62%**. This names
   vtable index `0x59` / byte offset `0x164` as a real virtual method and confirms the relation
   manager weight band at `relationManager+0x5c`.
2. `0x004dd1b0` `ResetDiplomacyNeedScoresAndClearAidAllocationMatrix` — **100% effective match**.
   This calls slot `0x59`, resets `diplomacyCounterB0`, `budgetPoolBase`, `budgetPoolDelta`, and
   clears aid-allocation columns.
3. `0x004dd270` `RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix` — **93.02%**. Same
   per-nation baseline refresh/aid-column clear path without the full accumulator reset preamble.

Also replaced vtable index `0x1e` / byte `0x078` with
`GetDiplomacyNeedScoreSlot1E_Provisional(int)`, grounded by both reset loops caching that vtable
entry and calling it for each nation. No static self-call shims were added; known `TGreatPower*`
receivers use direct virtual syntax.

Commands: `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`, targeted
`just compare` for all three addresses, `just compare-canaries` (`below_floor=0`), `just stats`
(aligned **+20**, paired **+41**, average similarity **+0.29 pp**).
### TradeControl promotion + ui_widget_shared.h scaffolding split (2026-06-03)

Promoted `TradeControl` out of `include/game/ui_widget_shared.h`'s anonymous
namespace into a single global header `include/game/TradeControl.h` (struct +
inline slot wrappers, verbatim). The per-TU anon copies were the last blocker to
globalizing the real trade-class headers (`TradeScreenContext`, etc.) that hand
back `TradeControl*`. Then split the global-scope scaffolding out of
`ui_widget_shared.h` into focused headers, leaving it a thin aggregator:

- `UiRuntimeContext.h` — `UiRuntimeContext` + `g_pUiRuntimeContext`.
- `win_rect.h` — `RECT` + `CopyRect`/`OffsetRect`.
- `quickdraw_guards.h` — `QuickDrawSurfaceGuard`, `ScopedMapQuickDrawContextGuard`
  + their construct/destroy thunks + `SetQuickDrawFillColor`.
- `ui_widget_thunks.h` — the loose ABI/lifecycle thunk declarations.

Kept the anonymous-namespace block (the 5 per-widget state structs, their
`g_vtbl*`/`g_pClassDesc*` placeholders, `TradeScreenRuntimeBridge`, control-tag
constants, `QueryActiveNationId`) inline in `ui_widget_shared.h`: relocating
anon-namespace types changes MSVC500's file-keyed mangling and would desync
`config/symbols.csv`. That extraction is deferred to a dedicated pass that also
re-runs the Ghidra/symbols resync (see INSTRUCTIONS note 84).

Investigation note: an intermediate per-class extraction (state structs moved to
their own headers / out of the anon namespace) was tried and reverted; a stray
`152` aligned reading turned out to be matcher jitter — HEAD, TradeControl-only,
and the shipped split all re-measure at **149** repeatably.

Commands:
1. `just build` — passed (links 100%).
2. `just stats` — aligned **149 (delta 0)**, coverage 99.98% (delta 0.00 pp).
3. `just compare-canaries` — `below_floor=0` (8/8).
4. `just format-check` on all touched headers — clean.

Also resolved a popped WIP stash (`THandleStream` ctor/vtable) whose changes were
already superseded by committed work; took the current HEAD version for
`stream.cpp`/`stream.h`/`symbols.csv` and dropped the obsolete stash.

### TGreatPower diplomacy need-score reset slice (2026-06-03 06:50 CEST)

Promoted three adjacent `TGreatPower` diplomacy/aid-budget methods from stubs into the real class
model:
1. `0x004dd140` `RecomputeDiplomacyAidBudgetScoreFromResourceWeights` — **84.62%**. This names
   vtable index `0x59` / byte offset `0x164` as a real virtual method and confirms the relation
   manager weight band at `relationManager+0x5c`.
2. `0x004dd1b0` `ResetDiplomacyNeedScoresAndClearAidAllocationMatrix` — **100% effective match**.
   This calls slot `0x59`, resets `diplomacyCounterB0`, `budgetPoolBase`, `budgetPoolDelta`, and
   clears aid-allocation columns.
3. `0x004dd270` `RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix` — **93.02%**. Same
   per-nation baseline refresh/aid-column clear path without the full accumulator reset preamble.

Also replaced vtable index `0x1e` / byte `0x078` with
`GetDiplomacyNeedScoreSlot1E_Provisional(int)`, grounded by both reset loops caching that vtable
entry and calling it for each nation. No static self-call shims were added; known `TGreatPower*`
receivers use direct virtual syntax.

Commands: `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`, targeted
`just compare` for all three addresses, `just compare-canaries` (`below_floor=0`), `just stats`
(aligned **+20**, paired **+41**, average similarity **+0.29 pp**).

### CArchive CheckCount → real method (2026-06-03)

Ported `0x006121cd` `CArchive::CheckCount` from a `__fastcall` free-function bridge into
a real class method — **100% match**. Removed the calling-convention reinterpret-cast
shape per the MSVC500 guardrail. Named the two touched fields: `m_pExceptionContext`
(+0x10, the name/context argument to `AfxThrowArchiveException`) and `m_nMapCount`
(+0x30, the object-map reference counter). Corrected the guard to `m_nMapCount >=
0x3ffffffe` so the emitted `cmp 0x3ffffffe; jb` matches the original (was `> 0x3ffffffd`
→ `jbe`).

Root-cause for the pairing failure after the method conversion: a Rule 3 violation — two
description comment lines sat between the `// FUNCTION` marker and the declaration, so
reccmp could not associate the marker with `CArchive::CheckCount`. Moving the comment
above the marker restored pairing. `0x00612000` `WriteCount` still 100%.

Also resolved a pre-existing unresolved merge conflict in this worklog (the
`||||||| original` / `=======` / `>>>>>>> theirs` block above), keeping both adjacent
entries.

Commands: `just build`, `just detect`, `just compare 0x006121cd` (**100%**),
`just compare 0x00612000` (**100%**), `just vtable-gate` (passed).

### CArchive Close + class-name getter (2026-06-03)

Two more archive-class leaves to **100%**:
- `0x00611d18` `CArchive::Close` — `Flush(this); m_pFile = 0`. Ground-truth disasm
  (`and dword ptr [esi+0x20], 0`) shows the zeroed field at +0x20 is `m_pFile`, not the
  "StreamCount" the provisional Ghidra name implied; `m_pFile = 0` reproduced the
  favor-size `and mem,0` exactly.
- `0x005e33c0` `GetTNetMgrClassNamePointer` — free `__cdecl` returning
  `&g_pClassDescTNetMgr` (data symbol at 0x0066f978); defined the global locally with
  the established `extern "C" { char g_pClassDescX = 0; }` pattern so the relocation
  pairs.

Skipped `0x00606fba` `GetCObjectRuntimeClass` for now: its returned pointer
(0x006706e0) has no named data symbol, so reccmp can't yet pair the relocation.

Commands: `just sync-ownership`, `just regen-stubs`, `just build`, `just detect`,
targeted `just compare` (both **100%**), `just vtable-gate` (passed).

### Empty no-op slot batch — 49 functions to 100% (2026-06-04)

Bulk-ported 49 empty vtable-slot / callback no-ops (free functions) into
`src/game/noop_slots.cpp`, all **100%**. Method: classify every unowned free
`__cdecl`/`__stdcall` "NoOp" candidate by its original epilogue via reccmp:
- plain `ret` → `void Name(void) {}`
- `ret N` → `void __stdcall Name(<N/4 int params>) {}` (callee-cleaned args)

Key finding: the originals are **FPO** (no frame pointer) even when they take
callee-cleaned stack args, but the global match flags use `/Oy-`, which wraps
`ret N` bodies in a `push ebp; mov ebp,esp; pop ebp` frame (40% similar). Added a
file-level `#pragma optimize("y", on)` to force frame-pointer omission; that took
every `__stdcall` no-op to 100% **and** repaired a pre-existing 40% entry
(`0x00412c10 NoOpTurnEventStateVtableSlot10`). Plain `void(void)` no-ops already
matched (empty body → bare `ret`).

Excluded 5 candidates (`0x4e0420`, `0x4e0440`, `0x4e1f20`, `0x4e2190`, `0x5d6e30`)
that are called by existing thunk wrappers under the generic `undefined4 (void)`
form (rule 9): their real `ret`/`ret N` ABI conflicts with the caller's mangling,
so they stay stubbed pending a callsite-cast follow-up. Note `sync-ownership` is
additive — removing functions from source needs a manual ownership-row prune.

Stats: aligned/original **+0.39 pp** (1.58%), paired globals **+1**, average
similarity **+0.39 pp**. `just vtable-gate` passed.

### Trivial-stub batch — 131 more functions to 100% (2026-06-04)

Extended the no-op lever to free `Stub`/`Return`/`Dummy`/`Ret*`-named functions:
classified 204 unowned candidates by original epilogue, ported the 131 that are a
bare `ret` (`void(void)`) or callee-cleaned `ret N` (`void __stdcall(<N/4 int>)`)
into `noop_slots.cpp`, all **100%**. No thunk-caller conflicts in this set. Two
candidates initially misclassified as bare-`ret` were actually `xor eax,eax; ret N`
(return 0): `0x0047fd70 ReturnFalseRuntimeSelectionAuxStatus` and `0x00534c20
ReturnZeroMissionVtableSlot2C` — fixed to `int __stdcall ...{ return 0; }`. The
FPO `#pragma optimize("y", on)` (added in the prior batch) keeps every `ret N`
epilogue frameless.

Method note for next time: classify the orig epilogue with one targeted compare
and bucket on the captured instruction string — `n=0 | 66.67%` = bare `ret`;
single `ret N` = stdcall; `xor al,al`/`mov al,1` = bool return; `xor eax,eax;
ret N` = `int` return 0 (this last one masquerades as bare-ret against the stub).

`just vtable-gate` passed.

### Constant-bool stub batch — 52 more to 100% (2026-06-04)

Third no-op-lever batch: free functions whose original is `xor al,al; ret[ N]`
(return false) or `mov al,1; ret[ N]` (return true). Ported all 52 into
`noop_slots.cpp` as `bool Name(...) { return false|true; }` — the 1-byte `bool`
return reproduces the `al`-width load (an `int`/`unsigned int` return would emit a
dword `xor eax,eax`/`mov eax,1` and miss). `__stdcall` for the `ret N` arg-cleaning
variants; FPO pragma keeps them frameless. No thunk-caller conflicts. All 52
verified **100%**; `just vtable-gate` passed.

Cumulative this session: 235 functions to 100% — 3 CArchive ports (CheckCount as a
real method, Close, GetTNetMgrClassNamePointer) plus 232 trivial stubs across three
`noop_slots.cpp` batches (49 empty no-ops, 131 empty/return-0 stubs, 52 const-bool).
aligned/original 1.18% → 2.99%.

### Autogen-body trivial sweep — 20 more to 100% (2026-06-04)

Broadened past name patterns by scanning `src/ghidra_autogen/*.cpp` for functions
whose decompiled body is a lone `return;`/`return <const>;`. That over-counts
(Ghidra renders terse getters the same way), so I re-classified each free candidate
by its real epilogue via reccmp and kept only the genuinely-trivial 20: bare `ret`
/`ret N`, plus **8-bit (`bool`)** and **16-bit (`unsigned short`)** zero returns —
`xor ax,ax` needs a `short`-width return type, `xor al,al` a `bool`. All 20 **100%**,
`just vtable-gate` passed. The 5 known thunk-referenced conflicts were re-excluded
automatically. After this, the trivial-empty/const-return vein is largely exhausted;
remaining trivial-looking autogen bodies are real getters (`mov eax,[ecx+..]`),
pointer/float-constant returns (`mov eax,<offset>` / `fld [g_..]`), or identity
(`mov eax,ecx`) — separate veins.

### CMapPtrToPtr class recovery + CArchive::WriteObject keystone (2026-06-04)

Ghidra archaeology on the CArchive object-serialization cluster. The autogen
modeled the embedded object map under the provisional "TNetMgr"; it is MFC's
**CMapPtrToPtr** (the CArchive store map, CObject* -> handle index). Recovered it
as a real class (`include/game/CMapPtrToPtr.h` + `src/game/CMapPtrToPtr.cpp`,
favor-size `optimize("ys")`), with 4 methods as real thiscall members — all
**100%**:
- `0x006033dd` InitHashTable — needed `call memset` (project's 0x5e9a90), not the
  favor-size rep-stosd intrinsic; use the repo memset thunk + typed callsite cast.
- `0x006034e4` GetAssocAt (hash `(key>>4) % size`, bucket walk)
- `0x00603481` NewAssoc (CPlex block grow via AllocateAndLinkBlockHead + freelist)
- `0x0060356b` GetOrCreateValueSlot (operator[] insert path)

Layout: `+4` m_pHashTable, `+8` m_nHashTableSize, `+0xc` m_nCount, `+0x10`
m_pFreeList, `+0x14` m_pBlocks, `+0x18` m_nBlockSize; CAssoc{next,key,value}=12B.

KEY LESSON: these map methods are dead-code-eliminated unless a live caller exists
(all their callers were stubs). The unlock was porting **CArchive::WriteObject**
(`0x006121e1`, vtable-live), which references GetOrCreateValueSlot -> the whole
chain links and pairs. Added `m_pStoreMap` (CMapPtrToPtr*) at CArchive +0x34, and
two object-virtual facades (CObject GetRuntimeClass slot0, Serialize slot8). Owned
`MapObject` (0x612315) and `WriteClass` (0x61240d) as CArchive methods with
pending bodies so WriteObject links/pairs.

WriteObject itself is at **51%** (deliberately not chased): structure + all call
pairings (MapObject, GetOrCreate x2, WriteClass, CheckCount, the two virtuals) are
correct; remaining diffs are facade `xor edx,edx` (edx_mode=zero should be none),
the object vtable not cached in one register, and the `objectRef==0` branch reusing
the arg register vs a separate epilogue.

### TGreatPower/TAutoGreatPower header split and TList hierarchy cleanup (2026-06-06)

Split the in-progress GreatPower class declarations into headers and moved the
TAutoGreatPower bodies into their own TU:
- `include/game/TGreatPower.h`
- `include/game/TAutoGreatPower.h`
- `src/game/TAutoGreatPower.cpp`

Added `tools/ghidra/function_slice.py` plus `just ghidra-function-slice` for quick
caller/callee/vptr-write/vcall evidence on class-recovery targets.

Promoted the current TAutoGreatPower slice:
- `0x004e6b30` class descriptor getter: **50.00%**
- `0x004e6b50` base-state constructor: **70.59%**
- `0x004e7810` aid-budget recompute/reset: **90.91%**
- `0x004e7be0` proposal replay/process queue: **81.63%**

Promoted `TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals`
(`0x004ddc30`) as a real virtual method at slot index `0x20` / byte offset
`0x80`; current score **63.16%** and canaries remain clean.

For the list foundation cleanup, confirmed from vptr-write evidence that
`RefCountedObjectBase` is a separate game-object root from MFC `CObject`.
`TPtrList` is the non-polymorphic common state wrapper
(`RefCountedObjectBase` vfptr at +0, embedded `CPtrList` at +4). `TList` and
`TSortedList` are the concrete polymorphic leaves, with vtables `0x00648f78` and
`0x00648ee0`; no constructor writes a standalone `TPtrList` vtable. Extracted the
former local `TListObject` virtual-call view into `include/game/TListObject.h` so
TAutoGreatPower/TGreatPower no longer carry a third ad-hoc list type in their
implementation file.

Validation:
- `just sync-ownership && just regen-stubs && just build`: clean
- `just detect`: clean
- targeted list constructor compares: `0x00487e50`, `0x00487a90`,
  `0x00488400`, `0x004ee4b0`, `0x004ee540` all **100.00%**
- `just compare-canaries`: `below_floor=0`
- `just vtable-gate`: passed via build

### TGreatPower vtable scope assessment + first leaf-slot wins (2026-06-06)

Inspected what remains to port for `TGreatPower`. Findings (ground truth from the
178-slot vtable `0x00653938` cross-referenced against `config/function_ownership.csv`
and `build-msvc500/reccmp_report.json`):

- 143 fns owned in `src/game/TGreatPower.cpp`: 35 at 100%, 104 partial, 4 pairing-fail.
- Of 178 vtable bodies: 77 owned (62 TGreatPower.cpp + 15 noop_slots.cpp), **101 unowned
  (~98 genuine GP-region virtuals 0x004d7xxx–0x004e2xxx + 3 shared-low)**. These ~98 are
  the bulk of "the rest"; currently stubbed as `TAutoGreatPower_VtblSlotXXX` in
  `src/autogen/stubs/` (Ghidra mis-attributes inherited base virtuals to the derived class).
- False positives in the bucket: `0x00601f1d`→CPtrList; the 3 shared-low + the `return 0`
  no-op slots (0x004d7f60, 0x004e0400) already owned by noop_slots.cpp.
- Structural blocker: most remaining slot bodies self-dispatch to *sibling* slots (e.g.
  slot 0x56 `0x004e03a0` calls vtable+0x130/+0x154 = slots 0x4c/0x55, both unowned). To
  match these without facades they want the whole vtable declared as real virtuals together.

Ported (promote → real virtual → build → compare):
- slot 0x6a `0x004ddb80` `SnapshotDiplomacyState1c6Into250` → **100%** (1c6→250 array copy).
- slot 0x69 `0x004ddb40` `SetDiplomacyState1c6ClampedToCounterA4` → 68.97% → **100%** after
  `#pragma optimize("y", on)` (leaf FPO, heuristic 38). Renamed provisional callsites in
  `ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`.
- `just compare-canaries`: below_floor=0.

### TGreatPower structural pass — first vtable-virtual clusters (2026-06-06, cont.)

Ran `tools/ghidra/create_vtable_body_functions.py` (writable Ghidra pass) to
CreateFunction the 61 undefined TGreatPower vtable-slot bodies (saved to the live
vendored project; re-runnable, idempotent — required before decompiling these bodies).

Wired vtable slots from provisional pure-virtuals to real TGreatPower virtuals:
- 0x69 `0x004ddb40` SetDiplomacyState1c6ClampedToCounterA4 -> 100% (FPO)
- 0x6a `0x004ddb80` SnapshotDiplomacyState1c6Into250 -> 100%
- 0x63 `0x004dd770` / 0x64 `0x004dd7b0` relationManager fieldB6 set/add -> 100% each.
  Key: added `fieldB6[0x17]` to TRelationManagerObject and called the real `Refresh80`
  virtual instead of the `RelationManager_RefreshSlot80` vcall_runtime facade — that
  removed the facade's spurious `xor edx,edx`; CSE'ing the manager pointer into a local
  removed the double-load. (Confirms heuristic: real virtuals beat facades.)
- 0x66 `0x004dda40` DecrementDiplomacyCounterA2Slot66 -> 100% (FPO leaf)
- 0x6d `0x004dde80` GetTrackedSlotEntryCountLow -> 100%
- 0x6e `0x004dde30` AnyTrackedSlotEntryHasZeroField4 -> 90.6% (logic-complete; FPO gap)
- 0x70 `0x004ddf20` AssignPayloadToTrackedSlotEntryMatchingField2 -> 64.5% (logic-complete; FPO gap)
  Added TQueueObject.entryCount(+8) + TDiplomacyTrackedEntry record; entries via real
  GetEntryAt1BasedSlot2C virtual.

Net: 6 slots to 100%, 2 logic-complete (FPO-only gap). `compare-canaries` below_floor=0.
Remaining unowned GP-region vtable bodies: ~91 (was ~98). Next: continue clusters;
an FPO sweep would close the two partials.
