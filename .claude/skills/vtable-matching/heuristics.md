# Field notes (vtable-matching)

Accumulated matching lessons for this skill's domain (migrated from the old
decomp-loop heuristics file; append new ones here).

### Vtable dispatch as real virtuals, not facades
*(ex decomp-loop note 4)*


The legacy `VCall_*` facade layer has been removed — always add real `virtual`
methods on the owning class and call `obj->Virtual()` directly. Real virtual dispatch
lets MSVC cache the vtable in a register across calls, matching the original. This is
AGENTS guardrail + [[model-real-classes-not-callconv-casts]].

- Verify slot **byte offset vs index** before converting: `index = byte/4` for most
  objects, but some generated GreatPower facades use a raw index (`SlotA1` = 0xA1).
  Grep the reccmp diff for the emitted `call [reg+0xNN]` after building.
- For opaque receivers whose class isn't recovered, use a local abstract "vtable-view"
  struct of pure virtuals up to the needed slot and cast the pointer to it — this
  works for `this` too (vptr is at offset 0), giving real `mov ecx; mov eax,[ecx];
  call [eax+slot]` without making the whole class polymorphic. `0x004df010` 34%→44%.
- Big-vtable classes (TGreatPower = 178 slots) self-dispatch to sibling slots on
  `this`; declare the **whole slot range** as real virtuals in one structural pass
  (bodies may temporarily delegate) so sibling calls resolve to real virtuals. Verify
  ownership against `config/function_ownership.csv` first — no-op slot bodies live in
  their owning class files. See [[next-tgreatpower-vtable-scope]].
- The slot macro arg / `// slot 0xNN` comments are **decimal** (slot 0xb0 = index 176).

### Declaration-order drift bug
*(ex decomp-loop note 12)*


A duplicated or over-sized declaration shifts every later slot/field by a constant.

- The tell-tale is a hand-written byte-offset cast where a named member "should" work,
  or a diff showing `call [reg+0xNN]` / `[esi+0xNNN]` off by a constant from the named
  slot/field. **Fix the declaration** (delete dup decls, shrink the array) — don't add
  more casts. Array-indexed accesses off the array base are immune; only members
  declared after the insertion point shift.
- Applies to both vtable slot decls (`TListObject` realign, 2026-06-10) and field
  layouts (`TGreatPower.serializedStatusFlags` over-declared `[0x0D]` → `[8]`).
- Before promoting a standalone interface's calls to real virtuals on an MFC-derived
  class, verify each "override" actually overrides the base slot (matching signature) —
  a redeclared-but-not-overriding virtual becomes a NEW appended slot (+misalignment).
  See [[diplomacy-state-cleanup-progress]].

### 12b. Vtable-not-matching: the five recurring defects

`override` is `#define override` (empty) in `compat.h` — MSVC500 has no override
keyword, so the compiler matches an override to a base slot purely by **name +
signature**. A derived "override" whose name/signature differs from the base virtual
is silently appended as a NEW slot → "Recomp vtable is larger than orig" + every later
slot shifts. Driving `Vtables not matching` down is mostly finding these. Five patterns,
all source-only (edit header/cpp → `just build` → `just vtable`):

1. **Duplicate virtuals for one slot** — generated `Orphan*`/`cmd_slotN` placeholder
   decls PLUS hand-written typed decls for the same slots ⇒ 2× the slots. Delete the
   junk set, keep the real typed methods (TBehavior, TCommand).
2. **Wrong base class** — a class whose vtable shows TObject bodies (Serialize 0x485e90,
   WriteTo 0x485f70, ShallowFree 0x415ce0 at 0x08/0x14/0x24) but is modeled `: CObject`
   or base-less. Reparent to `TObject` and drop the redundant slot decls
   (TCommand→TObject, TStream→TObject). TObject vtable is 0x6485c0, 10 slots.
3. **Missing base virtuals** — base header stops short, so derived new/override virtuals
   land early. Add the missing virtuals to the base in slot order (TPtrList 0x64-0x78,
   TStaticText 0x1c4-0x1d4).
4. **Phantom trailing virtuals** — base declares `virtual` methods past the real vtable
   end (orig shows "not annotated" tail). De-virtualize them (TAnimation 3 trailing).
5. **Junk-named overrides** — derived overrides named `Free`/`OwnerPanel`/`OrphanX`
   instead of the ancestor's real slot name ⇒ appended. Rename to the exact base virtual
   name+signature. Per-class, laborious; signatures must match exactly.

Plus a non-vtable infra tell: a slot-4 scalar-dtor mismatch where two `symbols.csv` rows
share the `Class::\`scalar deleting destructor'` name → reccmp mispairs our `~`. Make the
sibling-class row's name unique (TSortedPtrList vs sibling 0x649010).

### 12c. Retire ILT thunks by deleting the named `symbols.csv` row — don't cast them

When the original calls through an ILT jmp thunk (`CALL 0x409a11` → real target), reccmp
auto-resolves the thunk to the real function **only if the thunk address has no named
`symbols.csv` entry**. A named thunk row (`thunk_Foo`) makes reccmp compare
`call thunk_Foo` vs your `call Foo` as a literal symbol mismatch (caps the caller ~93%);
a row-less thunk resolves to 100% for free. Fix: **port the real target into its correct
file** (real body, `// FUNCTION:` marker, `sync-ownership`), delete the thunk's rows from
both `config/symbols.csv` and `config/thunk_map.csv`, then call the real function
directly — never declare the thunk with a typed signature and `reinterpret_cast` it, and
never whitelist a stub in `tools/stubgen.py` (both are banned hacks). Took
`TView::Refresh` 93%→100% (QuickDraw DC family). Watch conventions: MFC `CDC::FromHandle`
&c. are `PASCAL`/`__stdcall` — a `__cdecl` cast adds a spurious `add esp,4`.
See [[imported-thunks-block-vtable-resolution]], [[ilt-thunk-retirement]],
[[banned-operator-new-cdecl-factory]].

### "Same address in two sibling vtables" is inheritance, not COMDAT folding — check RTTI first
*(ex decomp-loop note 20)*


Two supposedly-sibling classes whose vtables point at *identical* original addresses for
several slots looks like linker folding of identical bodies. It isn't — this link does
not fold identical functions across TUs (§52). The real cause is almost always that one
"sibling" is the **base class** of the other, and the shared address is an inherited,
unoverridden virtual.

- **Check the RTTI ancestry before modeling either theory**: every vtable slot 0 is the
  `CRuntimeClass` getter, and the descriptor's `+0x10` is `m_pBaseClass` — an intact
  ground-truth chain. `uv run python -m tools.ghidra.vtable_slots "ClassA=0xVTABLE"`
  prints the full ancestry as a side-effect log line. Cheap and deterministic — run it
  before ever writing a "shared/COMDAT-folded" comment.
- A derived ctor calling the *grandparent's* ctor directly is just the trivial parent
  ctor being inlined — not evidence against a normal inheritance edge.
- **Fix once the real base is confirmed:** repoint the base, delete the duplicate
  override decls+bodies for genuinely-inherited slots (address matches the base's own),
  fix the ctor init list. Slots with a *distinct* address are genuine overrides — keep.
- Worked example: `TBeachheadMission`/`TBlockadePortMission` really derive from
  `TControlSeaZoneMission` (not sibling of it); fixing the base took both vtables to 100%
  (+33 aligned functions). See [[tmission-comdat-fold-was-inheritance]].

### Library vtable addresses need a decorated-symbol row, or every dtor pays
*(ex decomp-loop note 39)*


A statically-linked MFC vtable address (e.g. CObject's `??_7CObject@@6B@` at
0x66fec4) that only has a name-typed `global` row in `config/symbols.csv` classifies
the original-side reloc as DATA while the recomp side is VTABLE — reccmp then counts
a diff line in *every* destructor that stores it (the ubiquitous
`mov [ecx], offset CObject::vftable` tail of inlined base dtors). Fix: give the csv
row the decorated symbol (`66fec4|CObject::`vftable'|??_7CObject@@6B@||global||`) so
`match_symbols` pairs it exactly. One such row took `TViewMgr::~TViewMgr` 50%→100% and
improved ~50 functions. Corollary: a fully-optimized derived dtor can compile to a
*single* store of the root-base vtable + `ret`, so a 7-byte "SetXxxBaseVtable"
junk-named function called only from a scalar deleting destructor is that class's real
`~T()` — claim it with a `// SYNTHETIC:` block, never model it as a vtable-reset helper.

### A `call [eax+0xNN]` vs `call [eax+0xMM]` diff = wrong virtual at the callsite
*(ex decomp-loop note 44)*


Map byte-offset → named method with slot_index = byteOff/4 and the header's
`// slot 0xIDX` comments (repo convention even names methods by byte offset:
`Call30` = byte 0x30, `RefreshSlot40` = byte 0x40). Fix is swapping the method name at
the callsite, no signature change. (`TMission::ReadFrom` 0x5358a0 called
`RefreshSlot40()` where the original dispatches `Call30()`, 98%→100%.)

### Extractor over-extends a class vtable to swallow adjacent one-slot vtables
*(ex decomp-loop note 45)*


The generated `// slot 0xNN … 0xADDR` block appends every non-NULL pointer up to the
next *known* vtable, so a class whose table is followed in memory by small helper
vtables (often 1-slot `stretch<T>`) gets those foreign slots mis-attributed. Tell: a
run of NULL slots (the real abstract tail) then 1–2 more non-NULL "slots" whose targets
operate on a different `this` shape (touch only `[ecx+4/8/c]` = a stretch header, not
the class's layout). Confirm by resolving the slot pointer and checking which *global*
installs it as a vfptr — that global is the real owner. Fix: move the `// FUNCTION:`
markers onto a real concrete subclass of the helper template, rename the symbols.csv
rows, and leave the helper vtables unannotated when they overlap the host's vtable DATA
region (pair by address marker to avoid the collision gate). Turned two empty
"TMapMaker" stubs (0x52a760/0x52c0a0) — really `SeaSegmentStretch/SeapointStretch::
GetOrAppendUnique` — from 0–9% into 93%/91%. Corollary: a `stretch<T>` element size
reads straight off the grow strides (`n*0x30`/fallback `n*0x18` ⇒ 0x18 element), and a
by-value append copies exactly `sizeof/4` dwords — independent structural evidence.

### Recover a polymorphic NULL-abstract-slot's real receiver by scanning every vtable's byte offset
*(ex decomp-loop note 53)*


`TView` declares many high slots as NULL abstract placeholders that different subclass
trees fill with genuinely different-arity methods — so "byte 0x1e4" is not one method,
and a caller whose arg count contradicts the slot's arity in the class you *assumed*
means the receiver is a different subtree. Recovery recipe (proved the turn-event
'main' view is a `TDiplomacyMapView`, not a `TWorldView`):

1. Collect every `// VTABLE: IMPERIALISM 0x…` address (grep the headers).
2. For each vtable V, `just ghidra-read-data 0x<V+off> ptr` — keep non-null slots.
3. Resolve each filler's ILT thunk (`just ghidra-listing`), filter by the caller's
   needed arity via the target's `ret N`.
4. Map survivors back to vtable → class header; cross-check domain evidence (the class
   that also *stores* the tag constant is the receiver family). `just func-status`
   names the method.

Then wire the caller as `static_cast<TRealClass*>(resolve(...))->Method(args)` — a
codegen-neutral downcast plus the real virtual (0x5d7090 →100%). Different callers of
the same handler family can have different receivers — don't assume one recovery
covers the set.

### Cross-check a header's assumed vtable-slot order against a REAL call site before trusting it
*(ex decomp-loop note 54)*


`TSortedList.h`'s `GetCount()`/`GetEntryByOrdinal()` are declared assuming they're the
first new virtuals after AddHead/AddTail-family slots (byte 0x48/0x4c), matching a
prior session's declaration-order guess — but a real, already-shipped call site
(`TCountry::SeedInitialMilitaryAndNavyOrdersForOwnedRegions`, 0x004d71b0) shows the
ORIGINAL binary dispatching `GetCount()`/`GetEntryByOrdinal(ordinal)`-shaped calls
(0-arg count check vs. 1-arg ordinal fetch, argument counts confirmed via `push`
presence and `ret N`) at byte **0x28/0x24**, not 0x48/0x4c — visible directly in
`just compare 0x004d71b0`'s diff (`-call [edx+0x28]` / `+call [edx+0x48]`). This
mismatch is NOT new-function-specific: it already caps that committed function at
56.50% and will cap every other `ownedRegionList`/`militaryUnitList44`-touching
function the same way (confirmed again independently in
`TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask`, 0x511f30 → 18.59%).
Don't trust a header's declared vtable slot order from declaration position alone —
before writing new code against a base class's virtuals, check ONE real call site's
raw disassembly (arg count via push+ret-N, not just address) against the header's
assumed byte offset. A full fix needs runtime evidence (ideally winedbg) for
TSortedList's entire slot layout, since even the class's own static vtable dump can't
disambiguate on its own (two different in-binary vtable copies for the same class
were checked, both self-consistent with the header's WRONG assumption for the early
slots) — this is flagged as follow-up work, not patched piecemeal per function.

- **Never place a forward declaration between a `// VTABLE:` annotation and its
    class.** reccmp attaches the annotation to the next class-like declaration, so
    `// VTABLE: ...` + `class TOther;` + `class TReal {...}` silently pairs the
    vtable with TOther and fails `just vtable` with a confusing cross-class diff
    (hit three times in one session: TArmyTacUnit, TNavyBattle, TTacNavyToolbar).
    Put fwd decls above the class comment block.

  *(ex decomp-loop list-note 62)*

- **A block of junk-named `return 0` virtual-slot stubs (`VirtualSlot64/6C/70/74/78`)
    can hide a complete real algorithm -- check `ret N` and the Mac oracle before
    trusting any stub body.** TSortedList's six "no-op" sort slots were a full MacApp
    quicksort (Sort/SortBy/Compare/QuickSort/QSPartition + a default-compare
    trampoline), with symbols.csv rows that were outright wrong (QuickSort labelled
    Destruct*AndMaybeFree, Compare labelled Construct*BaseState). Two tells: the stub's
    claimed address had `ret 8`/`ret 0x10` (arguments the decl dropped), and the Mac
    evidence listed Sort/SortBy/Compare/QuickSort/QSPartition on the same class. Six of
    eight addresses hit 100% once the real shapes were written. Comparator shape:
    `short(__cdecl*)(void* a, void* b, void* context)` with the verdict in AX; Sort()
    passes a trampoline + the list as context to dispatch the virtual Compare. The
    parallel CPtrArray-backed chain (TSortedPtrList/TPtrList, same junk-named stubs in
    TPtrList.cpp, vtable 0x649010 / ctor 0x488400) still needs the same treatment, as
    do TNavyMission's two big score stubs (0x537270/0x537610). Recon for those two:
    all three helper thunks resolve to already-ported TShip order-node methods
    (GetNavyOrderNormalizationBaseByNationType 0x5505a0,
    ComputeOrderNodeDistanceQuotientByDescriptorWord24 0x550550,
    ComputeNavyOrderPriorityContributionPercentByCategory 0x54ff00), and
    TNavyMission.cpp's AccumulateNavyOrderVectorFromNode is the ported sibling
    idiom for the 4-float category-profile build; the remaining work is the
    squared-distance-vs-referenceVector math with several inline float-global
    constants that must be read from the raw listing (the Ghidra decompile garbles
    the stack profile arrays). (Follow-up resolved:
    the TSortedPtrList/TPtrList chain landed with 18/19 addresses at 100% plus all
    five leaf comparator overrides -- and exposed a real save-corruption bug in
    TTradeMgr::WriteTo. The 0x4acb60 idle hook turned out correctly attributed to
    TBattleReportView's own vtable slot 0x37 via note-74 checking -- it is just an
    unported 2041-byte body, still open.)

  *(ex decomp-loop list-note 76)*

- **Before acting on a triage `[call_target]` line that names a vtable slot, run
    `just vtable <Class>` — an already-100% vtable means the line is a misalignment
    artifact, not a missing virtual.** Triage reported
    `dword ptr [eax + 0x48] vs TMinor::SetDiplomacyStandingSlot48 (FUNCTION)` inside
    TGreatPower::SetNationTransferTargetCodeAndNotifyEligiblePeers (0x4de860), which
    looks like "slot 0x48 should dispatch a named virtual but our callsite calls it
    non-virtually." Investigated it fully: `just vtable TMinor` and `just vtable
    TCountry` both already report **100% match**, so slot 0x48 (index 18) is correctly
    modeled on both sides; `SetDiplomacyStandingSlot48` is an *unmarked, unpaired*
    internal helper (not in `symbols.csv`, no `// FUNCTION:` marker), not the slot body.
    The `[eax+0x48] vs <name>` line was reccmp pairing the orig's slot dispatch against a
    Ghidra name while our structurally-divergent function had an unrelated instruction at
    the aligned offset — an artifact of the diff misaligning a heavily-reshaped body, not
    a real vtable defect. Lesson: a `call_target` line that fingers a vtable slot is only
    a real bug if `just vtable <owning Class>` is below 100%; when it's already 100%,
    don't restructure the base vtable — the residual is the caller's own codegen
    divergence (see note 91). Cheap to check, saves a large wrong-headed base-class edit.

  *(ex decomp-loop list-note 90)*

- **`undefined`→`void` on a vtable slot with a trailing `+xor al,al` is a clean single-
    function win ONLY when no override redefines the slot — batching the whole slot is
    gated by every override being ported.** Removing the phantom `return 0;` (and the
    `undefined` return) took the standalone slot TTacticalBattle::ExecuteTacticalDigAction
    (0x5a3640, no overrides) 98.82%→100% in one edit. But the same fix on
    TAnimation::AdvanceAnimationTickAndInvalidateOnFrameFlip (0x49f140, base 97.87%→100%)
    forces its ~5 `override`s to `void` too (a void base can't have `undefined`/`return 0`
    overrides), and the unported stub overrides — previously `{ return 0; }`, which the
    NOOP gate ignores because a return statement isn't "empty" — become truly-empty `{}`.
    The `just noop-gate` then correctly fails `empty_but_big` on TIdleMeAnimation (0x4aca60),
    whose original is a real body (virtual gate-call on ownerView04 slot 0x13 + a
    g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(registryTag18) via ILT 0x4030a8).
    That override can't be ported without resolving a polymorphic view slot (TView slot 0x13
    is DispatchVslot134…(RECT*)void, but IdleMe calls it as char(int) — a concrete-view-type
    ambiguity), so faking it or a false `// NOOP` are both wrong, and the whole batch had to
    be dropped. Rule: only batch a slot-wide return-type narrowing when EVERY override is
    already a real port (or a genuinely small/empty original); otherwise land the isolated
    no-override slots (like 0x5a3640) and leave the shared slot until its stubs are ported.

  *(ex decomp-loop list-note 94)*

- **CDialog / CWnd vtable slots don't fail from ICF — MSVC500 doesn't fold — they
    fail from trivial-stub pairing ambiguity + symbols.csv mislabels.** After
    re-parenting the dialog subtree onto real MFC `CDialog` (note: TModalDialogBase :
    CDialog, see the 0x6050d0 retirement), a `// VTABLE:` marker on a dialog class shows
    the four dialog-specific slots modelled (scalar dtor / DoModal override at index 48 /
    Prepare+Cleanup new virtuals at 54/55) and the *non-trivial* inherited CWnd slots
    pairing (Create/DestroyWindow/WindowProc/OnInitDialog/OnOK/OnCancel), but ~15
    **trivial** CCmdTarget slots (index 7-21: IsInvokeAllowed/GetDispatchIID/
    GetTypeInfoCount/GetTypeLibCache/GetTypeLib and the OLE aggregation/connection
    virtuals, all `return 0`/`return 1`/`return this` 2-6 byte stubs) show as mismatches.
    Diagnosis steps and result:
    (a) **It is NOT ICF/COMDAT folding.** Rebuilt with `-DIMPERIALISM_MATCH_LINK_FLAGS_CSV=
    /OPT:NOICF`; the output binary differed from the folded build in only ~15 bytes (PE
    timestamp + a few debug-dir bytes) — MSVC 5.0's linker predates `/OPT:ICF` and does
    no identical-COMDAT folding. `/OPT:NOICF` is a no-op here; do not reach for it.
    (b) **Root cause: dozens of identical trivial stubs are ambiguous to pair**, and the
    orig-side rows are mislabelled in `config/symbols.csv` (e.g. 0x606c4e = a 6-byte
    `return 1` is named `TTechStorePage::CloseCityDialogChildrenAndReleaseSelf`; it is
    really `CCmdTarget::IsInvokeAllowed`). reccmp then can't map orig↔recomp for those
    slots and picks a wrong name.
    (c) **The fix is the CObject.cpp pattern applied to the whole CDialog vtable**
    (0x0066fc2c, 54 slots): model `CObject->CCmdTarget->CWnd->CDialog` as LIBRARY with a
    `// LIBRARY: 0xADDR` + canonical MFC name per slot, taking the slot order from the MFC
    headers (afx.h CObject: GetRuntimeClass/~/Serialize/AssertValid/Dump; afxwin.h
    CCmdTarget: OnCmdMsg/OnFinalRelease/IsInvokeAllowed/GetDispatchIID/GetTypeInfoCount/
    GetTypeLibCache/GetTypeLib/...; CWnd: ...Create/DestroyWindow/PreCreateWindow/... at
    index 22+) — NOT from the body-ambiguous oracle, which mis-guesses the trivial slots
    (`AfxGetAfxWndProc`×5, `COleUILinkInfo::AddRef`×4). Verify the non-trivial anchors
    against the raw vtable (Create=0x60820b idx23, WindowProc=0x60820b… OnInitDialog=
    0x605445 idx49, OnOK=0x6054aa idx51, OnCancel=0x6054c3 idx52, DoModal=0x6051b9 idx48).
    (d) **Complication making this a dedicated pass, not dialog-local:** those trivial MFC
    stubs are shared across many game-class vtables (the addresses are currently owned/
    named after game classes like TTechStorePage), so renaming+LIBRARY-annotating them is
    a binary-wide MFC-vtable-modelling effort that touches those game classes' vtables
    too. Until it's done, leave the dialog `// VTABLE:` markers unclaimed (the four
    dialog-specific slots are already real virtuals; see TModalDialogBase.h).

  *(ex decomp-loop list-note 98)*

### CView/CFrameWnd-family vtable LIBRARY pass: align the RECOMP vtable slot-by-slot, don't guess names
*(ex decomp-loop note 89)*

The note-88 pass (claim inherited MFC slots as LIBRARY so a CView/CFrameWnd-derived class
vtable can be marked and reach 100%) is driven from the **recompiled** vtable, which is
ground truth because it is built from real nafxcw.lib. Method that worked for CIncludeView
(`0x648418`, 68 slots, all 18 remaining red slots resolved, +0.11pp, no regressions):
1. Dump the ORIG vtable (`just ghidra-vtable-dump Class 0xADDR`) → slot byte-offset → orig
   addr. Game overrides appear as `0x40xxxx` ILT thunks (reccmp resolves them) or `0x48xxxx`
   game addresses; the red LIBRARY slots are direct `0x60xxxx/0x613xxx/0x614xxx` addrs
   carrying junk `symbols.csv` names.
2. Read the RECOMP vtable (`??_7Class@@6B@` from `cvdump -p`; its pointer array) and resolve
   each recomp slot → mangled symbol via the PDB's `S_GPROC32`/`S_PUB32` records.
3. Align by **byte offset** (identical MFC layout): recomp name+symbol at offset 0xNN is the
   canonical identity of the orig addr at offset 0xNN. VALIDATE the alignment on 3-4 slots
   that are already green (e.g. `CView::OnPrepareDC/OnUpdate/OnPrint`) before trusting it,
   and confirm orig and recomp vtables are the **same length** — if recomp is longer
   (extra OCC/OLE tail), the class can't reach 100% and it's a structural divergence, not a
   naming bug.
4. Emit one `config/msvc500_library_overrides.csv` row per red slot
   (`addr|CView::Name|<recomp mangled symbol>|<prototype>|nafxcw|<obj>|evidence`); take the
   mangled symbol verbatim from the recomp PDB, never hand-mangle. `just regen-stubs` applies
   them. These are shared nafxcw functions, so the rows also fix every other CView-family
   vtable that references them — run the full `just precommit` (all vtables) to confirm no
   regression.
5. Slot 12 (`0x30`) `GetMessageMap` is the class's own compiler-generated override (from
   `BEGIN_MESSAGE_MAP`), NOT a library slot — claim it with a `// SYNTHETIC:` marker +
   `?GetMessageMap@Class@@MBEPBUAFX_MSGMAP@@XZ`, same as the dialog GetMessageMaps.
Only after every slot pairs can the `// VTABLE:` marker go on (the vtable gate requires 100%
for marked vtables). A subagent is well-suited to the mechanical step-2/3 triangulation.

### A game "override" that forwards to the base but isn't in the orig vtable slot is a mis-attribution — check the raw slot
*(ex decomp-loop note 90)*

Extending note 89 to the CFrameWnd family (CMainFrame vtable 0x6488d8, 63 slots, 100%): most
slots were already claimed by the CDialog+CView passes (shared CObject/CCmdTarget/CWnd base),
leaving 5 CFrameWnd library slots (PreTranslateMessage/PostNcDestroy/IsFrameWnd/GetActiveFrame/
DelayUpdateFrameMenu) + 3 class-specific (GetMessageMap slot 12 SYNTHETIC, scalar-dtor SYNTHETIC,
a real WinHelp override). Two transferable lessons:
- **Slot 12 GetMessageMap and the scalar deleting destructor are per-class SYNTHETIC**, claimed
  with `// SYNTHETIC:` + `?GetMessageMap@Class@@MBEPBUAFX_MSGMAP@@XZ` / `??_GClass@@UAEPAXI@Z`
  (add the `??_G` row to symbols.csv if Ghidra never emitted the function).
- **When a class declares `virtual X() override` whose body just forwards to `Base::X()`, verify
  the ORIGINAL vtable slot actually points to that game function — not the inherited library
  one.** CMainFrame carried a bogus `CMainFrame::PreTranslateMessage` (forwarding to
  `CFrameWnd::PreTranslateMessage`), but orig slot 0x98 held the *library* CFrameWnd function
  (raw bytes `B7 C7 61 00` = 0x61c7b7). The function it was mapped to (0x413a20) is referenced
  from a *different* vtable (ImperialismApp slot 0x60, via thunk) and its body calls
  `CWinThread::PreTranslateMessage` — so it was really `ImperialismApp::PreTranslateMessage`
  (a CWinApp/CWinThread override) mis-attributed to CMainFrame with a wrong base call. A
  forwarding override that installs a function the original never put in that slot both breaks
  the marked vtable and hides the real owner. Re-home by: raw-reading the orig slot, xref'ing
  the function to find which vtable actually references it, and confirming the base call in the
  body identifies the parent class.

### Name shared base vtable slots from a coherent in-file protocol, not one slot at a time
*(ex decomp-loop note 102)*


The TEventHandler/TView base declares ~10 `vmethod_00NN` placeholder virtuals overridden by
~200 UI subclasses; each rename touches ~200 files. Don't invent names per isolated slot.
Instead read the base `.cpp` for a *cluster that calls each other* and name the whole protocol
at once. TEventHandler's active-view arbitration was fully legible in one file:
`IsActiveView` (0x22, `this==root->GetActiveView()`), `TryDeactivateActiveView` (0x20, asks the
incumbent to step aside), `GetDeactivateVetoCode` (0x18, veto gate: 0=allow), `OnDeactivated`
(0x19) and `OnDeactivateVetoed` (0x1a) notification hooks, plus `DetachUiResourceOwnerIfMatches`
(0x23, inverse of `SetUiResourceOwner` 0x24). Slots whose base is a bare `return 0;`/no-op with
no in-file caller (`vmethod_0017/0023/0081`) stay hedged — no evidence to name them.

Execution: the rename is codegen-neutral (reccmp pairs by address), so a word-boundary
find/replace across `src/game`+`include/game` (NOT autogen) + symbols.csv is safe — the `override`
keyword makes the compiler reject any inconsistency, and `just vtable` confirms 0 slot drift.
1191 replacements across 199 files, build green, all affected vtables still 100%, stats +0.
The Mac oracle gives candidate *names* but never the slot→name mapping (Hard Rule 12); derive
the mapping from behavior, then optionally cross-check the name exists in the Mac symbol list.

- **Resolve a method's real address through the vtable's ILT thunks before trusting a
    header slot comment — a body can be mis-attached across two markers even when
    `just vtable` reads 100%.** `just vtable` scores the slot-pointer *correspondence*, not
    the function *bodies*, so a swapped body/marker pair passes it while both functions
    score badly. Ground-truth recipe: dump the orig vtable (`objdump -s --start-address=
    <vtable+slot*4> …`), take the slot's dword (an ILT thunk `0x40xxxx`), then
    `objdump -d` that thunk to read its `jmp <realAddr>`. Documented pre-existing tangle in
    TForeignMinister (both branch and origin/main): vtable slot 0x1a→0x52fdc0, slot
    0x1e→0x530200. The real terrainSlot=7 "update per-nation interaction enable flags" body
    is at 0x52fdc0 (slot 0x1a) per disasm (`xor bl,bl; mov esi,7`), but the source models
    0x52fdc0 as an empty `MinisterSlot1A(short)` stub (0%) and attaches that terrainSlot=7
    body to the `UpdateNation…()` method marked 0x530200 (really QueueTurnEventHint, a big
    SEH fn, symbols.csv l.3498) → 6%. The header comment "slot 0x1e (0x0052fdc0)" is wrong.
    Fix (needs class-recovery/vtable-matching care, not a routine tick): swap the slot-0x1a
    and slot-0x1e *declarations* so the terrainSlot=7 body lands in slot 0x1a with marker
    0x52fdc0 (drop its phantom `short arg` — RefreshForeignMinisterState 0x52fd10 calls it
    arg-less; that's the lone `+push 0` diff there), stub 0x530200 as QueueTurnEventHint, and
    re-verify each caller's dispatched slot offset (`call [reg+off]`) before trusting the
    rename. Vtable stays 100% through the swap because the pointer pairing is unchanged.
    RESOLVED (commit d3373409): no declaration reorder was even needed — the markers were
    already correct (line-33 method→0x52fdc0=slot 0x1a, line-42→0x530200=slot 0x1e); only the
    *bodies+names* were swapped. Moved the terrainSlot=7 body onto the 0x52fdc0 method
    (renamed UpdateNation, void, arg dropped), stubbed 0x530200 as QueueTurnEventHint, fixed
    the three call sites by dispatched slot. 0x52fdc0 0%→51%, RefreshForeignMinisterState
    →100%, vtable still 100%. Confirmed the definitive arg check: 0x52fdc0 ends in `c3`
    (`ret 0`) so it's void — Call90's `push eax` before `call [edx+0x68]` (no cleanup) is a
    partial-port artifact, not a real short param.

  *(ex decomp-loop list-note 99)*

- **vtable-abi baseline fixes: match the callee family, and know when a slot is genuinely
  un-fixable.** `just vtable-abi-audit` flags slots whose declared stack-arg count (the C++
  signature's dword count) disagrees with the binary RET immediate. Most are trivial: an
  orphan/stub override declared `()` that the binary ends `RET 0x4` just needs one added
  param — model the arg from a caller if one exists, else an opaque `int`/`undefined4` (the
  body ignores it, dispatch is type-erased). Always verify the *whole override chain*
  (base + every override) shares the RET immediate before editing; the base is often
  un-flagged yet identical, so fix its declaration in lockstep (C++ `override` forces one
  signature). Cleared this way in one session: Animation slot 0x2c (`POINT* offset`),
  production-order slot 0x0e (dropped a phantom `const char*`, ported the two non-stub
  bodies), TGreatPower orphan slot 0xfc, InfoBar-text slot 0x7f, TTask slot 0x0a,
  TTacticalBattle slot 0x12, TCzechBox slots 0x75/0x77 — 32 baseline rows.
  **The un-fixable case:** when only *some* overrides of a slot return a value (or take an
  arg) while the base and siblings do not, the original binary is internally inconsistent
  and no single C++ signature matches both sides — changing the base to cover the outlier
  regresses the base's own body. Example left as a permanent baseline residual:
  `DispatchSlot9CToLinkedChildren` (slot 0x27, ~180 TView-hierarchy classes) — only
  TEditText's override 0x4907a0 returns `this->field_94` (a `CMcWindow*`) that 2 callers
  consume; TView (0x48c820) and TWindow (0x48de00) end plain `ret` with no deliberate
  return. Declaring the hierarchy `CMcWindow*` would force a bogus `return` into the base
  impls. Same shape appears when one caller pushes an arg a plain-`ret` callee ignores
  (production-order 0x4b5620's lone TGreatPower caller): match the many callee definitions,
  accept the one caller's ~1pp loss, don't contort the signature.
