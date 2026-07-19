---
name: data-modeling
description: Recover globals, tables, structs, and field types for the Imperialism decomp — promoting raw addresses to named globals in global_data_tables, struct-vs-parallel-globals decisions, dual-width field reads, short/int/pointer field typing evidence, datacmp verification. Load when a function reads unlabeled .data/.rdata addresses, when reccmp shows operand-symbol mismatches on globals, when deciding a field's true width/signedness, or before declaring any new global or struct.
---

# Data and struct modeling

Every referenced global must be a named symbol in `global_data_tables.{h,cpp}` with a
`symbols.csv` GLOBAL row — a raw `reinterpret_cast<int*>(0x6955f0)` never pairs its
operand and hides the table from datacmp. Read the actual bytes from the original
binary before declaring initializers, then verify with `just datacmp`.

Field-typing evidence (from strongest to weakest): the WIDTH of the original's loads
and stores (`movsx word` = short, `movsx byte` signed char…), signed vs unsigned
compares, construction-site writes, sibling accessors, the Mac oracle. When readers
disagree, type by the widest reader and cast at the narrow sites (see field note).

## Field notes

### Deserialization and stream shape
*(ex decomp-loop note 10)*


- Preserve aggregate read/write sizes from Ghidra (`0x0C`, `0x180`, ...) instead of
  expanding into element loops unless the original clearly does.
- Use stream-vtable read return values for loop bounds; do not reuse pointer params as
  scalar counts. Preserve original `short`/`int` loop truncation semantics.
- Keep refill stages (stream-read marker + conditional queue push) even if a simplified
  version compiles — omitting them caps similarity in the 20s–30s.
- Avoid defensive null-guards in hot legacy deserialization paths unless the original
  has them; extra guards usually hurt similarity.
- Prefer typed global-slot helpers (`ReadNationStateSlot`, ...) over raw address cursors.

### Type safety: distinct classes, opaque slots, and cast-free call sites
*(ex decomp-loop note 17)*


When a `reinterpret_cast` between two *named* classes looks necessary, stop — it is usually
a modeling error, and the fix removes casts rather than relocating them.

- **Don't infer an object's type from a neighbouring signature.** A method parameter typed
  `TEvent*` does not make whatever is passed there a `TEvent`. Confirm the object's real
  class from its constructor/vtable, `config/recovered_globals.csv`, `symbols.csv`, or the
  Mac oracle *before* typing or casting. Worked example: `ProcessQueuedWarTransitions`
  routes a `TNextTradeCommand` (a `TCommand`) into `DoEvent`'s `TEvent*` argument;
  `TCommand` ≠ `TEvent` (Mac evidence: `PostCommand(TCommand*)` vs `PostAnEvent(TEvent*)`),
  so that is a genuine pun in the original — keep that one cast, comment it, and type
  everything else correctly.
- **A polymorphic slot's parameter is `void*`.** If different overrides interpret the same
  vtable slot's argument differently (slot 0x0d: `TEventHandler` reads a `TCommand`, a
  `TView` draw path passes a `RECT*`), the honest base signature is `void* payload`; do the
  interpretation (`static_cast<TCommand*>(payload)`) inside each override body. Every call
  site then converts implicitly, and the single irreducible pun lives in one body. Picking
  one caller's type forces every other caller to `reinterpret_cast`.
- **Type pointer-bearing fields as typed pointers.** `TEventHandler* targetHandler` (not
  `int field10`) plus a typed init-helper argument lets call sites pass real objects by
  implicit upcast with zero casts.
- **"Dual-use" is a defect label, not an explanation — investigate, never rationalize.**
  When one offset appears to be a pointer in method A and an `int` in method B, the default
  is that *something is mismodelled*, not that the game intentionally overlays two meanings.
  In order of likelihood: (1) wrong receiver/class attribution on A or B; (2) wrong offset
  because the base or derived layout is wrong; (3) two adjacent fields/arrays scanned as one
  flat region; (4) one identifier domain (e.g. a tile index feeding parallel tables) given
  two different prose descriptions; (5) two distinct concrete classes merged into one; only
  (6) a genuine variant field controlled by a discriminator or per-instance role. Rule out
  1–5 from the raw listing (`just ghidra-listing`), the writer/reader inventory (`just
  xrefs`, `just field-xrefs`), and the layout oracle before ever concluding (6). While
  unresolved, keep the slot raw and mark it `// UNRESOLVED_FIELD_ATTRIBUTION:` with both
  readings + evidence addresses — **do not** write "dual-use"/"dual-purpose" prose and do not
  leave `reinterpret_cast<int>(ptr)` in a member store as the model. A *proven* variant
  (all eight criteria in AGENTS.md's type-modeling guardrail) is expressed as a real
  `union` / variant payload / separate record type / discriminator-keyed accessors, e.g.
  `union { TZone* zone; TGlobalMapCityScoreRecord* city; } target;` beside its `int
  attachment` discriminator — never a raw `int` + scattered casts. `just dual-use-gate`
  rejects the terminology and the pointer↔int member stores.
  - *Worked correction:* `TDealBookPicture::field98` was called an `int` "picture id" that
    was also a control pointer. It is neither dual-use nor an id: it is the `'guob'` sub-
    control pointer (a `TView*`), cached in RefreshHud and read as a `CaptureLayoutF0` view
    receiver in RefreshTradeSelection; the `SetPictureResourceIdAndRefresh` call that looked
    like it consumed it actually takes a separate bitmap-id local (the callee forwards to
    `LoadBmpResourceByIdCached`). Retyping to `TView*` removed every cast and improved the
    match — the "dual-use" story was masking a plain mismodel.
- **Renames and pointer↔pointer / int-as-int narrowing are codegen-neutral — verify and
  proceed fearlessly.** reccmp pairs by address and these casts emit no bytes, so `just
  compare <addr>` should be byte-identical. Use this to align `vmethodNN` identifiers to
  curated `symbols.csv` names (reuse the name, don't invent a third) and tighten types.
  Catch: update an override's signature in lockstep with the base (§14). The TU-fragility
  caveat (§16) applies when the touched header feeds a saturated TU.

### Two adjacent same-typed fields always used together are probably one field
*(ex decomp-loop note 22)*


Two adjacent `short`s (from Ghidra's default per-access typing) that every usage
reads/writes as a pair are usually **one** 4-byte field: check the write site (usually
the ctor) for a single `mov dword ptr [this+off], reg`. The split shape costs real score
where a caller compares the combined value in one op (two `cmp`s instead of one
`cmp dword`). Evidence: `TShip` +0xc was two shorts; one `int` restored the single
`cmp dword ptr [x+0xc],0` in `TZone::HandleKeyDown` (17.25%→28.85%).

### One "table" read at five different offsets is one struct, not five globals
*(ex decomp-loop note 24)*


Ghidra names a global by the *first* byte offset it sees, so a struct array accessed at
base/+4/+8/+0x10/... becomes several separately-named "tables". Tell: `g_Foo_0x...`
globals 4–8 bytes apart, all indexed with the **same per-element stride** (every read
does `index * 0x24`). Verify in the disassembly (the decompile hides it), then merge
into one real struct type + one array; raw-offset accessors collapse into named field
reads. Evidence: five "navy order lookup tables" at 0x698108–0x69811c were one
`TNavyOrderResourceDescriptor[64]` — and the split had caused two real bugs (a
wrong-stride read and a read from a disconnected local buffer).

### Field-by-field snapshot copies are a struct-recovery oracle
*(ex decomp-loop note 28)*


When a function copies a record wholesale but element-wise, the bytes it SKIPS are the
struct's padding, and every separately-copied slice is a real field boundary. Evidence:
DispatchCityRedrawInvalidateEvent 0x54abf0 snapshots the 0xa8 record and skips exactly
0x09/0x3d/0x96-97, proving fields that had been folded into pads. Use the copy to refine
the record, then rewrite the copy through typed fields.

### Mine reccmp diffs for global identities (`just global-xref-oracle`)
*(ex decomp-loop note 32)*


reccmp renders an unresolved original operand as `<OFFSETn>` while the recomp side
shows the real PDB symbol (`[g_Foo (DATA)]`). Each such positionally-paired mismatch
line is a vote that the original address belongs to that symbol; applying a voted pair
is just adding an `addr|name|||global||xref_oracle` row to symbols.csv — no marker or
rebuild needed. Round 1 (min 2 votes, no conflicts) moved 31 functions to 100%. The
conflict column doubles as an annotation-audit: consistent votes AGAINST an existing
row mean the row is probably wrong.

### "Cached context singleton" globals dispatched via `[ecx+slot]` can just be real CDC*
*(ex decomp-loop note 35)*


Before modeling a mystery "surface context" class behind vtable-slot calls, check whether
the callees are already-linked MFC methods: `CDC::SelectObject` is `virtual` at slot 0x30,
`CDC::SetTextColor` at 0x38, while `SetMapperFlags`/`SetTextAlign`/`OffsetWindowOrg`/
`LineTo` are plain direct calls — a global dispatching through both a vtable slot AND
direct calls with the same `ecx` is almost certainly a genuine `CDC*`/`CFont*`.
Cross-check virtual-vs-direct against the vendored `afxwin.h`. Retyping
`g_pScopedMapQuickDrawDcHandleObject` from `void*` to `CDC*` dissolved hand-rolled
`+4` offset hacks into a plain member access. Also: struct-by-value MFC returns
(`CPoint OffsetWindowOrg(int,int)`) push a caller-allocated hidden pointer *last* —
a `SUB ESP,N` at entry that's never read back is often that scratch buffer.

### All globals belong in global_data_tables — never architect around codegen noise
*(ex decomp-loop note 47)*


**Globals go in `global_data_tables.{h,cpp}`.** Declare every shared global in
`global_data_tables.h`, define it in the `.cpp` — including plain untracked subsystem
scratch tables. Do **not** stash a global in a subsystem `.cpp` with local `extern`s to
keep a widely-included header byte-identical: that was a wrong reaction to a phantom.

The phantom: recompiling a float-heavy TU flips commutative-FADD leaves
(0x4e0590–0x4e0690, `fld [tblA]; fadd [tblB]`) 100%→43% because MSVC reorders the
operands. `a+b == b+a` — **that "regression" is meaningless.** Ignore such flips — do
not revert real structure, relocate globals, or contort the design to defend a phantom
100%. Accept the delta and `just stats-baseline-update`. Same for sub-1pp
register-allocation wobbles in neighbouring functions when a TU grows.

Corollary: reccmp's per-function % is a matching *aid*, not a score to defend. A drop
caused by operand order, register allocation, or scheduling in code you did not change
is not a regression worth a single line of work.

- **Read a runtime-global's true value from `just datacmp -a`, not a hand-rolled
    VA->file-offset dump.** When modeling a global referenced by an `fmul/fld [0xADDR]`,
    a raw PE-section read can land on the wrong bytes (e.g. reported 0.0 for what reccmp
    shows as 0.2f). datacmp prints `orig : recomp` for the symbol -- use that value in the
    `float g_x = <value>;` initializer. A zero initializer also lands the global in BSS,
    which datacmp reports as `(uninitialized)` and DIFFs against an initialized original;
    a non-zero initializer forces .data. (RecomputeTileStrategicScoreHeatmap 0x518130,
    g_TileHeatmapNeighborDiffusionFactor 0x658780 = 0.2f.)
  *(ex decomp-loop list-note 80)*

### Dual-width global reads: type by the widest reader, cast at the narrow ones
*(ex decomp-loop note 118)*


When one function loads a global as a full dword (`MOV reg, dword [g]` then uses both the
sign-extended low word AND the raw dword) while another reads it `MOVSX reg, word [g]`,
model the global as `int` and have word readers write `static_cast<short>(g)` — MSVC500
emits `MOVSX reg, word ptr [g]` for a (short) cast of an int lvalue in memory, so both
codegen shapes fall out (g_wMapDialogViewportTileSpan 0x6a33b0: 0x51adf0 dword reader,
0x51ac40 movsx-word reader). A `short` global can never reproduce the dword load.

### Never model overlapping views with a union: pick one model, migrate all accessors
*(ex decomp-loop note 119)*


This is the opposite situation from a genuine *discriminated variant* field (one slot whose
value's TYPE is chosen by a discriminator — e.g. `MapContextActionRecord::tileOrObject08`
keyed by `actionType04`, modeled as a `union`; see the dual-use rule above). Here there is no
discriminator: different code just *reads the same bytes two ways*, which means one reading is
the true model (almost always an array) and the union "both views" answer is wrong — always.
Determine the single true model and migrate every accessor to it: the named flags usually turn
out to be
specific indices of the array (TTechMgr::OrderCapRow's fort/recruit "flags" were
techStatusByTechId[0x0b/0x16/0x13...]; TGlobalMapCityScoreRecord's stage1/stage2
"counters" were resourceDevelopmentCounts82[1..8]). Before merging, verify every access
site's RECEIVER is the same class/table (same global, same stride, same base offset) —
distinct classes sharing a layout region are not the same object (TCommand ≠ TEvent).
Keep the semantic map (index → meaning) in the struct comment, and land the migration as
one pass over all users (grep the old field names to zero before building). Renamed
accesses are codegen-neutral; confirm with the affected functions' baseline scores.

- **A referenced .rdata data table Ghidra never symbolized shows up as `g_prev+N` in the
     reccmp diff — give it its own `global` row in symbols.csv so both sides pair.** When a
     ported function reads a const table (e.g. 0x66ac10) that has no symbol, reccmp attributes
     the ORIGINAL reference to the nearest preceding global (`g_anCapabilityPriorityRangePairs+106`)
     while the RECOMP references your new `g_..._0066ac10` — same address, different symbol, so
     the operand never pairs and the score sticks low. Fix: define the table with the correct
     values read from the binary (`va2off` + `struct.unpack`), then add a bare
     `ADDR|g_name_00ADDR|||global||` row in symbols.csv (globals have no size, so no
     overlap-gate issue). reccmp then resolves the original address to your symbol (exact match
     beats `+N`) and the reference pairs. Then, to match MSVC's address *grouping* when a
     table-driven byte offset is added to `this` and the record base is a struct member: the
     original keeps `[this + fieldOffset]` as the pointer with the member displacement (0x268)
     and row stride (`row*0x1d`) riding the addressing mode — reproduce by
     `reinterpret_cast<TCls*>((unsigned char*)this + fieldOffset)->memberArray[row].firstByte`,
     NOT `&memberArray[row]` byte-indexed by fieldOffset (that folds 0x268+row*stride into the
     base and mis-groups). Fold the `this` cast inline (no named `self` local) so `this` stays
     in ECX (`add esi,ecx`) instead of being copied to a callee-saved reg. Took 0x5b0a20 from
     26%→74% (residual is one MSVC regalloc quirk on the first `&&` branch — not worth chasing).

  *(ex decomp-loop list-note 105)*

- **Two writes at a fixed offset delta inside one bounded loop = parallel arrays, not one
     long array.** 0x50f860 inserts `record id` at `[slot]` and a companion tile at
     `[slot+0x18]` under the same k<0xc bound, and the 0x518840 byte-swapper swaps `[p]` and
     `[p+0x18]` pairs in a 0xc-count loop → TGlobalMapCityScoreRecord's `[0x18]` short array is
     really `adjacentRegionIds0A[0xc]` + `adjacentRegionAnchorTiles22[0xc]`. Grep for existing
     `[i + 12]`-style accessors before splitting — they confirm the boundary and are exactly the
     sites the split cleans up.

  *(ex decomp-loop list-note 108)*

- **A 16-bit store spanning a byte field and its "pad" (`mov word ptr [..+0x1c],1`) means the
     field is really a short.** Retyping (TTerrainStateRecordView::activeFlags1c uchar→ushort)
     turns two-store sites (`flags = X; pad[0] = 0;`) into the matching single word store, and
     `&`-mask reads / `|=` low-bit writes on the short still compile to the orig's byte-wide
     test/or forms, so existing 100% users keep matching. It also deletes the
     `*reinterpret_cast<short*>(&...)` copy hacks at snapshot sites.

  *(ex decomp-loop list-note 109)*
