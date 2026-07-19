# Ghidra DB mutation ledger

The vendored Ghidra database (`vendor/ghidra/exports/Imperialism.gzf`, LFS) is
planned to be replaced with a newer DB in a separate folder. Everything below is
the record of what has mutated the DB, so the still-wanted mutations can be
re-run against the new database.

## 2026-07-19 (latest): CDataExchange/CView added to the MFC datatype pack; TypeResolver stub-exclusion fix

`tools/ghidra/apply_mfc_datatypes.py`'s `MFC_MODELS` gained two verified layouts
(measured from the vendored `vendor/msvc500/headers/mfc/include/afxwin.h`, not
guessed): `CDataExchange` (0x10 bytes, 4 fields, afxwin.h:1224-1245) and `CView`
(0x40 bytes, one field beyond its CWnd base, afxwin.h:3536-3612). Applied via
`just apply-mfc-datatypes --apply` and persisted with `just export-project`.

This was the single largest `opaque_pointee` bucket in the structural signature
audit: ~23 `DoDataExchange(CDataExchange*)` overrides across every MFC dialog-
template class were graded opaque_pointee purely because `CDataExchange` had no
real size/fields in the DB, even though every one of those signatures was
already logically/ABI converged — only the semantic type-identity grade was
weak. Verified live: `opaque_pointee` 39 -> 11, `exact_complete` +23,
`semantically_converged` +23 (`just structural-signature-audit`).

Applying `CView` for the first time exposed a PRE-EXISTING, previously-invisible
bug: a stale `/Demangler/CView` 1-byte stub (the C++ Demangler analyzer's own
auto-generated placeholder) had been silently "winning" `TypeResolver`'s
simple-name lookup because no real `/CView` existed yet to collide with it.
Once the real datatype was added, naive name-collision counting would have
flagged `ambiguous_simple_name` for a real-definition-vs-disposable-stub pair —
violating the "ambiguous_simple_name stays zero" invariant the 67-dedup work
(commit `409a6aa5`) established. Fixed at the RESOLVER level, not by deleting
the DB stub (the existing `dedupe_ambiguous_datatypes.py` refused to remove it:
a `/Demangler/CView *` pointer with no root counterpart of its own still
references it, so cascading the deletion needed more care than this pass
wanted to risk): `TypeResolver.__init__`'s simple-name selection is now the pure
`select_named_datatype()`, which excludes `/Demangler/*` stub candidates from
the ambiguity count the same way it already excluded bare `FunctionDefinition`
candidates (a Win32 function-pointer typedef's pointee signature) — two
instances of the same principle (a known-disposable placeholder category is not
a genuine competing definition), not two unrelated special cases.

Also added `_SCALAR_TYPEDEF_ALIASES` to `TypeResolver`: five project-local
scalar typedefs (`include/game/nation_domain_types.h`: `NationSlot`,
`ProposalCode`, `GrantEntry`, `NeedType`, `RelationDelta`, all `typedef short`)
are pure C++ source constructs Ghidra has zero visibility into — they resolved
`unresolved` with no table entry mapping them to their real underlying
primitive. `unresolved` 16 -> 12 live.

New read-only `tools/ghidra/weak_pointer_type_inventory.py` (`just
weak-pointer-type-inventory`) builds a distinct-type inventory over every
remaining `opaque_pointee` / `generic_pointer_fallback` / `unresolved` grade
(48 distinct types after the fixes above) and classifies each as
`canonical_game_class_exists` / `canonical_mfc_type_exists` /
`typedef_or_namespace_spelling_mismatch` / `missing_external_opaque_type` /
`stale_duplicate` / `genuinely_unknown` — the remaining backlog (12
`canonical_mfc_type_exists`, e.g. `CFile`/`CFont`/`CScrollBar`/`COleDataObject`/
`CPrintInfo`, are further MFC_MODELS candidates; 12 `missing_external_opaque_type`
like `CREATESTRUCT`/`WAVEFORMATEX` are correctly-opaque Win32/CRT types needing
no further work; 24 `genuinely_unknown` are real class-recovery gaps).

## 2026-07-19: `apply_mfc_rtti` stops creating class-layout datatypes (code change, no DB re-apply)

`apply_mfc_rtti.py` had two code paths (`ensure_class_struct`'s "no preserved
root struct" branch and `ensure_root_class_dt_for_curated`) that independently
built a NEW root class struct (via `build_class_struct`, now removed) whenever
none existed yet, sized from RTTI `m_nObjectSize` with only a `vftable` field
and opaque `field_0x..` base-flattened bytes. This is a second, cruder class-
layout authority competing with `apply_class_model.py` (Clang AST + MSVC500
layout oracle + RTTI cross-check) -- worse, an empty/opaque stub it created for
a not-yet-modeled class is exactly the kind of duplicate `TypeResolver` indexes
by simple name and can pick over the real one once `apply_class_model` later
lands the correct struct (see the `ambiguous_simple_name` fix above/below).

Both call sites now only REUSE an existing canonical root struct (refreshing
its vftable-pointer field to the newly-typed `<Class>Vtbl`) and otherwise defer
entirely -- no struct is created, sized, or replaced. A class not yet reached by
`apply_class_model` is left alone (`class_struct_deferred` stat) rather than
filled with a stub. `apply_mfc_rtti.py` keeps its read-only-adjacent job scope:
CRuntimeClass descriptor mining, vtable identification/naming, and Ghidra
runtime-class (DECLARE_DYNAMIC) namespace/inheritance-edge naming -- no
independent game-class datatype creation, no empty root stubs, no separate
class-hierarchy authority. `tools/ghidra/rtti_class_oracle.py` remains the
actual read-only RTTI evidence extractor (walks CRuntimeClass, never opens the
project writable).

This tool is not wired into `ghidra-apply-source-full` (it has its own
standalone `just apply-mfc-rtti` target), so the change did not require
re-running it with `--apply` against the live DB; verified via dry-run (no
crash, `descriptors=458 vtables=407 overrides_renamed=2425` unaffected) plus
the full gate/test/stats suite.

## 2026-07-19: `ghidra-rename-class` tool + full autogen convergence (committed)

Added `just ghidra-rename-class OLD NEW --vtable 0xADDR --apply`
(`tools/ghidra/rename_class.py`) — the atomic class re-attribution the ledger's
"class renames should be atomic" note called for. It migrates, in one transaction: the
function namespace, the class datatype (Ghidra rewrites applied `&_vftable_`
construction-site references automatically), the vtable-struct datatype, the
`::'vftable'` label, and removes the emptied namespace. Verified end-to-end against the
`TSoundChannelNode` → `TLongintList` case (vtable 0x650a08): after `--apply` the DB had
zero `TSoundChannelNode` remnants.

**Convergence landed.** After clearing the 3 stale overrides (below), a single clean
`sync_exports` regenerated `src/ghidra_autogen` + `include/ghidra_autogen` from the live
DB and `just export-project` re-wrote the vendored `.gzf` so it matches. Verified:
`TSoundChannelNode.cpp` is gone with zero remnants; 0x4c6740 is `TLongintList::InsertLast`
and 0x413250 stayed `TDiplomacyMgr::IsNationSlotEligibleForEventProcessing` (the overrides
fix held). `config/symbols.csv`/`symbols.ghidra.txt` were kept at HEAD (authoritative
curation; the export's +2033 uncurated rows dropped). `ghidra-name-drift-gate` baseline
shrank 222 → 56 (166 drifts resolved, TSoundChannelNode among them).

**CORRECTION (same day):** an earlier version of this note claimed the DB was "~1000
names behind" and that `sync_exports`'s curated-merge reverted curated names. Both were
wrong. The DB *is* converged (0x413250 is `IsNationSlotEligibleForEventProcessing` in
the DB), and `merge_curated_symbols_csv` provably preserves curated names. The reversion
had two real, small causes: (1) a `sync_exports` run of mine timed out *after* it
overwrote `symbols.csv` with the raw DB export but *before* the curated merge, and a
second run then read that half-written file as "curated"; and (2) `sync_exports` applies
`config/function_name_overrides.csv` *after* the curated merge, and exactly **3** stale
override rows there still forced pre-rename names (0x413250, 0x60a60a, 0x556410),
reverting them. Fixed by removing those 3 stale rows and adding an
override-vs-symbols.csv consistency check to `ghidra-name-drift-gate` (hard invariant:
an override may never contradict the authoritative symbols.csv).

**Drift-gate false-positive fixed in the same pass.** The re-export surfaced 6 MFC
template-instantiation buckets (`CList_long_long`, `CArray_void_void`,
`CMap_WORD_WORD_CacheRecord_CacheRecord`, …) as "stale". They were not drift: the autogen
bucket *filename* sanitizes template syntax (`<`,`,`→`_`, `*`,`>` dropped) while
`symbols.csv` keeps it (`CList<long,long>::Serialize`), so the gate's string compare never
matched an owned template class. Added `sanitize_stem()` to normalize before the ownership
check (+ regression tests) so owned template buckets are no longer falsely flagged.

## 2026-07-19 (second): `ghidra-apply-source` — the one-way source→DB operation (committed)

The bidirectional sync pipeline is retired. `just ghidra-apply-source`
(`tools/ghidra/apply_source.py`) is now the ONE sanctioned mutation path from the
source model into the DB: qualified names parsed from the C++ declarations under
`// FUNCTION:` markers (SYNTHETIC/TEMPLATE/LIBRARY claims use their convention
comment line; raw-inventory names as fallback), primary-aware function
renames/namespaces, labels, and `Class::'vftable'` labels from `// VTABLE:`
annotations, ending with a datatype-drift audit. First applied run:
primary_exact=6566, set_fn=1642 (source-declaration names replacing stale DB
names, e.g. `ImperialismApp::InitInstance` over
`InitializeImperialismApplicationInstance`), set_label=3, vtable_labels=48,
failed=1 (pre-existing `_fprintf` duplicate). Exported to the vendored .gzf.

Retired: `sync-ghidra`, `db-resync`, `push-names`, `push-source-names` (modules
deleted; the primary-aware push loop lives inside apply_source). The wholesale
raw-inventory refresh is now `just refresh-inventory`; class *datatype* renames
remain the `just ghidra-rename-class` repair tool until PDB-driven type import
lands (the known gap the audit reports).

## 2026-07-19 (third): PDB-driven type/signature import wired into apply-source-full (committed)

`just ghidra-apply-source-full` now includes reccmp's PDB importer
(`just import-ghidra`) as the class-synchronization step the spec called for: it
imports game-owned class datatypes, inheritance, field layouts, full typed
function signatures, and vftables from the recomp PDB into the DB (this run:
9125 successes, 1748 functions changed, vftables imported, zero missing types;
29 benign failures). The retired hand-curated `apply-source-datatypes` (3-class
spec importer) and `push-library-override-names` (absorbed as an apply-source
name source: reviewed identities now beat inventory names) are deleted.

**Ordering matters and is encoded in the recipe:** the PDB import names entities
from the generated data sources (inventory names), so it must run BEFORE the
apply-source name pass — source-declaration names win last. The first run used
the wrong order and the import reverted 1642 source names; re-applying restored
them (primary_exact 6504 -> 8185; 27 residual DuplicateName conflicts from
pre-existing plain-name labels at the same addresses).

## 2026-07-19 (fourth): model-driven apply + consolidation epilogue (committed)

`ghidra-apply-source` now derives everything from the central source model
(tools.source_model): claims-only application (no re-push of DB-derived
inventory names for unclaimed addresses), free-function names first-class
(the old parser required `::`), 1057 `// GLOBAL:` labels, and reviewed library
identities as LIBRARY claims. Applied: set_fn=60 (free-function convergence),
set_label=5, primary_exact=7113, 27 residual duplicate-label conflicts.

The granular source→DB targets (`import-ghidra`, `name-vtable-slots`,
`propagate-virtual-method-names`, `ghidra-rename-class`) are `[private]` —
internals/repair tools, not sanctioned workflows. `refresh-inventory` is
inventory-only (`sync_exports --inventory-only`); the full decompile/type
snapshot is the separate optional `just export-ghidra-evidence`.

## 2026-07-19 (fifth): strict convergence + in_stack migration (in_stack part RETRACTED — see below)

The 27 residual DuplicateName conflicts are eliminated: stale non-primary labels
whose simple name equals the target (often an already-qualified secondary like
`CMcWindow::OnQueryNewPalette` beside a Global primary) are deleted before the
namespace move; 26 stale labels dropped, 26 functions converged, failed=0.
`ghidra-apply-source-full` is now STRICT: it fails on any apply failure and
requires a converged second dry-run (zero pending, zero failures) — verified:
primary_exact=7205, pending=0, failed=0. The apply audit also reports DB class
namespaces owning source-claimed functions under a different class than the
model (6 residual stale namespaces flagged, e.g. TNetMgr x2 — small repair
queue for ghidra-rename-class).

**RETRACTED (2026-07-19, sixth):** the `fix-in-stack-params --apply` work in this
entry was UNSOUND and has been reverted. It appended each `in_stack_*` slot as a
formal parameter via `Function.addParameter(ParameterImpl(None, dtype, offset,
program))`. For a function without custom variable storage Ghidra IGNORES the
supplied stack offset and lets the calling convention place the parameter — so
the flagged slot never bound, and each pass appended another bogus parameter.
That (plus never flushing the decompiler cache between edits) produced the
spurious 261 -> 151 -> 136 -> 127 -> 112 "convergence": an artifact of the tool,
not real parameter recovery. On the clean DB the count is back to the original
**261** — the passes fixed nothing.

**De-pollution:** restored the pre-`in_stack` `.gzf` (commit f4f51048 / PR #88,
LFS oid a973690b…), deleted the polluted live program, re-ran the sound
`ghidra-apply-source --apply --strict` (redoes names + the code-based label
cleanup: 27 stale labels dropped, failed=0), confirmed a converged strict
dry-run (primary_exact=7205, pending=0, failed=0), and re-exported. The strict
label-cleanup + broader-audit code from the fifth entry is retained (it is
sound); only the parameter appends are gone.

**Reframed as a classification problem, not a migration backlog.** The read-only
`just in-stack-audit` (`tools/ghidra/in_stack_audit.py`) classifies the 261:
  - **214 source-owned** — the real prototype already lives in the C++
    declaration (the audit prints it, e.g. `ImperialismCommandLineInfo::ParseParam`
    -> `(LPCSTR, BOOL, BOOL)`); the DB just lags. Fix = PDB import via
    `ghidra-apply-source-full`, never a DB param append (the next import
    overwrites it).
  - **6 library** — prototype from the reviewed identity / PDB.
  - **41 unported**, of which **36 have unknown calling convention** (one carries
    the INT_MAX unknown-purge sentinel) — broken ABI analysis, not missing
    params; repair the convention/boundary. Only **~5** have clean callee-cleaned
    evidence and are genuine complete-signature (`updateFunction(DYNAMIC_STORAGE_
    FORMAL_PARAMS)`) candidates.

The mutating target is retired; `just in-stack-audit` is read-only. Real repairs
happen in source (the 214) or as verified per-function ABI fixes (the ~5), not
as a bulk pass.

## 2026-07-19 (seventh): source-model signature projection (PR #92, committed)

The sound successor to the retracted `fix-in-stack-params`. Diagnosis (PR #91,
`docs/reference/source-signature-import.md`) established that the MSVC500 PDB
carries **no** argument-list type records the modern cvdump can read, so the PDB
import can converge names/returns but never parameter lists — the 214
source-owned `in_stack` functions are a projection gap, not an importer bug.

`tools/ghidra/apply_source_signatures.py` (`just apply-source-signatures
--apply`, wired into `ghidra-apply-source-full`) projects the **source model's**
C++ prototype onto each source-owned (`FUNCTION`) and reviewed-library
(`LIBRARY`) function that still has `in_stack`:

- Complete signature via `replaceParameters(DYNAMIC_STORAGE_FORMAL_PARAMS)` with
  the convention from source (method ⇒ `__thiscall`, free ⇒ `__cdecl`); Ghidra
  auto-generates `this`. A leaked `undefined` return keeps the DB's inferred
  return (source is not authoritative for a placeholder).
- **flushCache + re-decompile + verify**, then classify into one of three
  buckets. It NEVER infers a parameter from an `in_stack` slot and never appends —
  the two bugs that made the old fixer unsound:
  - **converged** — no `in_stack` left; keep.
  - **params_bound_residual** — the flagged offsets are bound (params correct) but
    a residual `in_stack` remains at a *different* offset (a sub-dword read inside
    a bound slot); keep the binding, log the residual (reverting would restore a
    weaker signature).
  - **dynamic_storage_insufficient** — a flagged offset stayed unbound; revert to
    the exact prior signature.

Applied on the clean #91 DB: **152 converged** + **11 params_bound_residual**
(163 signatures kept, verified) + **53 reverted** (`dynamic_storage_insufficient`
— packed sub-dword args, sret hidden pointers, spurious high-offset locals), **0**
unparsable/apply_error (strict passes). The **64** queued
(`build-msvc500/evidence/source_signature_queue.csv`) are the standing evidence —
explained, not a backlog — so every source-owned function that still decompiles
with `in_stack` has an understood reason. `just in-stack-audit` is retained as the
final read-only diagnostic in the full flow; `packed`/`sret` binding via
`CUSTOM_STORAGE` is a deliberate follow-up, not part of this pass.

## 2026-07-19 (eighth): signature projection made transactionally safe (PR #94, NO DB change)

Hardening of the projector; **the committed `.gzf` is unchanged** (the DB
mutations are identical, only the safety/classification of the *apply path* is).

- **Per-function transactions replace the manual restore.** Each projection now
  runs in its own `startTransaction`/`endTransaction`; on reject the transaction is
  ABORTED, and Ghidra's rollback is the exact-restore mechanism. The old
  `_restore()` rebuilt the signature by hand, ignored `hasCustomVariableStorage()`
  and every saved storage object, and swallowed exceptions — so a reverted
  custom-storage function would NOT have been restored, while the outer transaction
  still committed and the queue still reported it "reverted". Verified live: a
  reverted function (`TOcean::EnsurePortZoneForTile`, DB `__stdcall`/2-param vs
  source 1-param method) is byte-for-byte its prior signature after rollback.
- **Audit of the prior committed DB (the concern the restore flaw raised):** on the
  clean #91 base, **0 of 4064** projection candidates (FUNCTION + LIBRARY with a
  prototype) had `hasCustomVariableStorage()`. Since every candidate already used
  dynamic storage, the old `_restore` reproduced the original exactly for all 53
  reverted functions — **the seventh-entry `.gzf` (`d7103d46…`) was NOT corrupted**,
  no restore/replay needed.
- **Distinct outcome states** (previously conflated): `missing_function` (address
  has no DB function), `decompile_failed:before`/`:after` (a `None` decompile ≠ an
  empty `in_stack` set), `apply_error`. The `_HARD_FAIL_REASONS` (unparsable /
  apply_error / decompile_failed) fail `--strict`; the structural buckets do not.
- **Verifier caveat made explicit** (and a known classification gap documented):
  `in_stack` clearing is NECESSARY, not SUFFICIENT — it does not prove the
  convention / member-vs-static kind / param types are correct. The entity-kind →
  convention classification is punctuation-based (a `static` member or a
  namespace-qualified free function whose out-of-class definition head omits
  `static` is read as an instance method → `__thiscall`). A structural,
  compiler-backed convergence check is the follow-up; today `in_stack` is a
  projection trigger + weak verifier. New live-Ghidra smoke test covers the
  rollback primitive; pure-Python tests cover parse / entity-kind / bucket logic.

## 2026-07-19 (ninth): source-DRIVEN signature projection (PR #96, committed DB change)

The PR #95 structural audit showed the source→DB gap was far larger than the 64
in_stack queue: ~1936 claims sat at `cc=unknown`/0 params (Ghidra never resolved
them; they produce no `in_stack`, so the in_stack-triggered projector never saw
them), plus ~294 arity mismatches. This projects that gap.

`just project-divergent-signatures --apply` (a mode of `apply_source_signatures`,
`run_divergent`) applies source signatures to the safe, high-value candidates —
db_signature_incomplete and param_count with source arity > DB arity and matching
convention — regardless of `in_stack`. Acceptance is STRICTER than the in_stack
path (those functions have no in_stack to clear, so clearing proves nothing):
per-function transaction, commit ONLY on FULL convergence — the re-decompile has
no `in_stack` (the source signature didn't introduce a frame the binary
contradicts) AND the resulting DB logical signature structurally matches expected
(convention + arity + this). Everything else rolls back (transaction abort) and is
queued. Convention_mismatch and DB-over-declared (source arity < DB) are excluded
as delicate / handled elsewhere.

Applied on the committed #92 base (`d7103d46…`): **projected=1740** (fully
converged, verified), **queued=277** (unresolved_param=177 — a source type we
cannot size; introduced_in_stack=87 — source/binary disagree, e.g. sret/packed/
under-declaration; sret_by_value_return=3; decompile_failed=9; structural_mismatch=1),
0 apply_error (strict passes). Re-exported → `5ccd1088…`.

Structural convergence over all 4064 claims moved **converged 1813 → 3701**
(db_signature_incomplete 1936 → 255, param_count_mismatch 294 → 87) — 45% → 91%.
No regressions (the projector only touches incomplete/short functions and only
commits full convergence, so a converged function cannot become non-converged).
The 277 queue is the input to the ABI-exception lowering follow-up (sret / packed
CUSTOM_STORAGE / type modeling for the 177 unresolved). Wired into
`ghidra-apply-source-full` after the in_stack projection.

## 2026-07-19 (tenth): constructor-prototype parse fix + missing typedefs (PR #97, committed DB change)

Diagnosing the divergent queue's 177 `unresolved_param` revealed most were not
missing types but a PARSER bug: `parse_prototype` took the LAST balanced paren
group as the arg list, so a constructor with a member-initializer list
(`TFoo::TFoo(args) : TBase(...), field(0)`) parsed its args as the init-list tail
(`) : TBase(`). Fixed to take the FIRST balanced group (nested parens in a
function-pointer parameter handled by a depth counter); added the genuinely-missing
pointer-sized typedefs (`RgnHandle`, `LPCTSTR`/`LPTSTR`, `LPCREATESTRUCT`,
`TSortedListCompareFunc`, window/dialog procs, …) to the pointer-alias set.

Re-running `project-divergent-signatures --apply` on the #96 base (`5ccd1088…`):
`unresolved_param` 177 → 6, **projected=37** more, 0 apply_error. Re-exported →
`6b841b63…`. The structural audit moved **converged 3701 → 3871** (95%),
`db_signature_incomplete` 255 → 87, type-resolution `unresolved` 201 → 15 — a mix
of 37 real new projections and ~133 constructors that were always converged but
mis-measured by the same parse bug (the audit shares `parse_prototype`), so the
true convergence was always higher than #96 reported. The remaining queue (87
`introduced_in_stack`, 3 sret, 6 unresolved, 8 decompile timeouts) is the genuine
ABI-exception set — sret needs correct return-type SIZES first (e.g. `CPoint` is a
1-byte DB placeholder; MSVC returns non-trivial small structs via a hidden pointer
Ghidra won't model until the type is sized), so type modeling precedes the
sret/packed CUSTOM_STORAGE lowering.

## 2026-07-19 (eleventh): verified packed sub-dword CUSTOM_STORAGE (PR #98, committed DB change)

The dominant `introduced_in_stack` residue (50 @0x6, 20 @0xa, …) is the packed
sub-dword case: MSVC500 packs adjacent short/byte args into one dword, which
DYNAMIC_STORAGE dword-aligns, leaving the packed read unbound.
`just project-packed-signatures --apply` (`run_packed`) models the arguments
tight-packed from 0x4 (`this` in ECX for __thiscall) via CUSTOM_STORAGE and commits
ONLY on a fully clean re-decompile — the packing is the hypothesis, the empty
in_stack the proof; a wrong packing rolls back (`packing_mismatch`).

On the #97 base (`6b841b63…`): **projected=11** (verified), queued=45
(packing_mismatch=43 — the tight-packing model doesn't fit the real layout, e.g.
3+ mixed sub-dword args; decompile_failed=2). Re-exported → `6c413c42…`. Also fixed
`_db_logical` to treat a `this`-named param as the receiver whether Ghidra models it
auto (DYNAMIC_STORAGE) or explicit-in-ECX (CUSTOM_STORAGE) — without it the audit
mis-counted the packed functions' explicit `this` as a parameter. Structural audit:
converged 3871 → 3876 (the 11 packed clear their in_stack; the audit measures the
signature match). The 43 packing_mismatch need per-function packing analysis (a
richer packing model than tight-consecutive) — future work.

## 2026-07-19 (twelfth): datatype hygiene — opaque by-value stub correctness (PR #99, committed DB change)

Custom class types are represented in the DB as empty/1-byte stub structures (from
old `apply_mfc_rtti` root-stub creation and Ghidra's own inference). `TypeResolver`
indexed them by simple name and graded any unique match `exact`, so a by-value use
of a stub made the projector believe a real object was 1 byte — a WRONG ABI: a
by-value param allocated 1 byte, or a by-value return bypassing the `size > 4` sret
detection. A DB-based audit found **17 committed signatures using a stub by value**
(e.g. `CMcWindow::OnLButtonDown(uint, CPoint)` with `CPoint` = 1 byte instead of 8).

Fixes:
- `TypeResolver.resolve_quality` never grades an opaque (0-field / <=1-byte) struct
  `exact`; a by-value use returns `(None, opaque_by_value)` so the projector QUEUES
  it (distinct `opaque_by_value_param/return`) rather than committing a placeholder
  size. Behind a `*`/`&` the same stub is fine (`opaque_pointee`, 4 bytes). New
  quality ladder: exact_complete / canonical_alias / opaque_pointee /
  generic_pointer_fallback / ambiguous_simple_name / opaque_by_value / unresolved.
- `apply_mfc_rtti.datatype_for_mac_arg` no longer creates canonical root stubs for
  unknown pointees — uses `void*` (no fake sized type to mistake for a class).
- New `just datatype-hygiene-audit` (`--datatype-audit`): reports committed by-value
  opaque uses (the wrong ABI) and source signatures that would (backlog). `--strict`
  fails on any committed; wired report-only into `ghidra-apply-source-full`.
- `run_divergent` also treats a DB opaque-by-value type as a candidate (arity can
  match yet a scalar arg be typed as a game class by value).

Correction (per the plan): restored the pre-divergent base (`d7103d46…`, the #95
DB) and replayed divergent+packed with the fixed resolver — the 14 divergent-
introduced opaque-by-value params now queue; the extended candidate condition fixed
`TMapOrderChildLinkNode::SetChainActiveFlag`. Committed by-value opaque **17 → 1**
(`TInvadeMission::SetFlag10FromArgSlot94`, a pre-existing Ghidra type error whose
source under-declares, so it can't be auto-projected — a class-model residual).
Re-exported → `ec63a5e3…`. Structural convergence 3871 → 3856: the drop is
CORRECT — 15 signatures that were falsely converged with a 1-byte stub are removed;
they await real class layouts. This is the datatype-hygiene prerequisite to the
compiler-backed class-model work (the durable fix that sizes CPoint/CRect/game
classes and drives committed opaque-by-value to 0).

## 2026-07-19 (thirteenth): class-model projection — real layouts replace the stubs (PR #101, committed DB change)

`just apply-class-model --apply` (`tools/ghidra/apply_class_model.py`) projected
the verified class model (PR #100's three artifacts) into the DB: **438 records
projected (375 existing stub/partial datatypes REPLACED — rewriting every
reference — and 63 created), 0 failures, 96 blocked** per the RTTI audit
(source_incomplete=83 / source_oversized=13 never project — the tool refuses to
choose between disagreeing models). One transaction, verify-then-commit (every
projected structure's final length re-checked against the oracle size).

Per record: game bases flattened recursively at oracle offsets (e.g. `TMission`
= 20 bytes: `base_CObject`@0, `nationId04:short`@4, `pathMarker06:short`@6 …;
`TView` = 96 bytes with the flattened TEventHandler chain); MFC bases placed as
single components of the DB's MFC type when its length matches the oracle
EXTBASE size; fields at exact oracle offsets with the semantic type used ONLY
when it resolves at exactly the oracle size (physical truth wins; otherwise
undefined bytes); vptr at 0 for polymorphic roots.

Downstream effect (the reason class projection precedes signature projection):
datatype-hygiene **committed opaque-by-value 1 → 0** ("signature rows using fake
by-value classes: 0" acceptance met), type resolution `generic_pointer_fallback`
77 → 28 and `exact_complete` 3728 → 3797 — the signature projector now resolves
parameter types against real layouts instead of 1-byte placeholders. Exported →
`75494c6b…`. Wired into `ghidra-apply-source-full` BEFORE the signature
projections; blocked records live in
`build-msvc500/evidence/class_model_queue.csv` until their source declarations
are fixed (exact size deltas in the class-model audit).

## 2026-07-19 (fourteenth): MFC value types + sret attempt-and-verify (PR #102, committed DB change)

The last fake-by-value blockers were the MFC VALUE types (`CPoint`/`CRect`/
`CSize`/`CTime` — 1-byte stubs or missing). The layout oracle now measures them
like everything else (MFCVALUE/MFCFIELD lines: field names are the public MFC API
surface, every offset/size measured by real VC5 — CPoint=8 {x@0,y@4}, CRect=16,
CSize=8), and `apply-class-model` projects them FIRST so game fields typed with
them resolve at the correct size. Applied: 438 game records re-projected
idempotently + the 5 MFC value types (441 replaced, 2 created).

The signature projector's `sret_by_value_return` gate is retired: a >4-byte
by-value return is now ATTEMPTED (Ghidra models the MSVC sret ABI itself once the
return type is really sized) and per-function verification decides. Result:
**14 signatures projected** that were blocked on CPoint — all the
`OnLButtonDown(uint, CPoint)`-family message handlers (game + MFC library rows).
Two honest residuals remain queued: `ReadOrCreateRegistryStringValueWithFallback`
(CString return — a 4-byte non-trivial class MSVC returns via sret but Ghidra's
size-based auto-sret cannot model) and `TView::TransformPointViaSlot138` (the
attempt did not rebind in_stack@0x8 under __thiscall; rolled back, needs explicit
CUSTOM_STORAGE sret lowering).

Datatype hygiene reached the acceptance target: **by-value opaque uses 0
(committed=0, queued=0)** — no signature anywhere uses a fake by-value class and
no backlog remains. Type resolution: opaque_by_value 15 → 0, opaque_pointee
101 → 33, exact_complete 3797 → 3863; structural converged 3854 → 3868.
Exported → `85a1e55b…`.

## 2026-07-19 (fifteenth): source class-size campaign — 72 classes verified (PR #103, committed DB + SOURCE change)

The class-model audit's `source_incomplete` queue is a SOURCE defect list: a class
whose sizeof is short compiles a wrong allocation size into the recomp
(`operator_new(sizeof(T))` immediates), diverging from the original binary. The
mechanical campaign: for each incomplete class with delta ≤ 28, append honest
unknown trailing fields (`int fieldNN;` named by offset + evidence comment citing
`m_nObjectSize`), exactly the codebase's existing pad-field convention.

The oracle re-run is the physical verifier, and it caught two real cascade bugs:
(1) editing a base AND its derived class in one pass double-counts the delta —
detected as new `source_oversized`, trimmed, converged over three iterations;
(2) a genuine mis-attribution: `TDeluxeText.field94/field95/padding96` belong to
the base `TTEView` (RTTI proves sizeof(TTEView)=0x98, and TDeluxeText's remaining
fields then land exactly on their offset-suffixed names — `cursorThemeCode98`@0x98).
Moved to the base; inherited member access keeps all call sites compiling.

Result: **verified 312 → 384** (+72 classes), incomplete 83 → 11 (only >28-byte
deltas needing real recovery), oversized back to the pre-existing 13.
`just build` green over the 64 edited headers; **reccmp stats: 76 functions
improved, 0 regressions, +1 at 100%** — the corrected allocation immediates match
the original binary. class-size-gate passes (0 mismatches). Baseline updated.

`apply-class-model --apply` then projected the newly-verified: **projected
438 → 510** (blocked 96 → 24). Exported → `697ee1cc…`. Remaining queue: 11
incomplete (large deltas: TCityInteriorMinister-family +380, THighScoresPicture
+360, TScenarioChooser +204, …) and 13 oversized (TGreatPower family −0x208,
TMinister −0x38, …) — per-class investigations, each with its exact delta.

## Committed mutations (already in the current .gzf, newest first)

From `git log --follow -- vendor/ghidra/exports/Imperialism.gzf`:

| commit | what it did to the DB |
|---|---|
| (prev change) | `just push-source-names --apply`: mirrored current source function/label names into the DB (set_fn=948, set_label=145, already=7106, 0 failed), then `just export-project`. Fixes accumulated DB↔source name drift — e.g. 0x514dc0 now decompiles as the source name `MapMgrSlot1F` instead of the stale `WrapperFor_IsValidSecondary…_At00514dc0`. Function/label names only; placeholder *class datatypes* (e.g. DB `TSoundChannelNode` = source `TLongintList` @ vtable 0x650a08) are NOT touched by this tool and remain a separate datatype-import follow-up. |
| 3170d5a2 | Propagate Ghidra virtual method names |
| 05dcd197 | Regenerate ghidra_autogen folder (DB names/types refresh) |
| 4a1e94a4 | Regenerate ghidra_autogen folder |
| 0a7ad0c5 | Tier-1 singleton typing, dissolve pseudo-classes, cc overrides |
| 6855af06 | Dissolve placeholder pseudo-class namespaces |
| 1a8390bc | Collapse duplicate Ghidra class datatypes |
| 15750044 | Canonicalize MFC datatypes |
| b41b8790 | Improve MFC class datatypes |
| db7e68fd | Model CString |
| d8cf9200 | Source datatype importer run |
| 97e73bf3 / a9402f72 | Export refreshes |
| 80c2c633 | TCity vtable slot bodies defined (CreateFunctionCmd) |
| 9f94b192 | TAutoGreatPower vtable slot bodies defined |
| 2e01f8ef | TGreatPower vtable slot wiring |
| 68d7c5f9 / 781ca9f3 | Initial vendoring |

Most of these are *derived* mutations (names/types pushed from source or from
imports) and are reproducible on a new DB via the standard pipeline:
`just ghidra-apply-source-full` (build -> PDB import -> source-name apply -> export)
plus the MFC appliers (`apply_mfc_datatypes`, `apply_mfc_rtti`).

## 2026-07-02: gap-repair mutation committed (two bugs found and fixed)

The gap-repair mutation (`tools/ghidra/repair_code_gaps.py --apply` + ILT-range
cleanup + `just sync-ghidra`) was attempted three times against this same live
DB before it stuck. The first two attempts were reverted; the root causes are
recorded here so they aren't rediscovered.

**Attempt 1 (first session).** `repair-code-gaps --apply` created 2167 missing
functions. Reverted because the subsequent `sync-ghidra` export re-introduced
ILT-range (0x401000–0x409ab5) function entities into `config/symbols.csv`,
collapsing `just vtable` (~400 functions lost 100%, hundreds of vtable slots
stopped auto-resolving through jmp thunks).

**Attempt 2.** Fixed the ILT problem by directly deleting the stray Function
entities in the live DB (`FunctionManager.removeFunction`) *before*
`sync-ghidra`, rather than relying on `just prune-ilt-thunks` alone — that tool
turned out to have its own bug (below). `just vtable` held 393/393 through the
full resync this time, but `just stats` regressed hard (-34 aligned functions,
305 lower-similarity, several functions dropping 100% → 0%, e.g.
`CMcWindow::OnKeyDown` at 0x493b30). Reverted again (repo tree + the **live**
Ghidra project both restored from the pre-mutation `.gzf` checkpoint).

**Root causes found and fixed:**

1. **`tools/workflow/prune_ilt_thunks.py`** read `parts[3]` as the CSV `type`
   column, but the schema is `address|name|symbol|size|type|prototype[|provenance]`
   — a `symbol` column was inserted at index 2 at some point without updating
   this tool, so it was actually comparing the `size` field against
   `"function"` and silently pruning **zero rows on every run**, forever.
   Fixed to read `parts[4]`.
2. **`tools/ghidra/repair_code_gaps.py`**'s `CreateFunctionCmd(address)` call
   bounds the new function's body from *already-disassembled* code units. On a
   raw undisassembled gap (the normal case here — that's *why* it's a gap),
   there are no code units yet, so Ghidra silently created a degenerate 1-byte
   function instead of following the real instruction flow — e.g.
   `CMcWindow::OnKeyDown` (0x493b30, real body `ret 0xc`, 3 bytes) became a
   1-byte stub, clamping reccmp's compare window to nothing. Fixed to
   `DisassembleCommand` the target first when no instruction exists there yet,
   and to detect+undo (rather than silently leave behind) any function that is
   still 1-byte after disassembling, reporting it as `DEGENERATE` instead.

**Attempt 3 (this fix): committed.** Re-ran the full procedure with both fixes:
`repair-code-gaps --apply` (493 created, 0 failed, 23 genuinely degenerate —
removed and reported, not left corrupting anything), direct ILT-range
Function-entity deletion (2479 removed), `push-names --apply`, `import-ghidra`,
`just sync-ghidra` (full resync — also re-introduced 393 stale
`'vftable'`-typed symbols.csv rows colliding with real header `// VTABLE:`
annotations, same pattern as the merge step; deleted by address), then
`just export-project` last. Verified: `just gates` clean, `just vtable` 393/393
100%, `just stats` **zero regressions** vs the pre-mutation baseline (confirmed
both mechanically and by hand: `CMcWindow::OnKeyDown` and
`TFileBasedDocument::CreateObject` back to their correct pre-mutation scores).

## 2026-07-02 (second): pipeline-automation resync

Validation run of the automated pipeline (`just db-resync`). DB deltas: 29
`push-names` renames; 9 stray ILT-range Function entities removed by the new
`prune-ilt-db-functions` step (34 claimed/referenced ones kept).

Finding from this run: the previously committed `symbols.ghidra.txt` showed 627
ILT-range `f` symbols while the committed `.gzf` actually contained only 43 ILT
Function entities — the gap-repair session exported symbols *before* its manual
ILT surgery, so the txt (and ~20 `symbols.csv` `function` rows over label-only
addresses) were stale against the DB. The honest re-export therefore demoted
those rows to `global`, which silently dropped the autogen stubs manual
extern-thunk callsites link against (7 unresolved externals). Two fixes landed:
the curated merge now preserves a curated `function` row over a bare-label
export row, and `ilt_keep_reason` also matches Ghidra's `_00ADDR`-suffixed
names. The raw-vtable gate no longer scans regenerated `src/ghidra_autogen/`
reference files (their pattern counts change with every resync and are not a
source-policy signal).

## Procedure for a future re-run (this DB or a newer one)

The manual repair steps from the attempts above are now **automated inside the
pipeline** (2026-07-02 tooling overhaul):

- `just sync-ghidra` runs `prune-ilt-db-functions --apply` before the export, so
  stray ILT-range Function entities can no longer survive a resync (old step 3).
- The curated-symbols merge (`merge_curated_symbols.py`) **drops** any
  symbols.csv row at a source `// VTABLE:` address instead of re-introducing it
  for manual deletion (old step 5), and `sync-ghidra` ends with
  `symbols-integrity-gate` + `vtable-collision-gate` to prove it.
- `just db-resync` chains the whole thing: `tooling-check` → `sync-ghidra` →
  `regen-stubs` → `build` → `detect` → `gates` → `stats` → `export-project`.

So the procedure is:

1. Restore/open the DB; run the standard reproduction pipeline first
   (`push-names --apply`, datatype appliers, `import-ghidra`).
2. For gap repair: `just repair-code-gaps` (dry-run), review, then `--apply`.
   The tool disassembles gaps before creating functions and self-reports any
   residual degenerate (1-byte) result — treat a nonzero `degenerate` count as
   worth a look, not silently ignorable.
3. `just db-resync`. If `just vtable` (393/393 must stay 100%) or `just stats`
   (no mass regressions) fails partway, fix forward and re-run; the pipeline
   ends with `export-project`, so a completed run leaves the committed `.gzf`
   carrying everything.
