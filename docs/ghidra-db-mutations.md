# Ghidra DB mutation ledger

The vendored Ghidra database (`vendor/ghidra/exports/Imperialism.gzf`, LFS) is
planned to be replaced with a newer DB in a separate folder. Everything below is
the record of what has mutated the DB, so the still-wanted mutations can be
re-run against the new database.

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
