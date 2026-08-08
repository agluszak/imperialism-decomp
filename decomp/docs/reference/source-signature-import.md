# Source → Ghidra signature projection: coverage diagnosis (PR #91)

## Question

`ghidra-apply-source-full` runs `build → import-ghidra → ghidra-apply-source
--apply --strict → export`. Strict convergence checks that **names** converge.
Yet `just in-stack-audit` finds **214 source-owned** functions whose Ghidra
signature is weaker than the C++ declaration already present in source (the
missing parameters surface as `in_stack_*` reads). Why does the PDB import miss
them?

## Experiment (read-only)

`tools/ghidra/signature_probe.py` (since removed; see git history) captured the DB signature + `in_stack` for 16
representative source-owned functions (free / `__thiscall` / `__stdcall` /
vtable override / MFC override / ctor / struct-return / packed-args / unknown-cc),
**before and after a fresh `just import-ghidra`** against a matching build.

Result: **0 of 16 changed.** `before == after`, byte for byte. The import run
itself reported `Successes: 9149, Functions changed: 148, Missing types: <none>` —
i.e. it "succeeded" on ~everything while changing almost nothing, and touched
none of the affected functions.

## Root cause (toolchain, systemic)

`reccmp-ghidra-import` builds each function's parameter list from the PDB's
argument-list type records (`cvdump -t`; the importer skips any function whose
current Ghidra signature already matches the type it derived — see
`function_importer.matches_ghidra_function`).

On this **MSVC500 (1997)** recomp PDB, the modern cvdump (14.00.23611, the one
reccmp ships and uses) extracts:

| `cvdump` section | records |
|---|---|
| `-s` symbols (`S_GPROC32`) | **8549** (names/addresses/return-type index resolve fine) |
| `-t` types (`LF_MFUNCTION` / `LF_ARGLIST`) | **0** — the `*** TYPES` section is empty |

The CodeView **type** stream MSVC 5.0 emitted is in a format/location the modern
cvdump does not parse, so reccmp gets **no argument lists for any function**. The
importer therefore constructs a parameter-less signature, which matches the
parameter-less signature Ghidra already inferred for these functions → it skips
them. Names converge (from symbols); **parameter lists cannot converge from the
PDB on this toolchain.**

This is why the "214" never move: it is not an importer bug to patch, it is a
data source that does not carry the needed information.

## Implication for the fix (PR #92)

The PDB is a dead end for parameters here. The authoritative signature source
must be the **source model** (`tools/source_model.py` already parses the C++
declaration head into a prototype). The supplemental projection the plan
mentioned as a fallback is actually the *primary* mechanism: read the source
prototype and apply a complete signature via
`updateFunction(DYNAMIC_STORAGE_FORMAL_PARAMS)`, verify by re-decompile, and
check signature convergence **against the source model**, not the PDB.

## Failure taxonomy (the 16, generalising to the 214)

Ownership is already known (audit); these sub-categories drive *how* the source
signature must be projected:

1. **Plain missing trailing params** — the common case. DB has 0–2 params, source
   declares more; each `in_stack` offset is exactly a declared parameter.
   `ImperialismCommandLineInfo::ParseParam` (DB 2, src 3 — missing `BOOL bLast`
   @0xc), `TFATemplateDialog::TFATemplateDialog` (DB 0, src 1 @0x4),
   `TSortedList::AddHead` (0→1), `TFileStream::ReadBytes` (0→2),
   `TWindow`/`TControl::HandleEvent` (1→3). *Fix:* project the source prototype
   with dynamic-storage formal params.

2. **Struct return (sret hidden pointer)** — source returns a struct by value, so
   the ABI inserts a hidden return-pointer parameter at the first stack slot and
   the real args shift up. `TView::TransformPointViaSlot138` returns `CPoint`;
   DB `param_1@0x4` is the sret pointer, `in_stack@0x8` is the real `CPoint*`.
   *Fix:* the projection must model return-by-value → hidden pointer (reccmp's
   importer already has this `X* __return_storage_ptr` handling; the source
   projector needs the same rule).

3. **Short/bool packing & sub-dword alignment** — the compiler packs two `short`s
   into one dword (`short@0x4` + `short@0x6`), or a `bool` byte; Ghidra models the
   second arg dword-aligned at `0x8`, so the real read at `0x6` is unbound.
   `TPicture::SetPictureResourceIdAndRefresh`, `ResolveCivilianTileSelection…`,
   `TOcean::EnsurePortZoneForTile`. *Fix:* needs `CUSTOM_STORAGE` with the packed
   stack offsets, or acceptance that dword-aligned vs packed is a structural
   difference (the convergence audit must treat these carefully, not by textual
   offset).

4. **Calling-convention mismatch** — DB convention disagrees with source.
   `GetMapContextActionLabelTokenByActionCode`: DB `__cdecl`, source `__stdcall`.
   *Fix:* project the convention from source (this alone re-lays the frame).

5. **`cc = unknown` / spurious `in_stack`** — when Ghidra can't determine the
   convention, params are unplaced and *locals* can masquerade as `in_stack`.
   `TMapMaker::ReindexContiguousCityRegionIds` declares **zero** params in source
   yet shows `in_stack@0x14` — a high offset that is a local, not a parameter.
   `TRadioTextCluster::AddItem`, `TViewMgr::DispatchLocalizedUiMessageWithTemplate`
   (unknown cc; the latter also has `CString`-by-value params spanning slots).
   *Fix:* set the convention from source first; some residual `in_stack` here are
   genuinely not parameters and must be recognised as such (not "fixed").

## Deliverable status

PR #91 is diagnosis only — no committed DB change (the fresh import ran in the
live project for observation; the vendored `.gzf` stays at the clean #90 state).
`signature_probe.py` served as the basis of the `source-signature-audit` /
convergence check in PR #92 (now `tools/ghidra/apply_source_signatures.py`) and
has since been removed; see git history for the probe implementation.

## PR #92: the source-model signature projector (enforcement)

`tools/ghidra/apply_source_signatures.py` (`just apply-source-signatures
--apply`) implements the projection the diagnosis called for, and is wired into
`ghidra-apply-source-full` (after `ghidra-apply-source`, before the audit +
export). It is **source-authoritative** and **verify-and-revert**:

1. Candidates = every source marker (`FUNCTION`) and reviewed library identity
   (`LIBRARY`) that carries a prototype and still decompiles with `in_stack_*`.
2. Parse the C++ declaration head → `(cc, return, [param types])`. The
   convention comes from source; when the declaration omits it the C++ ABI fixes
   it (method ⇒ `__thiscall`, free function ⇒ `__cdecl`). A leaked `undefined`
   return is treated as "keep the DB's inferred return" — source is not
   authoritative for a Ghidra placeholder, and the params (not the return) clear
   the `in_stack`.
3. Apply a COMPLETE signature via
   `replaceParameters(DYNAMIC_STORAGE_FORMAL_PARAMS)` (Ghidra auto-generates
   `this`), **flush the decompiler cache**, and re-decompile.
4. **Keep only if the `in_stack` set actually clears.** Anything that does not
   converge is reverted to its exact pre-projection signature and queued with the
   residual offsets, never left with a guessed signature. `--strict` fails only
   on `unparsable_prototype` / `apply_error`; the classified structural queue is
   the honest evidence, not a failure.

This is the sound successor to the retired `fix-in-stack-params --apply`
(see `ghidra-db-mutations.md`): it never infers a parameter from an `in_stack`
slot, it replaces the *complete* signature instead of appending, it flushes the
cache, and it verifies every edit by fresh decompilation.

### Result (clean #91 DB → projected)

Every processed function lands in exactly one bucket; the projection is applied
(kept in the DB) for the first two and reverted for the third:

| bucket | count | kept? | meaning |
|---|---|---|---|
| **converged** | **152** | yes | projected; the re-decompile has NO `in_stack` left |
| **params_bound_residual** | **11** | yes | every originally-flagged offset now bound (params correct), but a residual `in_stack` remains at a *different* offset — logged, not silently "converged" |
| **dynamic_storage_insufficient** | **53** | no (reverted) | an originally-flagged offset stayed unbound; reverted to the exact prior signature |
| unparsable / apply_error | **0** | — | strict passes |

163 signatures are kept in the DB (152 + 11); 53 are reverted. The **64** queued
(`build-msvc500/evidence/source_signature_queue.csv`) are the standing evidence —
*explained*, not *unexplained*:

- **`dynamic_storage_insufficient` (53)** — `DYNAMIC_STORAGE`-insoluble frames a
  formal-param projection cannot bind: **packed sub-dword args** (two `short`s in
  one dword, second read at `@0x6` — the dominant case; needs `CUSTOM_STORAGE`,
  deliberately out of scope: "bulk-fix the plain params, queue the rest"),
  **sret hidden pointers** (by-value struct return shifts the real args up a slot,
  e.g. `TView::TransformPointViaSlot138` → `CPoint`, residual `@0x8`), and
  **spurious high-offset locals** (`TMapMaker::ReindexContiguousCityRegionIds`
  `@0x14`, `__chsize_lk` `@0x1008` — a 4 KB local buffer, not a parameter).
- **`params_bound_residual` (11)** — the parameters ARE bound correctly (e.g.
  `ImperialismCommandLineInfo::ParseParam` gets all three source params), but the
  decompiler still shows a sub-dword read *inside* an already-bound slot (`@0x9`,
  `@0xd`). Reverting would restore a weaker signature, so the binding is kept and
  the residual is logged instead — the honest classification that keeps the queue
  accounting for every function that still decompiles with `in_stack`.

The remaining source-owned `in_stack` therefore carries an understood reason
apiece — the diagnosis goal ("not zero, but every one explained") is met, and the
count is no longer a manual backlog. (A tiny number of functions flip `in_stack`
on/off with surrounding DB state — decompiler context-sensitivity, not a missing
param; those are caught by `in-stack-audit`, not projected.)

## PR #95: authoritative entity kinds + structural convergence audit (read-only)

Two follow-on gaps from the projector's verifier: (a) the entity-kind → convention
classification was punctuation-based, so a `static` member or a namespace-scoped
free function was read as an instance method (`__thiscall`) when it is really
`__cdecl`; (b) projection is *symptom-driven* — it only visits functions that
decompile with `in_stack`, so a function the DB never resolved (`cc=unknown`,
0 params) that produces no `in_stack` is invisible to it.

**Clang-AST declaration index** (`tools/clang_ast_index.py`, `just clang-decl-index`).
A real clang parse of the game headers (umbrella TU, vendored MSVC500/MFC includes,
clang-cl `/TP` mode) yields `qualified_name -> [DeclInfo(kind, is_static, ret,
params, has_this)]` for ~14.6k names (9213 instance methods, 1396 ctors, 700 dtors,
**534 static methods**, **41 namespace functions**, 4646 free functions). The
projector consults it (`resolve_entity_kind`, matched on qualified name + arity for
overloads) and falls back to the punctuation guess only when a name is absent —
true of free functions defined only in a `.cpp`, where punctuation is already right.
It corrects the convention for **12** source-owned functions that are `static`
methods (e.g. `TMapMgr::GetNeighborTileIDArray`); none currently have
`in_stack`, so this changes no projection today — it is defensive correctness and
the input to the audit below.

**Structural convergence audit** (`just structural-signature-audit`, READ-ONLY). For
EVERY FUNCTION/LIBRARY claim — not just those showing `in_stack` — it compares the
expected logical signature (source model + decl index) against the DB signature and
classifies the gap. On the clean #91 DB, over **4064** claims:

| category | count | meaning |
|---|---|---|
| converged | 1813 | DB convention + this-presence + arity match source |
| **db_signature_incomplete** | **1936** | DB `cc=unknown` / 0 params — Ghidra never resolved it (invisible to the in_stack projector) |
| param_count_mismatch | 294 | arity differs (either direction) |
| convention_mismatch | 21 | DB convention disagrees with source |

Type resolution quality is recorded per row (logical vs ABI-storage convergence are
separate concerns): exact=3674, unresolved=204 (a non-pointer type we cannot size),
generic_pointer_fallback=110 (pointee unknown — ABI-size only), ambiguous_simple_name=67
(same simple name shared by several datatypes), canonical_alias=9. Only `exact` /
`canonical_alias` count as *semantic* convergence; the pointer fallback counts only as
*ABI-storage* convergence.

Update: `ambiguous_simple_name` is now **0** (`just dedupe-ambiguous-datatypes --apply`
removed the `/Demangler/{CCmdTarget,CDC,CFrameWnd,CWnd,"CWnd *"}` placeholder structs
Ghidra's demangler analyzer had left duplicating the canonical root MFC classes, and
`TypeResolver.__init__` now excludes bare `FunctionDefinition` datatypes from the
by-simple-name ambiguity count — a Win32 callback typedef like `WNDPROC` and Ghidra's
auto-generated `.../functions/WNDPROC` pointee-signature companion are not a real
collision, since the latter is never itself a usable parameter type).

This audit is the measurement, not the repair — it is wired as a read-only final stage
of `ghidra-apply-source-full` and changes no DB. Projecting the ~2000 divergent
signatures (the `db_signature_incomplete` majority plus the arity/convention cases),
with per-function verify-and-commit as in PR #94, is the DB-changing follow-up.
