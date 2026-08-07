# `apply_mfc_rtti.py` mutation-ownership audit

`tools/ghidra/apply_mfc_rtti.py` mines MFC `CRuntimeClass` (DECLARE_DYNAMIC)
descriptors and mutates the Ghidra DB from that evidence. Per the 2026-07-19
change recorded in `docs/ghidra-db-mutations.md`, it no longer creates game
class *layout* datatypes — `apply_class_model.py` is the sole layout authority.
This table inventories every mutation responsibility STILL in the tool, so the
remaining scope is legible and any future consolidation has a clear map to
follow, per the standing goal: *eliminate competing authorities, not
automatically delete the tool*.

## Classification key

- **unique_binary_evidence** — this pass is the only place that derives this
  fact from the binary (RTTI descriptor structure, vtable-slot scan, ECX-this
  heuristics) and applies it; no other tool owns the underlying evidence or the
  write.
- **already_owned_by_source_model** — the DATA this pass applies is curated by
  hand in a `config/*.csv` (a source-adjacent, human-reviewed input); the pass
  is just the applier, not a competing authority over the data itself.
- **already_owned_by_class_model** — `apply_class_model.py` (Clang AST + MSVC500
  layout oracle + RTTI cross-check) owns this; `apply_mfc_rtti.py` must only
  defer or refresh a pre-existing field, never create/size independently.
- **already_owned_by_vtable_tooling** — a dedicated vtable-focused tool
  (`propagate_virtual_method_names.py`, `name_vtable_slots.py`,
  `vtable_extent.py`, `vtable_matrix.py`, `vtable_struct_check.py`) is the
  canonical owner; `apply_mfc_rtti.py` must not independently re-derive the
  same result.
- **historical_migration_only** — retired from this pass; kept here as a record
  of what used to happen and where it moved to, so a future DB re-apply against
  a fresh database knows not to reintroduce it here.

## The mutation inventory

| # | Mutation | File:line (as of this audit) | Classification | Notes |
|---|----------|-------------------------------|-----------------|-------|
| 1 | CRuntimeClass descriptor typing + Ghidra label | `find_descriptors`/`looks_like_descriptor` (~200-238), applied ~451-474 | unique_binary_evidence | **Watch item**: `tools/ghidra/rtti_class_oracle.py` is a dedicated, READ-ONLY, more careful two-pass RTTI scanner (candidate filtering + base-chain membership) that the project's own ledger calls "the actual read-only RTTI evidence extractor." `apply_mfc_rtti.py`'s own single-pass `looks_like_descriptor` re-derives the same evidence independently. Not consolidated this pass (would require re-plumbing the oracle's output into a mutation-only tool) — flagged as a genuine future duplication to resolve, not claimed fixed. |
| 2 | Ghidra namespace + DECLARE_DYNAMIC inheritance edge | `get_or_make_class` (~340s), `class_info` population (~470-480) | unique_binary_evidence | Ghidra-namespace bookkeeping derived directly from the RTTI base-chain walk; no other tool owns this. |
| 3 | Vtable identification + `<Class>::'vftable'` label | `descriptor_to_vtable` (~285-305), label creation (~487-494) | unique_binary_evidence | Same RTTI-derived provenance as #1/#2. |
| 4 | Virtual-method-name propagation (base → derived override) | *(removed this audit)* | **historical_migration_only** | **Consolidated this session.** This pass carried its own inline slot-walk-and-rename (~30 lines: `is_propagatable`, the shared-slot loop, `der_fn.setName(...)`) that independently re-derived and wrote the exact same result `propagate_virtual_method_names.py` (`just propagate-virtual-method-names`) already owns as its sole stated purpose — two tools authoring the same function names with zero conflict detection between them. Verified the inline copy's `der_fn`/`new_name`/`stats["slots_renamed"]` had no downstream reader elsewhere in the file (safe to remove with no coupling break), removed it, and replaced the removed stats line with a pointer to the dedicated tool. Both tools re-verified via live dry-run afterward (`descriptors=458 vtables=407`; `propagate-virtual-method-names` unaffected, still correctly reports `<unnamed> -> CObject::GetRuntimeClass`-style pending renames). |
| 5 | `/MFC/vtables/<Class>Vtbl` struct build/replace | `ensure_vtbl_struct` (~756-780), `apply_vtable_data` (~781-790) | unique_binary_evidence | **Watch item**: uses its own private `vtable_extent()` closure (~351-370) rather than the standalone `tools/ghidra/vtable_extent.py` module of the same name/purpose — a naming collision worth resolving (consume the shared module) but not addressed this pass. |
| 6 | Class-own root struct creation/sizing | `ensure_class_struct` (~700s), `ensure_root_class_dt_for_curated` (~1150s) | **already_owned_by_class_model** | Already retired (2026-07-19 PR #108 change, recorded above in the ledger): both call sites only REUSE an existing canonical root struct (refreshing its vftable-pointer field), never create/size one. A class `apply_class_model.py` hasn't reached yet is left alone (`class_struct_deferred` stat). |
| 7 | Per-slot function-pointer signatures (vtable struct member types) | `make_function_definition`, `mac_signature_for` (~640-660) | unique_binary_evidence | Uses the live target function's own signature, or Mac CodeWarrior evidence as a NAME/SIGNATURE ORACLE ONLY (never assigns Windows addresses/vtables — Hard Rule 12 respected). No other tool types vtable-struct member slots. |
| 8 | `CreateObject` factory return-type typing | ~890-900 | unique_binary_evidence | RTTI-specific: `CreateObject`'s return type is the class the descriptor belongs to. |
| 9 | Direct vtable-store method `this`-typing | `ecx_this_like` heuristic (~830-840), applied ~920-945 | unique_binary_evidence | ECX-load-before-vptr-store heuristic; no other tool infers `this` from this specific pattern. |
| 10 | Class-namespace ECX-this function typing | ~945-965 | unique_binary_evidence | Same heuristic family as #9, applied to namespace-scoped functions. |
| 11 | Caller-based class assignment (all-callers-agree heuristic) | ~965-1015 | unique_binary_evidence | **Watch item**: conceptually the same evidence class as `tools/ghidra/class_owner_probe.py`'s interactive, human-in-the-loop investigation — but `class_owner_probe.py` is read-only/diagnostic (a decision-support tool for a human), while this is an automated mutation. Not a genuine "two tools writing the same fact" conflict today; a plausible future direction is having this heuristic consume the probe's evidence-gathering rather than reimplementing it, not evaluated this pass. |
| 12 | Locality-based class attribution (bracketed-by-neighbors + RTTI size tie-break) | ~1015-1135 | unique_binary_evidence | Same watch-item relationship to `class_owner_probe.py` as #11. |
| 13 | Curated globals typing | `config/recovered_globals.csv`, ~1135-1200 | already_owned_by_source_model | The DATA (which global is which type) is hand-curated and reviewed in the CSV; this pass is only the applier. `ensure_root_class_dt_for_curated` is non-creating (same PR #108 pattern as #6). |
| 14 | Pseudo-class namespace dissolution | `config/dissolve_namespaces.csv`, ~1200-1235 | already_owned_by_source_model | Curated list of namespaces to fold back into their real owner; applier only. |
| 15 | Curated data reclassification | `config/recovered_data.csv`, ~1235-1315 | already_owned_by_source_model | **Distinct from #6**: this path DOES still create a root struct (`_DataStructDT`), but for arbitrary flat DATA blobs (not RTTI game classes) named in a hand-curated config — a different category from the game-class-layout authority `apply_class_model.py` owns, so this is not a regression of the PR #108 boundary. |
| 16 | Calling-convention overrides | `config/calling_convention_overrides.csv`, ~1315-1355 | already_owned_by_source_model | **Watch item**: `tools/ghidra/apply_source_signatures.py`'s projector ALSO sets calling convention (from the source-model prototype) during signature projection. Both are curated/source-driven rather than guessed, so this is lower-risk than the virtual-name-propagation case (#4) — but a function present in BOTH `config/calling_convention_overrides.csv` and a `// FUNCTION:`-claimed prototype could in principle have its CC set by either tool depending on run order. Not evaluated for an actual live conflict this pass; flagged for a future audit rather than claimed resolved. |
| 17 | Function → class overrides | `config/function_class_overrides.csv`, ~1355-1410 | already_owned_by_source_model | Curated override list; applier only. |

## Summary against the Task-5 acceptance criteria

- **Ownership table covers every mutation category**: yes — all 17 responsibilities
  above (the full inventory from a dedicated research pass over the file).
- **No game class datatype creation returns**: confirmed still true (#6, #13
  remain non-creating per the PR #108 boundary; #15's data-struct creation is a
  distinct, non-game-class category).
- **No function signature is independently authored by two tools**: the one
  CONFIRMED, VERIFIED instance (#4, virtual-method-name propagation) is fixed
  this session — inline duplicate removed, `propagate_virtual_method_names.py`
  established as sole owner, both tools re-verified live. Three additional
  PLAUSIBLE-but-unconfirmed duplication risks are flagged as watch items (#1
  RTTI descriptor mining vs. `rtti_class_oracle.py`, #5 `vtable_extent()` vs.
  the standalone module, #16 calling-convention overrides vs.
  `apply_source_signatures.py`) rather than claimed fixed — each would need its
  own live-DB before/after comparison to confirm an actual conflict exists
  before touching working code, which this pass did not have budget for.
- **Dry-run output distinguishes evidence discovery from planned mutation**:
  the tool's existing `[DRY RUN]` / `[APPLIED]` mode banner plus per-category
  stat counters already do this; the removed virtual-name-propagation stats
  (`overrides_renamed`, `skipped_already_named`, the latter a pre-existing dead
  counter never incremented) were replaced with an explicit pointer to the
  dedicated tool rather than silently dropped, so a reader of the dry-run
  output is told where that evidence/mutation now lives instead of just seeing
  it vanish.
- **Removal accompanied by a reproducible replacement workflow**: yes — `just
  propagate-virtual-method-names` (dry-run by default, `--apply` to write) is
  the existing, already-tested replacement; no new tool had to be built.
