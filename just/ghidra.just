# ---------------------------------------------------------------------------
# ghidra-inspect — read-only evidence from the vendored Ghidra project.
# ghidra-db — targets that WRITE the vendored Ghidra database (see the section
# banner inside for the export-project rule).
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

# Optional full Ghidra evidence snapshot (decompiled bodies + type headers) into
# {{build_dir}}/evidence/ghidra-export/. Read-only over committed state.
[doc('Full decompile/type evidence snapshot into build evidence (read-only, slow)')]
[group('ghidra-inspect')]
export-ghidra-evidence: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  uv run python -m tools.ghidra.sync_exports \
    --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
    --ghidra-project-dir "{{GHIDRA_PROJECT_DIR}}" \
    --ghidra-project-name "{{GHIDRA_PROJECT_NAME}}" \
    --ghidra-program-name "{{GHIDRA_PROGRAM_NAME}}"

# ---------------------------------------------------------------------------
# ghidra-inspect — read-only evidence from the vendored Ghidra project.
# ---------------------------------------------------------------------------

# Read-only inspect targets route through tools.ghidra.query: when the persistent
# daemon (`just ghidra-daemon`) is running they answer in milliseconds over its
# socket; otherwise they fall back to the classic one-shot pyghidra path with
# identical output. The daemon holds the exclusive project lock, so every other
# project open — the remaining one-shot read tools below and all MUTATES-Ghidra-DB
# targets — evicts it automatically (via ghidra_env.open_project); re-warm with
# `just ghidra-daemon` afterwards.
[doc('Start the persistent read-only Ghidra query daemon (one JVM, instant queries)')]
[group('ghidra-inspect')]
ghidra-daemon: _require-ghidra-install
  uv run python -m tools.ghidra.daemon start

[group('ghidra-inspect')]
ghidra-daemon-stop:
  uv run python -m tools.ghidra.daemon stop

[group('ghidra-inspect')]
ghidra-daemon-status:
  uv run python -m tools.ghidra.daemon status

# Unified read-only Ghidra query dispatcher (tools.ghidra.query). Replaces the old
# per-command ghidra-listing / ghidra-decompile / xrefs / string-oracle / ... wrappers:
#   just ghidra listing 0xADDR          just ghidra decompile 0xADDR
#   just ghidra xrefs 0xADDR            just ghidra vtable-dump Class=0xVT
#   just ghidra                          (lists all sub-commands)
# Sub-commands: listing, decompile, xrefs, func-sig, field-xrefs, string-oracle,
# read-data, jumptable, function-slice, linear-disasm, raw-disasm, search,
# original-modules, portprep, vtable-dump, vtable-abi-evidence.
[doc('Read-only Ghidra query dispatcher: just ghidra <cmd> <args> (no cmd lists them)')]
[group('ghidra-inspect')]
ghidra *args: _require-ghidra-install
  uv run python -m tools.ghidra.query {{args}}

[doc('Audit data/code function pointers and hidden callback registrations')]
[group('ghidra-inspect')]
data-function-pointers *args: _require-ghidra-install
  uv run python -m tools.ghidra.query data-function-pointers {{args}}

# Read-only vtable evidence dump: resolve each slot of one or more vtables to its real
# body (ILT thunks chased) as JSON on stdout — target address, Ghidra name, size,
# listing signature, optional decompile. Inspection only; never writes source/symbols.
# Manual class recovery is source-first; use this as evidence, not a generator.
#   just class-vtable-dump TMapUberPicture=0x00668f08[:COUNT] [Base=0x... ...] [--decompile]
[doc('Read-only: dump a vtable class resolved slot targets as JSON (evidence only)')]
[group('ghidra-inspect')]
class-vtable-dump *args: _require-ghidra-install
  uv run python -m tools.ghidra.vtable_slots {{args}}
# Ordered (address -> constant) store map of an unrolled table-initializer function,
# read straight from the original binary via capstone (no Ghidra round-trip).
# `just const-stores 0xADDR [--len N] [--cpp NAME:BASE:STRIDE:f0,f1]`.
[group('ghidra-inspect')]
const-stores *args:
  uv run python -m tools.binary.const_stores {{args}}

# Decode a turn-event screen-builder into widget-block pseudo-source (bd 1uj.51):
# per-eventCode case map + helper-call sequences with FourCC tags decoded. Reads the
# ORIGINAL binary directly (no Ghidra round-trip; works where the decompiler
# degenerates). `just decode-builder 0xADDR [--len N]`.
[group('ghidra-inspect')]
decode-builder *args:
  uv run python -m tools.binary.decode_builder {{args}}

[doc('Check all original UI builder dispatches against the semantic manifest')]
[group('ghidra-inspect')]
ui-builder-dispatch-check:
  uv run python -m tools.binary.decode_builder --check-manifest

[doc('Query the committed Mac control class/tag/screen semantic index')]
[group('ghidra-inspect')]
mac-control-usage *args:
  uv run python -m tools.workflow.mac_control_usage {{args}}

[doc('Query the committed file-scoped Mac resource reference graph')]
[group('ghidra-inspect')]
mac-resource-xrefs *args:
  uv run python -m tools.workflow.mac_resource_xrefs {{args}}

[doc('Inspect differential Mac widget payload evidence for one effective class')]
[group('ghidra-inspect')]
mac-payload-diff class_name *args:
  uv run python -m tools.workflow.mac_payload_diff "{{class_name}}" {{args}}

[doc('Search file-scoped Mac STR# text and show ranked Windows candidates')]
[group('ghidra-inspect')]
mac-string-search query:
  uv run python -m tools.workflow.mac_string_crosswalk search "{{query}}"

[doc('Crosswalk one Mac STR# group/index; add --resource-file through direct tool query when ambiguous')]
[group('ghidra-inspect')]
string-crosswalk group index:
  uv run python -m tools.workflow.mac_string_crosswalk crosswalk "{{group}}" "{{index}}"

[doc('Show statically resolved string references for a Windows function address')]
[group('ghidra-inspect')]
strings-for-function address:
  uv run python -m tools.workflow.mac_string_crosswalk function "{{address}}"

[doc('Report Mac-resource versus generated Windows UI semantic deltas')]
[group('ghidra-inspect')]
ui-platform-diff *args:
  uv run python -m tools.workflow.ui_platform_diff {{args}}

[doc('Print one scoped Mac View resource from committed UI IR (FILE:ID)')]
[group('ghidra-inspect')]
ui-resource-show resource:
  uv run python -m tools.ui_codegen --view "{{resource}}"

[doc('Explain generated lines and evidence for FUNCTION EVENT [NODE-OFFSET-OR-TAG]')]
[group('ghidra-inspect')]
ui-codegen-explain *args:
  uv run python -m tools.ui_codegen --gen-dir "{{build_dir}}/generated/ui" --explain {{args}}

[doc('Summarize per-case and per-node source-map coverage for one UI factory')]
[group('ghidra-inspect')]
ui-codegen-triage function:
  uv run python -m tools.ui_codegen --gen-dir "{{build_dir}}/generated/ui" --triage-map "{{function}}"

# Evidence-only predecessor: disassemble a Windows region into a draft.  It is
# intentionally outside the build/codegen pipeline.
[group('ghidra-inspect')]
gen-builder-binary *args:
  uv run python -m tools.binary.gen_builder_cpp {{args}}

# Audit every manual `new TViewFamily(...)` spelling against the original's allocator
# (TView::operator new 0x41b1c0 vs ::operator new 0x606f73). Exit 1 on mismatch.
[group('ghidra-inspect')]
alloc-audit:
  uv run python -m tools.binary.alloc_audit
# Read-only porting seed: decompile the target into an evidence draft the agent
# copies/repairs from by hand. Writes {{build_dir}}/evidence/decomp/<addr>.cpp and
# never touches source or ownership metadata (the replacement for the retired
# promote-from-autogen source mutation).
[doc('Seed a port: decompile 0xADDR into build evidence (read-only, never edits source)')]
[group('ghidra-inspect')]
seed-function addr: _require-ghidra-install
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p "{{build_dir}}/evidence/decomp"
  out="{{build_dir}}/evidence/decomp/{{addr}}.cpp"
  uv run python -m tools.ghidra.query decompile {{addr}} > "$out"
  echo "seeded $out ($(wc -l < "$out") lines) — copy/repair by hand; this file is evidence, not source"

# One-stop function status from the config CSVs + reccmp baseline (no Ghidra / no build,
# instant): curated name/size/proto, ownership, autogen body location, current match %.
# `just func-status 0xADDR [0xADDR ...]`.
[group('ghidra-inspect')]
func-status *args:
  uv run python -m tools.workflow.func_status {{args}}

# Rank porting candidates: the biggest weakly-matched functions (no Ghidra / no build).
# `just port-candidates [--range LO HI] [--min-size N] [--max-score PCT] [--limit N]`.
[group('ghidra-inspect')]
port-candidates *args:
  uv run python -m tools.workflow.port_candidates {{args}}
# Extract the immutable per-slot ABI evidence snapshot the vtable ABI audit
# consumes. Default: every `// VTABLE:`-annotated class in the tree, written to
# config/vtable_abi_evidence.json (slow; one-time — the binary never changes).
#   just vtable-abi-extract                       -> full refresh
#   just vtable-abi-extract TMapMaker=0x6598f8    -> one class, to stdout
[doc('Extract per-slot vtable ABI evidence (RET imm, ECX use, caller pushes/cleanup/ret-use)')]
[group('ghidra-inspect')]
vtable-abi-extract *args: _require-ghidra-install
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -z "{{args}}" ]; then
    uv run python -m tools.ghidra.query vtable-abi-evidence --from-source --out config/vtable_abi_evidence.json
  else
    uv run python -m tools.ghidra.query vtable-abi-evidence {{args}}
  fi

[group('ghidra-inspect')]
ghidra-vtable-struct-check *args: _require-ghidra-install
  uv run python -m tools.ghidra.vtable_struct_check {{args}}

[group('ghidra-inspect')]
ghidra-datatype-audit *args: _require-ghidra-install
  uv run python -m tools.ghidra.datatype_audit {{args}}

# MUTATES (with --apply): removes /Demangler/<Name> datatypes that duplicate a
# canonical root datatype by simple name, one cause of TypeResolver's
# ambiguous_simple_name grade. Dry-run by default.
[doc('Remove /Demangler duplicate datatypes that make TypeResolver name lookups ambiguous')]
[group('ghidra-inspect')]
dedupe-ambiguous-datatypes *args: _require-ghidra-install
  uv run python -m tools.ghidra.dedupe_ambiguous_datatypes {{args}}

# READ-ONLY: cross-check no_rtti class-model records against original-binary
# evidence (operator new immediates, ctor/dtor max-offset scans, derived-class
# zero-own-field chains). Writes build-msvc500/evidence/no_rtti_class_audit.csv.
[doc('READ-ONLY: audit no_rtti class-model records against original-binary evidence')]
[group('ghidra-inspect')]
no-rtti-class-audit *args: _require-ghidra-install
  uv run python -m tools.ghidra.no_rtti_class_audit {{args}}

# Decompile benchmark gate: must-keep patterns for curated Ghidra typing work.
# Pass --strict to also fail on missing should-improve patterns.
[doc('Decompile benchmark gate for curated Ghidra typing work')]
[group('ghidra-inspect')]
ghidra-decomp-check *args: _require-ghidra-install
  uv run python -m tools.ghidra.decomp_check {{args}}

# Classify functions as ecx_this (likely __thiscall) / no_ecx (likely cdecl) / empty (thunk).
# Pass addresses, or pipe addresses to --stdin (e.g. from config/original_entities.csv __cdecl rows).
# One-shot (NOT daemon-routed): --stdin addresses can't reach the daemon process. Running it
# evicts a warm daemon; re-warm with `just ghidra-daemon` afterwards.
[doc('Classify functions: ecx_this (thiscall) / no_ecx (cdecl) / empty (thunk)')]
[group('ghidra-inspect')]
scan-cdecl-thiscall *args: _require-ghidra-install
  uv run python -m tools.ghidra.scan_cdecl_thiscall {{args}}

[group('ghidra-inspect')]
class-owner-probe address *args: _require-ghidra-install
  uv run python -m tools.ghidra.class_owner_probe "{{address}}" {{args}}

# Walk every MFC CRuntimeClass descriptor in the binary: true class names, object
# sizes, base-class edges, resolved CreateObject addresses. Ground truth for class
# recovery — refresh config/rtti_class_oracle.csv with `--csv`.
[doc('Walk CRuntimeClass descriptors (ground truth); --csv refreshes config/rtti_class_oracle.csv')]
[group('ghidra-inspect')]
rtti-oracle *args: _require-ghidra-install
  uv run python -m tools.ghidra.rtti_class_oracle {{args}}

# Enumerate every MFC message map (AFX_MSGMAP): per-class message->handler table
# joined against function ownership (Audit C, bd 1uj.58.3). `--csv` for the full
# table, `--unported` for handlers with no manual owner.
[doc('Enumerate MFC message maps: message->handler->port-status per class; --csv / --unported')]
[group('ghidra-inspect')]
dump-message-maps *args: _require-ghidra-install
  uv run python -m tools.ghidra.dump_message_maps {{args}}

# ---------------------------------------------------------------------------
# ghidra-db — targets that WRITE the vendored Ghidra database.
# After any of these, `just export-project` must run before committing so the
# LFS .gzf matches the live project (ledger: docs/ghidra-db-mutations.md).
# ---------------------------------------------------------------------------

# One-time / fresh clone: recreate the live Ghidra working project from the vendored .gzf.
[group('ghidra-db')]
restore-project *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  uv run python -m tools.ghidra.restore_project {{args}}

# MUTATES: vendor/ghidra/exports/*.gzf (LFS).
# Refresh the committed .gzf archive from the live project after Ghidra-side changes.
[group('ghidra-db')]
export-project *args: _require-ghidra-install
  uv run python -m tools.ghidra.export_project {{args}}

# MUTATES: Ghidra DB (with --apply).
# Define real functions Ghidra never created (vtable slot targets, ILT jmp
# targets, inventory rows). Dry-run by default; --apply writes + saves the DB.
# See docs/ghidra-db-mutations.md before applying.
[doc('MUTATES: Ghidra DB (--apply). Define real functions Ghidra never created')]
[group('ghidra-db')]
repair-code-gaps *args: _require-ghidra-install
  uv run python -m tools.ghidra.repair_code_gaps {{args}}

# MUTATES: Ghidra DB (with --apply).
# Re-bound existing degenerate 1-byte functions in place (disassemble the entry,
# then fixupFunctionBody — preserves the curated name). Pass entry addresses.
# Dry-run by default; --apply writes + saves the DB.
[doc('MUTATES: Ghidra DB (--apply). Re-bound degenerate 1-byte functions')]
[group('ghidra-db')]
fix-function-bounds *args: _require-ghidra-install
  uv run python -m tools.ghidra.fix_function_bounds {{args}}

# MUTATES: Ghidra DB (with --apply).
# Define a computed-jump switch table (dword entries + COMPUTED_JUMP references
# from the jump instruction) so fixupFunctionBody can follow flow into the case
# bodies. Dry-run by default; --apply writes + saves the DB.
[doc('MUTATES: Ghidra DB (--apply). Define a switch jump table + references')]
[group('ghidra-db')]
create-switch-table *args: _require-ghidra-install
  uv run python -m tools.ghidra.create_switch_table {{args}}

# MUTATES: Ghidra DB (with --apply).
# Remove the Function entity at case-body pseudo-function entries (keeps the
# label) so an enclosing dispatcher can reabsorb the bytes on the next
# fix-function-bounds run. Refuses call-referenced targets without --force-refs.
[doc('MUTATES: Ghidra DB (--apply). Demote case-body pseudo-functions to labels')]
[group('ghidra-db')]
demote-functions *args: _require-ghidra-install
  uv run python -m tools.ghidra.demote_functions {{args}}

# MUTATES: Ghidra DB (with --apply).
# Delete stale user labels whose address manual source has since subsumed into a
# typed struct region (they poison reccmp's original-side operand rendering).
[doc('MUTATES: Ghidra DB (--apply). Delete stale user labels')]
[group('ghidra-db')]
delete-labels *args: _require-ghidra-install
  uv run python -m tools.ghidra.delete_labels {{args}}

# MUTATES: Ghidra DB (with --apply).
# Rename an existing function entry without changing its body or boundary. This
# covers compiler-generated source names that contain characters Ghidra rejects.
[doc('MUTATES: Ghidra DB (--apply). Rename existing function entries')]
[group('ghidra-db')]
rename-functions *args: _require-ghidra-install
  uv run python -m tools.ghidra.rename_functions {{args}}

# MUTATES: Ghidra DB (with --apply).
# Remove Function entities sitting on ILT jmp thunks (they block reccmp's thunk
# auto-resolution and collapse vtable matching). The DB-side counterpart of
# prune-ilt-thunks; refresh-inventory runs it automatically before the export.
[private]
[doc('MUTATES: Ghidra DB (--apply). Remove Function entities on ILT jmp thunks (runs inside refresh-inventory)')]
[group('ghidra-db')]
prune-ilt-db-functions *args: _require-ghidra-install
  uv run python -m tools.ghidra.prune_ilt_db_functions {{args}}

# READ-ONLY audit of Ghidra `in_stack_*` locals (unbound positive-stack reads).
# These are EVIDENCE (missing param OR wrong convention/boundary/purge/varargs),
# not a param oracle — classifies each into source-owned / library / unported
# buckets with the ABI evidence needed to repair the RIGHT fact. Writes
# build-msvc500/evidence/in_stack_audit.csv. (Replaces the retired unsound
# `fix-in-stack-params --apply`, whose addParameter appended params at
# convention-chosen offsets, not the detected slot — see the module docstring.)
[doc('Audit Ghidra in_stack_* locals (read-only): classify each with ABI evidence')]
[group('ghidra-inspect')]
in-stack-audit *args: _require-ghidra-install
  uv run python -m tools.ghidra.in_stack_audit {{args}}

# MUTATES: Ghidra DB (with --apply). Projects source-model C++ prototypes onto
# source-owned functions whose DB signature is weaker than the declaration (the
# MSVC500 PDB carries no arg types, so PDB import can't — see PR #91). Applies a
# COMPLETE signature via replaceParameters(DYNAMIC_STORAGE_FORMAL_PARAMS) with the
# convention from source (method=>__thiscall, free=>__cdecl), flushes the cache,
# re-decompiles, and KEEPS ONLY functions whose in_stack actually clears —
# reverting + queueing the rest (sret / packed-short / spurious) with evidence.
# --strict fails only on unparsable/apply_error (the classified queue is honest).
# Writes build-msvc500/evidence/source_signature_queue.csv.
[private]
[group('ghidra-db')]
apply-source-signatures *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  uv run python -m tools.ghidra.apply_source_signatures {{args}}

# MUTATES: Ghidra DB (with --apply). Source-DRIVEN projection: applies source
# signatures to claims the DB left incomplete/short (cc=unknown / 0 params / missing
# trailing params) regardless of whether they show in_stack — the majority that the
# in_stack-triggered apply-source-signatures never reaches. Per-function transaction,
# commit ONLY on full convergence (no in_stack introduced + structural signature
# match), rollback + queue everything else. Needs the decl index (clang-decl-index).
[private]
[group('ghidra-db')]
project-divergent-signatures *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  uv run python -m tools.ghidra.apply_source_signatures --project-divergent {{args}}

# MUTATES: Ghidra DB (with --apply). Recovers PACKED sub-dword parameter frames (two
# shorts in one dword, byte+short, ...) via CUSTOM_STORAGE: MSVC500 packs adjacent
# sub-dword args, which DYNAMIC_STORAGE dword-aligns and leaves an unbound in_stack
# read. Models the args tight-packed from 0x4 (this in ECX for __thiscall) and commits
# ONLY on a fully clean re-decompile — the packing is the hypothesis, the empty
# in_stack is the proof. Everything else rolls back.
[private]
[group('ghidra-db')]
project-packed-signatures *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  uv run python -m tools.ghidra.apply_source_signatures --project-packed {{args}}

# READ-ONLY static audit of the source->Ghidra signature projection: parses every
# source-owned C++ prototype and reports which resolve cleanly vs which are queued
# for a structural reason detectable without mutating (unparsable / unresolved
# type / sret by-value return). Does NOT verify convergence (that needs --apply);
# for the full picture run `apply-source-signatures --apply`. --strict fails on
# unparsable prototypes (a source-hygiene lint).
[doc('Static audit of source-model signature projection (read-only; no DB write)')]
[group('ghidra-inspect')]
source-signature-audit *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_source_signatures {{args}}

[doc('Cross-check oracle layouts vs binary RTTI sizes (read-only)')]
[group('ghidra-inspect')]
class-model-audit *args:
  uv run python -m tools.class_model_audit {{args}}

# READ-ONLY: measures semantic field-name/type quality per class (weak fieldXX/
# padXX names, void*, undefined placeholders) and ranks classes by active weak
# bytes x code-reference weight. Writes build-msvc500/evidence/class_field_coverage.csv.
[doc('READ-ONLY: semantic field-quality report ranking classes by weak-byte impact')]
[group('ghidra-inspect')]
class-field-coverage *args:
  uv run python -m tools.class_field_coverage {{args}}

# MUTATES: Ghidra DB (with --apply). Projects the VERIFIED class model into the DB:
# sized structures replace the 1-byte stubs (references rewrite), game bases are
# flattened at oracle offsets, MFC bases placed as single components, fields at
# exact oracle offsets (semantic type only when it matches the oracle size —
# physical truth wins), vptr at 0 for polymorphic roots. Only audit-verdict
# verified/no_rtti records project; source_incomplete/source_oversized stay
# blocked. Single transaction, verify-then-commit.
[private]
[group('ghidra-db')]
apply-class-model *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  uv run python -m tools.ghidra.apply_class_model {{args}}

# READ-ONLY structural convergence audit: for EVERY source/reviewed claim (not just
# functions showing in_stack), compare the expected signature (source model + clang
# decl index) against the DB signature on THREE separate tiers -- logical (cc/this/
# arity/varargs: converged / db_cc_unknown / db_signature_incomplete /
# convention_mismatch / this_presence_mismatch / param_count_mismatch /
# varargs_mismatch), abi_storage (per-param + return ABI sizes, sret presence; only
# evaluated once logical converges), and semantic (every resolved type is a REAL
# match -- exact_complete/canonical_alias -- not just an ABI-compatible pointer
# stand-in; only evaluated once abi_storage converges). No DB write. Writes
# build-msvc500/evidence/signature_convergence.csv.
[doc('READ-ONLY: audit every source signature vs the DB on 3 tiers (no DB write)')]
[group('ghidra-inspect')]
structural-signature-audit *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_source_signatures --structural-audit {{args}}

# READ-ONLY datatype-hygiene audit: report by-value uses of OPAQUE (empty/1-byte
# stub) custom types in source signatures, and flag any already COMMITTED in the DB
# (a wrong ABI — the projector believed a placeholder's size). `--strict` fails on
# any committed by-value opaque use. Pointer/reference uses of a stub are fine.
# The guard the class-model work must drive to zero. Writes
# build-msvc500/evidence/datatype_hygiene.csv.
[doc('READ-ONLY: flag by-value uses of empty/1-byte stub types in signatures (no DB write)')]
[group('ghidra-inspect')]
datatype-hygiene-audit *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_source_signatures --datatype-audit {{args}}

# READ-ONLY, no Ghidra needed (pure file I/O): merges the 3 per-mode projector
# queues (in_stack/divergent/packed -- previously one shared file, silently
# clobbered by whichever projector ran last) with the structural audit, datatype
# hygiene audit, and in_stack_audit into ONE address-keyed view, so nothing masks
# another phase's evidence. `--strict` fails on "unexplained structural divergence":
# a non-converged structural row with zero trace in any other evidence source.
# Writes build-msvc500/evidence/signature_evidence_union.csv.
[doc('READ-ONLY: merge all signature-projection evidence files by address (no Ghidra)')]
[group('ghidra-inspect')]
signature-evidence-union *args:
  uv run python -m tools.ghidra.signature_evidence_union {{args}}

# READ-ONLY: distinct-type inventory over every source signature's remaining
# opaque_pointee / generic_pointer_fallback / unresolved type-resolution grade
# (ambiguous_simple_name and opaque_by_value are already driven to zero). Each
# DISTINCT type text (not per-function) is classified as
# canonical_game_class_exists / canonical_mfc_type_exists /
# typedef_or_namespace_spelling_mismatch / missing_external_opaque_type /
# stale_duplicate / genuinely_unknown. Writes
# build-msvc500/evidence/weak_pointer_type_inventory.csv.
[doc('READ-ONLY: classify every remaining weak source-signature pointer/value type')]
[group('ghidra-inspect')]
weak-pointer-type-inventory *args: _require-ghidra-install
  uv run python -m tools.ghidra.weak_pointer_type_inventory {{args}}

# MUTATES: Ghidra DB (with --apply).
[private]
[group('ghidra-db')]
apply-mfc-datatypes *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_mfc_datatypes {{args}}

# MUTATES: Ghidra DB (with --apply).
[private]
[group('ghidra-db')]
apply-mfc-rtti *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_mfc_rtti {{args}}

# MUTATES: Ghidra DB (with --apply).
[private]
[group('ghidra-db')]
apply-fidb *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_fidb {{args}}

# MUTATES: Ghidra DB (with --apply).
# Atomically re-attribute a class in the DB: namespace + functions + datatypes +
# vtable-struct + vtable label, in one transaction (ghidra-apply-source only does
# function/label names, so a datatype-level junk name survives it). Dry-run by default.
#   just ghidra-rename-class TSoundChannelNode TLongintList --vtable 0x650a08 [--apply]
[doc('MUTATES: Ghidra DB (--apply). Atomically rename a class: namespace+datatypes+vtable')]
[private]
[group('ghidra-db')]
ghidra-rename-class old new *args: _require-ghidra-install
  uv run python -m tools.ghidra.rename_class {{old}} {{new}} {{args}}

# MUTATES: Ghidra DB (with --apply).
# Name + expand a class's <Class>Vtbl struct from its recovered header slot map so
# virtual dispatches through that class decompile as obj->vftable->Method(...).
[doc('MUTATES: Ghidra DB (--apply). Name + expand the <Class>Vtbl struct slots')]
[private]
[group('ghidra-db')]
name-vtable-slots *args: _require-ghidra-install
  uv run python -m tools.ghidra.name_vtable_slots {{args}}

# MUTATES: Ghidra DB (with --apply).
[private]
[group('ghidra-db')]
propagate-virtual-method-names *args: _require-ghidra-install
  uv run python -m tools.ghidra.propagate_virtual_method_names {{args}}

# MUTATES: Ghidra DB.
# Import source annotations into the Ghidra DB via reccmp-ghidra-import.
[private]
[group('ghidra-db')]
import-ghidra *args: _require-ghidra-install
  file_in_project="{{GHIDRA_PROGRAM_NAME}}"; \
  [[ "$file_in_project" == /* ]] || file_in_project="/$file_in_project"; \
  (cd "{{build_dir}}" && GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" uv run reccmp-ghidra-import \
    --target "{{target}}" \
    --local-project-name "{{GHIDRA_PROJECT_NAME}}" \
    --local-project-dir "{{GHIDRA_PROJECT_DIR}}" \
    --file "$file_in_project" \
    {{args}})

# Diagnostic: aggregate every identity signal for one address (symbols, ownership,
# reviewed override, cached FID match, object-matcher oracle) into a verdict.
# Run before behaviourally naming any MSVC/MFC-range or CRT-shaped function:
# a missing FID result is NOT evidence of game ownership. `just library-identify 0xADDR`.
[group('ghidra-inspect')]
library-identify address:
  uv run python -m tools.mfc.library_identify "{{address}}"
