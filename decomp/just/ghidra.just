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

[private]
[group('ghidra-inspect')]
ghidra-daemon-stop:
  uv run python -m tools.ghidra.daemon stop

[private]
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
# original-modules, portprep, vtable-dump.
[doc('Read-only Ghidra query dispatcher: just ghidra <cmd> <args> (no cmd lists them)')]
[group('ghidra-inspect')]
ghidra *args: _require-ghidra-install
  uv run python -m tools.ghidra.query {{args}}

# Read-only vtable evidence dump: resolve each slot of one or more vtables to its real
# body (ILT thunks chased) as JSON on stdout. Prefer `just ghidra vtable-dump` for the
# dispatcher path; this recipe remains for the slot-resolved JSON shape.
#   just class-vtable-dump TMapUberPicture=0x00668f08[:COUNT] [Base=0x... ...] [--decompile]
[private]
[doc('Read-only: dump a vtable class resolved slot targets as JSON (evidence only)')]
[group('ghidra-inspect')]
class-vtable-dump *args: _require-ghidra-install
  uv run python -m tools.ghidra.vtable_slots {{args}}

[private]
[group('ghidra-inspect')]
ui-resource-show resource:
  uv run python -m tools.ui_codegen --view "{{resource}}"

[private]
[group('ghidra-inspect')]
ui-codegen-explain *args:
  uv run python -m tools.ui_codegen --gen-dir "{{build_dir}}/generated/ui" --explain {{args}}

[private]
[group('ghidra-inspect')]
ui-codegen-triage function:
  uv run python -m tools.ui_codegen --gen-dir "{{build_dir}}/generated/ui" --triage-map "{{function}}"

# Classify functions as ecx_this (likely __thiscall) / no_ecx (likely cdecl) / empty (thunk).
# Pass addresses, or pipe addresses to --stdin (e.g. from config/original_entities.csv __cdecl rows).
# One-shot (NOT daemon-routed): --stdin addresses can't reach the daemon process. Running it
# evicts a warm daemon; re-warm with `just ghidra-daemon` afterwards.
[private]
[doc('Classify functions: ecx_this (thiscall) / no_ecx (cdecl) / empty (thunk)')]
[group('ghidra-inspect')]
scan-cdecl-thiscall *args: _require-ghidra-install
  uv run python -m tools.ghidra.scan_cdecl_thiscall {{args}}

[private]
[group('ghidra-inspect')]
class-owner-probe address *args: _require-ghidra-install
  uv run python -m tools.ghidra.class_owner_probe "{{address}}" {{args}}

# Walk every MFC CRuntimeClass descriptor in the binary: true class names, object
# sizes, base-class edges, resolved CreateObject addresses. Ground truth for class
# recovery — refresh config/rtti_class_oracle.csv with `--csv`.
[private]
[doc('Walk CRuntimeClass descriptors (ground truth); --csv refreshes config/rtti_class_oracle.csv')]
[group('ghidra-inspect')]
rtti-oracle *args: _require-ghidra-install
  uv run python -m tools.ghidra.rtti_class_oracle {{args}}

# Enumerate every MFC message map (AFX_MSGMAP): per-class message->handler table
# joined against function ownership. `--csv` for the full
# table, `--unported` for handlers with no manual owner.
[private]
[doc('Enumerate MFC message maps: message->handler->port-status per class; --csv / --unported')]
[group('ghidra-inspect')]
dump-message-maps *args: _require-ghidra-install
  uv run python -m tools.ghidra.dump_message_maps {{args}}

# ---------------------------------------------------------------------------
# ghidra-db — targets that WRITE the vendored Ghidra database.
# After any of these, `just export-project` must run before committing so the
# LFS .gzf matches the live project. See docs/ghidra-db.md.
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
[private]
[doc('MUTATES: Ghidra DB (--apply). Define real functions Ghidra never created')]
[group('ghidra-db')]
repair-code-gaps *args: _require-ghidra-install
  uv run python -m tools.ghidra.repair_code_gaps {{args}}

# MUTATES: Ghidra DB (with --apply).
# Re-bound existing degenerate 1-byte functions in place (disassemble the entry,
# then fixupFunctionBody — preserves the curated name). Pass entry addresses.
# Dry-run by default; --apply writes + saves the DB.
[private]
[doc('MUTATES: Ghidra DB (--apply). Re-bound degenerate 1-byte functions')]
[group('ghidra-db')]
fix-function-bounds *args: _require-ghidra-install
  uv run python -m tools.ghidra.fix_function_bounds {{args}}

# MUTATES: Ghidra DB (with --apply).
# Define a computed-jump switch table (dword entries + COMPUTED_JUMP references
# from the jump instruction) so fixupFunctionBody can follow flow into the case
# bodies. Dry-run by default; --apply writes + saves the DB.
[private]
[doc('MUTATES: Ghidra DB (--apply). Define a switch jump table + references')]
[group('ghidra-db')]
create-switch-table *args: _require-ghidra-install
  uv run python -m tools.ghidra.create_switch_table {{args}}

# MUTATES: Ghidra DB (with --apply).
# Remove the Function entity at case-body pseudo-function entries (keeps the
# label) so an enclosing dispatcher can reabsorb the bytes on the next
# fix-function-bounds run. Refuses call-referenced targets without --force-refs.
[private]
[doc('MUTATES: Ghidra DB (--apply). Demote case-body pseudo-functions to labels')]
[group('ghidra-db')]
demote-functions *args: _require-ghidra-install
  uv run python -m tools.ghidra.demote_functions {{args}}

# MUTATES: Ghidra DB (with --apply).
# Delete stale user labels whose address manual source has since subsumed into a
# typed struct region (they poison reccmp's original-side operand rendering).
[private]
[doc('MUTATES: Ghidra DB (--apply). Delete stale user labels')]
[group('ghidra-db')]
delete-labels *args: _require-ghidra-install
  uv run python -m tools.ghidra.delete_labels {{args}}

# MUTATES: Ghidra DB (with --apply).
# Remove Function entities sitting on ILT jmp thunks (they block reccmp's thunk
# auto-resolution and collapse vtable matching). The DB-side counterpart of
# prune-ilt-thunks; refresh-inventory runs it automatically before the export.
[private]
[doc('MUTATES: Ghidra DB (--apply). Remove Function entities on ILT jmp thunks (runs inside refresh-inventory)')]
[group('ghidra-db')]
prune-ilt-db-functions *args: _require-ghidra-install
  uv run python -m tools.ghidra.prune_ilt_db_functions {{args}}

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

# Diagnostic: aggregate maintained identity signals for one address (symbols,
# ownership, reviewed override, object-matcher oracle) into a verdict. Run before
# behaviourally naming any MSVC/MFC-range or CRT-shaped function.
[private]
[group('ghidra-inspect')]
library-identify address:
  uv run python -m tools.mfc.library_identify "{{address}}"
