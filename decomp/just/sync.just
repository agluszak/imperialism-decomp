# ---------------------------------------------------------------------------
# sync — regenerate derived artifacts (original_entities.csv).
# The three canonical playbooks live in docs/workflows.md.
# ---------------------------------------------------------------------------

# MUTATES: Ghidra DB (--apply). The ONE sanctioned source->Ghidra operation:
# derives names from source markers + C++ declarations (inventory names as
# fallback), applies function names/namespaces (primary-aware), labels, and
# `Class::'vftable'` labels from // VTABLE: annotations, then audits datatype
# drift. Dry-run by default. There is no automated Ghidra->source path.
[doc('MUTATES: Ghidra DB (--apply). One-way apply of the source model; dry-run default')]
[group('sync')]
ghidra-apply-source *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  uv run python -m tools.ghidra.apply_source {{args}}

# MUTATES: Ghidra DB (prune), config/original_entities.csv (curated refresh).
# Intentional raw-inventory refresh from the DB after boundary analysis
# (gap repair, function-bounds fixes). Preserves curated names, prototypes, and
# link-required function types while importing new DB entities.
[doc('MUTATES: original_entities.csv (curated merge) + Ghidra DB boundary repair. Refresh the raw inventory')]
[group('sync')]
refresh-inventory *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon stop --quiet
  just prune-ilt-db-functions --apply --quiet
  just ghidra-apply-source --apply --quiet --strict --prune-vtable-interiors-only --demote-embedded-functions-only
  just ghidra-apply-source --quiet --strict --prune-vtable-interiors-only --demote-embedded-functions-only
  uv run python -m tools.ghidra.sync_exports \
    --inventory-only \
    --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
    --ghidra-project-dir "{{GHIDRA_PROJECT_DIR}}" \
    --ghidra-project-name "{{GHIDRA_PROJECT_NAME}}" \
    --ghidra-program-name "{{GHIDRA_PROGRAM_NAME}}" \
    {{args}}
  just prune-ilt-thunks
  just symbols-anchor-gate
  just symbols-integrity-gate
  just vtable-collision-gate
  @echo "refresh-inventory done. Run 'just export-project' before committing."

# MUTATES: config/original_entities.csv (with --apply).
# Drop inventory rows whose Ghidra entity is gone (after demote-functions /
# delete-labels / a fix-function-bounds reabsorb). Verifies against the live DB that each
# named address has no function and no label, and that no source marker claims it; keeps
# anything that fails a check. Dry-run by default.
[doc('MUTATES: original_entities.csv (--apply). Drop rows whose Ghidra entity is gone')]
[group('sync')]
inventory-drop *args: _require-ghidra-install
  uv run python -m tools.ghidra.inventory_drop {{args}}

# MUTATES: config/original_entities.csv.
# Drop incremental-link `jmp` thunk rows (linker artifacts) from config/original_entities.csv.
# reccmp auto-detects unannotated jmp thunks and excludes them from the report.
[private]
[doc('MUTATES: original_entities.csv. Drop ILT jmp-thunk function rows (linker artifacts)')]
[group('sync')]
prune-ilt-thunks *args:
  uv run python -m tools.workflow.prune_ilt_thunks {{args}}
