# ---------------------------------------------------------------------------
# sync — regenerate derived artifacts (original_entities.csv).
# The three canonical playbooks live in docs/workflows.md.
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

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

# The full one-command operation: build (fresh PDB/inputs), apply the source
# model to the DB, export the vendored .gzf.
# Order matters: the PDB import names entities from the generated data sources
# (inventory names), so the source-declaration name pass must run AFTER it —
# source names win last.
# Class projection runs BEFORE signature projection so the signature projector
# resolves parameter types against real layouts instead of 1-byte placeholders.
[doc('MUTATES: Ghidra DB + vendored .gzf. build -> import -> names -> type model -> class projection -> signature projection -> audits -> export')]
[group('sync')]
ghidra-apply-source-full:
  just build
  just import-ghidra
  just ghidra-apply-source --apply --quiet --strict
  just ghidra-apply-source --quiet --strict
  just clang-decl-index
  just generate-type-model
  just apply-class-model --apply
  just apply-source-signatures --apply --strict
  just project-divergent-signatures --apply --strict
  just project-packed-signatures --apply --strict
  just in-stack-audit
  just structural-signature-audit
  just datatype-hygiene-audit
  just signature-evidence-union --strict
  just export-project

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

# MUTATES: config/original_entities.csv.
# Drop incremental-link `jmp` thunk rows (linker artifacts) from config/original_entities.csv.
# reccmp auto-detects unannotated jmp thunks and excludes them from the report.
[private]
[doc('MUTATES: original_entities.csv. Drop ILT jmp-thunk function rows (linker artifacts)')]
[group('sync')]
prune-ilt-thunks *args:
  uv run python -m tools.workflow.prune_ilt_thunks {{args}}

# Build the Clang-AST declaration index (qualified name -> kind/static/types) from a
# real clang parse of the game headers with the vendored MSVC500/MFC includes. Gives
# the projector authoritative static-vs-instance-vs-namespace facts a definition head
# cannot show. Writes build-msvc500/generated/decl_index.json. Needs host clang++
# and the vendored headers (`just vendor-msvc500-headers`).
[doc('Generate the Clang-AST declaration index (entity kind + types) for the projector')]
[group('sync')]
clang-decl-index *args:
  uv run python -m tools.clang_ast_index {{args}}

# The durable class model, two strictly separated evidence layers:
#   SEMANTIC  — Clang AST record walk (records/bases/fields; never host layout)
#   PHYSICAL  — the MSVC500 layout oracle: a generated TU compiled+run by the REAL
#               VC5 container (same flags as the game), printing sizeof/offsets.
# Then the audit cross-checks oracle sizeof against the original binary's
# CRuntimeClass::m_nObjectSize (config/rtti_class_oracle.csv):
#   verified / source_incomplete (missing trailing fields; projection blocked) /
#   source_oversized (modelling error; projection blocked) / no_rtti.
# Needs docker (imperialism-msvc500 image) for the oracle step.
[doc('Generate the class type model: AST records -> MSVC500 layout oracle -> RTTI audit')]
[group('sync')]
generate-type-model:
  uv run python -m tools.class_model
  uv run python -m tools.layout_oracle
  uv run python -m tools.class_model_audit

[doc('AST record extraction only (semantic layer of the class model)')]
[private]
[group('sync')]
record-model *args:
  uv run python -m tools.class_model {{args}}

[doc('MSVC500 layout oracle only (physical layer; needs docker)')]
[private]
[group('sync')]
layout-oracle *args:
  uv run python -m tools.layout_oracle {{args}}
