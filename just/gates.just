# ---------------------------------------------------------------------------
# gates — mechanical checks (all read-only).
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

[doc('Validate committed UI semantics, structural invariants, and class bindings')]
[group('gates')]
ui-codegen-check:
  uv run python -m tools.ui_codegen --check

[doc('Account for every committed Mac View in the Windows source model')]
[group('gates')]
ui-view-coverage *args:
  uv run python -m tools.workflow.ui_view_coverage {{args}}

[doc('Reject unclassified Mac Views and a stale committed coverage report')]
[group('gates')]
ui-view-coverage-check:
  uv run python -m tools.workflow.ui_view_coverage --check

[doc('Generate the source-only turn-event screen and callback coverage matrix')]
[group('gates')]
turn-event-coverage *args:
  uv run python -m tools.workflow.turn_event_coverage {{args}}

[doc('Reject a stale committed turn-event coverage matrix')]
[group('gates')]
turn-event-coverage-check:
  uv run python -m tools.workflow.turn_event_coverage --check

[doc('Generate the classified scalar-conversion and enum-candidate audit')]
[group('gates')]
scalar-type-audit *args:
  uv run python -m tools.workflow.scalar_type_audit {{args}}

[doc('Reject new or stale scalar-conversion and enum-candidate findings')]
[group('gates')]
scalar-type-audit-check:
  uv run python -m tools.workflow.scalar_type_audit --check

[doc('Generate the classified four-character tag inventory')]
[group('reports')]
fourcc-audit *args:
  uv run python -m tools.workflow.fourcc_audit {{args}}

[doc('Reject raw/duplicate/mis-spelled four-character tags and a stale inventory')]
[group('gates')]
fourcc-audit-check:
  uv run python -m tools.workflow.fourcc_audit --check

[doc('Reject stale Mac control class/tag/screen semantic metadata')]
[group('gates')]
mac-control-usage-check:
  uv run python -m tools.workflow.mac_control_usage --check

[doc('Reject stale resource xrefs and unexplained dangling edges')]
[group('gates')]
mac-resource-xrefs-check:
  uv run python -m tools.workflow.mac_resource_xrefs --check

[doc('Reject stale Mac widget payload differential evidence')]
[group('gates')]
mac-payload-diff-check:
  uv run python -m tools.workflow.mac_payload_diff --check

[doc('Reject stale Mac-to-Windows string crosswalk metadata')]
[group('gates')]
mac-string-crosswalk-check:
  uv run python -m tools.workflow.mac_string_crosswalk --check

[doc('Reject undeclared or stale UI platform deltas')]
[group('gates')]
ui-platform-diff-check:
  uv run python -m tools.workflow.ui_platform_diff --check

# ---------------------------------------------------------------------------
# gates — mechanical checks (all read-only).
# ---------------------------------------------------------------------------

# The complete repository verification sequence in one local command. It includes
# the checks that formerly lived in hosted automation: the lint rejection fixture,
# generated-artifact integrity over the branch/worktree diff, and the asset-backed
# PR runtime suite. Review the stats delta, then run `just stats-baseline-update`
# if accepted and commit the baseline with the change.
[doc('Complete local verification: builds + gates + tests + integrity + runtime suite')]
[group('gates')]
precommit:
  just build
  just gates
  just cstring-runtime-probe
  just runtime-harness-lint
  just lint-warning-gate-test
  just test
  just _precommit-generated-integrity-gate
  just runtime-check pr --jobs 1 --junit build-runtime-tests/runtime-pr.xml

# Compare the entire current branch plus worktree with main. PRECOMMIT_BASE_REF
# permits an explicit integration base; otherwise prefer origin/main, then local
# main. A single-branch checkout still checks all uncommitted changes against HEAD.
[private]
_precommit-generated-integrity-gate:
  #!/usr/bin/env bash
  set -euo pipefail
  base_ref="${PRECOMMIT_BASE_REF:-}"
  if [[ -z "$base_ref" ]]; then
    if git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null; then
      base_ref=origin/main
    elif git rev-parse --verify --quiet refs/heads/main >/dev/null; then
      base_ref=main
    else
      base_ref=HEAD
    fi
  fi
  base="$(git merge-base HEAD "$base_ref")"
  echo "Generated-integrity base: $base ($base_ref)"
  just generated-integrity-gate --base "$base"

# Run all mechanical source-policy gates (the pre-commit check).
# Run `just format-check <touched paths>` separately on files you edited; the tree
# is not fully clang-formatted, so format-check is per-path, not whole-tree.
[doc('Run all mechanical source-policy gates (the pre-commit check)')]
[group('gates')]
gates:
  just source-gates
  just stats --ui-codegen-gate --fail-on-regression
  just semantic-gate
  just vtable
  just datacmp-gate
  just decomplint
  just lint-warning-gate

# Named warning gate used by the general checks. Keep it separate from the
# implementation recipe so callers have one stable policy entrypoint.
[doc('Fail unless every clang-cl lint translation unit compiles warning-free')]
[group('gates')]
lint-warning-gate:
  just lint

[group('gates')]
tooling-check:
  uv run python -m tools.workflow.check_tooling_surface

# Generated stub count vs baseline (ratchet down). A rise is the un-claiming
# tell: a real owner lost its marker and would be re-stubbed, breaking vtables.
[group('gates')]
stub-count-gate:
  uv run python -m tools.workflow.check_stub_count

# ASSERT_SIZE vs the RTTI oracle, strict; known mismatches must be allowlisted
# in config/class_size_allowlist.txt with a tracking bead.
[group('gates')]
class-size-gate:
  uv run python -m tools.workflow.check_class_sizes --strict --allowlist config/class_size_allowlist.txt

# Global-data drift vs baseline: reccmp-datacmp fingerprints may not regress.
# Needs a built binary (like `just vtable`); `just datacmp` stays the raw report.
[group('gates')]
datacmp-gate:
  uv run python -m tools.workflow.check_datacmp_baseline --target "{{target}}" --build-dir "{{build_dir}}"

# Empty-body ratchet: silent `{}` placeholders may not grow; intentionally-empty
# bodies need a // FUNCTION marker or a `// NOOP: verified empty in original 0xADDR`.
[group('gates')]
noop-gate:
  uv run python -m tools.workflow.check_empty_bodies --baseline config/baselines/empty_body_baseline.csv

# Ratchet: no NEW constructor defined out-of-line without a claimed address. Such a ctor
# cannot be inlined into subclass ctors / CreateObject bodies in other TUs, so VC5 emits a
# CALL where the original absorbed the body. Read the caller before fixing -- bd nwdn.
[group('gates')]
ctor-placement-gate:
  uv run python -m tools.workflow.check_ctor_placement

# Report every empty-body finding (audit mode of the noop gate).
# `just noop-audit [--kind empty_but_big|empty_unmarked|empty_unresolved]`
[group('gates')]
noop-audit *args:
  uv run python -m tools.workflow.check_empty_bodies {{args}}

# Audit Hard-Rule-9 typedef casts against binary evidence (RET-imm purge bytes):
# catches dropped-args/convention bugs drift can't see. Report-only; --strict to fail.
[group('gates')]
typedef-args-audit *args:
  uv run python -m tools.workflow.check_typedef_ghidra_args {{args}}

# Run the Python tooling unit tests (tests/tools).
[group('gates')]
test:
  # Off-screen: a few of these exercise the Wine harness end to end, and without this
  # they map a game window on the developer's desktop and steal focus mid-run.
  IMPERIALISM_RUNTIME_DISPLAY=virtual uv run python -m unittest discover -s tests/tools

[doc('Ratchet every manual FUNCTION high-p-code call contract; regenerates stale build evidence')]
[group('gates')]
semantic-gate: _require-ghidra-install
  uv run python -m tools.semantic_calls --target "{{target}}" --build-dir "{{build_dir}}" gate --generate-if-stale

[doc('Audit every ported ReadFrom/WriteTo for save-file byte desync against the listing')]
[group('reports')]
serde-audit *args:
  uv run python -m tools.workflow.serde_audit {{args}}

# Raw-vtable source gate (Hard Rule 13); also runs as the first step of `just build`.
[group('gates')]
vtable-gate:
  uv run python -m tools.workflow.check_no_raw_vtable_calls

# Vtable ABI audit: current source declarations vs the binary's immutable
# calling-convention evidence (config/vtable_abi_evidence.json). Catches wrong
# signatures that `just vtable` (slot->address matching) cannot see.
#   just vtable-abi-audit                 -> ranked report, conflict classes only
#   just vtable-abi-audit TMapMaker -v    -> one class, all slots
[doc('Audit vtable slot declarations against binary ABI evidence (RET imm, pushes, ret-use)')]
[group('gates')]
vtable-abi-audit *args:
  uv run python -m tools.workflow.vtable_abi_audit {{args}}

# Hard-ban gate over the ABI audit: fails on ANY proven declaration conflict not
# covered by a reviewed config/vtable_signature_overrides.csv row. Baseline-free.
# Pure source + static evidence; no Ghidra needed.
[group('gates')]
vtable-abi-gate:
  uv run python -m tools.workflow.vtable_abi_audit --gate

[group('gates')]
marker-gate:
  uv run python -m tools.workflow.check_marker_hygiene --paths src include

# Reject stale recover-class "generated declaration" ownership markers in manual
# source (include/game, src/game). Those "do not hand-edit" boundaries are obsolete:
# all game source is hand-owned; the read-only extractor (`just class-vtable-dump`)
# inspects but never rewrites it. Excludes the real generated trees.
[group('gates')]
generated-marker-gate:
  uv run python -m tools.workflow.check_generated_markers

# CString is the real VC5/MFC type: reject pseudo/internal models, unpaired mutable
# buffers, and CString objects passed through the stack-indexed string ellipsis.
[group('gates')]
cstring-gate:
  uv run python -m tools.workflow.check_cstring_usage

[group('gates')]
cstring-ownership-audit-check:
  uv run python -m tools.workflow.cstring_ownership_audit --check

# Hard-ban gate: "dual-use"/"dual-purpose"/"reused as" hand-waving and raw
# pointer<->int member storage (reinterpret_cast<int>(ptr), int-member->class-pointer
# casts). A purported dual-use field is an unresolved modelling defect: prove one model
# (union/record/accessors) or mark it // UNRESOLVED_FIELD_ATTRIBUTION: with both readings
# + evidence. Baseline-free: zero occurrences allowed.
[group('gates')]
dual-use-gate:
  uv run python -m tools.workflow.check_dual_use

# Enforce the recovered geometry boundary: game-owned APIs use CPoint/CRect, while
# POINT/RECT remain at verified Win32/MFC boundaries. Reject cast bridges; only a
# locally documented GEOMETRY_RAW_BUFFER packed payload may require one.
[group('gates')]
geometry-type-gate:
  uv run python -m tools.workflow.check_geometry_types

# Hard-ban gate against ILT/thunk-name ossification in manual source: rejects ANY
# identifier that starts with thunk_/ILT_/WrapperFor_ or ends with _At<8hex> (calls via
# linker thunks; history-encoded body names). Baseline-free: zero occurrences allowed.
[group('gates')]
ilt-ossification-gate:
  uv run python -m tools.workflow.check_ilt_ossification

# Ensure every `// VTABLE:` annotation is immediately followed by its class/struct
# (not a forward declaration, comment, or blank line).
[doc('Every // VTABLE: must be immediately followed by its class/struct')]
[group('gates')]
vtable-annotation-gate:
  uv run python -m tools.workflow.check_vtable_annotations --paths src include

# Ensure no inventory DATA row or `// GLOBAL:` marker collides with a `// VTABLE:`
# address (which would make reccmp drop the vtable entity as a duplicate).
[doc('No inventory DATA row or // GLOBAL: marker may collide with a // VTABLE: address')]
[group('gates')]
vtable-collision-gate:
  uv run python -m tools.workflow.check_vtable_address_collisions --paths src include

# Ensure synthetic symbol names in source comments match symbols.csv.
[group('gates')]
synthetic-gate:
  uv run python -m tools.workflow.check_synthetic_names --paths src include

# Every explicit destructor is placed where its original evidence puts it: a standalone
# ~Class body out of line (or inline with its // FUNCTION: marker), a listing-proven
# inline body in the header, or an empty body backing a scalar deleting destructor.
# Empty destructors with none of those three justifications are source noise.
[doc('Explicit destructors match their original evidence (standalone / inline-proven / compiler-generated)')]
[group('gates')]
destructor-placement-gate:
  uv run python -m tools.workflow.check_destructor_placement --paths src include

# Structural integrity of config/original_entities.csv: header row exactly at line 1, no
# duplicate headers, parseable hex addresses, no duplicate addresses, no two
# function rows claiming overlapping byte ranges. (Every consumer is a DictReader
# that silently degrades when the header is misplaced.)
[doc('symbols.csv structural integrity: header at line 1, parseable + unique addresses, no function-range overlaps')]
[group('gates')]
symbols-integrity-gate:
  uv run python -m tools.workflow.check_symbols_integrity

# Reject editor indexes, compiler output, build trees, stray logs, and large non-LFS
# binaries from the tracked tree. Complements .gitignore: ignoring a directory only stops
# the next add of that exact path, which is how 1933 clangd index files under .cache/
# survived until PR #318. Whole-tree rather than diff-scoped, because every category is at
# zero tracked hits -- a diff-scoped check would grandfather whatever slipped in earlier.
[doc('Reject tracked build/editor artifacts and stray large binaries')]
[group('gates')]
repo-hygiene-gate:
  uv run python -m tools.workflow.check_repo_hygiene

# Reject generated build inputs and retired generated source trees in a branch or
# worktree diff. `precommit` resolves the merge base and includes local changes.
[doc('Reject generated artifacts relative to a merge base')]
[group('gates')]
generated-integrity-gate *args:
  uv run python -m tools.workflow.check_generated_integrity {{args}}

# Semantic gate for reviewed MSVC500 library identities: every row in
# config/reviewed_library_identities.csv must be faithfully projected (overlay+markers)
# (name/symbol/prototype/type) + ownership=library, and the applied count must not
# fall below the ratchet baseline. Pins e.g. 0x005e83f0 = rand/_rand permanently.
[doc('Semantic library-identity gate: reviewed overrides applied + ownership=library + ratchet')]
[group('gates')]
library-identity-gate:
  uv run python -m tools.workflow.check_library_identity

# Sanity-check a few reccmp-critical symbols.csv rows after Ghidra export.
[group('gates')]
symbols-anchor-gate:
  uv run python -m tools.workflow.check_symbols_anchors

[group('gates')]
antipattern-gate:
  uv run python -m tools.workflow.check_construction_antipatterns

# Ensure // GLOBAL: markers live in global_data_tables.cpp and declarations in global_data_tables.h
[group('gates')]
global-location-gate:
  uv run python -m tools.workflow.check_global_location --source-dir src --include-dir include

# Ensure manual CRuntimeClass definitions are replaced with MFC macros
[group('gates')]
manual-cruntimeclass-gate:
  uv run python -m tools.workflow.check_manual_cruntimeclass --source-dir src

# Structure-audit gate (8mo.18): no duplicate top-level #include, no alias headers, no CRLF in manual
# source. Umbrella home for the source-structure cleanups; more rules land with 8mo.11-16.
[group('gates')]
structure-audit-gate:
  uv run python -m tools.workflow.check_structure_audit

# Check the decompilation annotations (// FUNCTION / // VTABLE / // GLOBAL etc.)
# for syntax errors, duplicate addresses, and stray markers.
[doc('reccmp annotation lint: marker syntax, duplicate addresses, stray markers')]
[group('gates')]
decomplint:
  (cd "{{build_dir}}" && uv run reccmp-decomplint --target "{{target}}" --warnfail)

# Manual audits of the legacy typedef-cast scaffolding (0 instances remain in the
# tree; new casts are already hard-banned by antipattern-gate + boundary-gate, so
# these no longer run per-commit -- keep them as rare on-demand audits).
[doc('Audit Hard-Rule-9 typedef-cast externs for cross-file signature drift (report-only)')]
[group('gates')]
typedef-cast-audit *args:
  uv run python -m tools.workflow.check_typedef_cast_drift {{args}}

# No local `extern` redeclarations of globals already in global_data_tables.h.
[group('gates')]
global-redeclaration-gate:
  uv run python -m tools.workflow.check_global_redeclarations

# Hard-ban gate over the boundary report: zero manual->stub call/cast references
# and zero function-pointer casts of named symbols (both counts must stay at 0).
[group('gates')]
boundary-gate:
  uv run python -m tools.workflow.check_boundary_ratchet

# Shadow-stub gate (bead rcb6): non-virtual degenerate methods that hide a real vtable
# slot -- direct calls into do-nothing bodies where the original dispatches virtually.
# Ratchets against config/baselines/shadow_stub_baseline.csv (known offenders tracked to
# their beads); any NEW offender is a hard error. Refresh with `--write-baseline` only
# when a tracked offender is genuinely fixed.
[group('gates')]
shadow-stub-gate:
  uv run python -m tools.workflow.check_shadow_stubs

# Lint the structured agent rule KB (config/agent_rules.yml): ids, supersedes,
# required/forbidden contradictions, just-only tools, derivable triggers.
[group('gates')]
agent-rules-gate:
  uv run python -m tools.workflow.check_agent_rules

# The binary-free gate subset (no docker/wine/original exe: excludes vtable,
# datacmp-gate, decomplint, and lint). Keep in sync with `gates`.
[doc('Source-only gate subset; no built binary needed')]
[group('gates')]
source-gates:
  just generate
  just --jobs 4 _source-gates-parallel

[private]
[parallel]
_source-gates-parallel: ui-codegen-check ui-view-coverage-check turn-event-coverage-check scalar-type-audit-check fourcc-audit-check ui-platform-diff-check tooling-check vtable-gate antipattern-gate marker-gate generated-marker-gate cstring-gate cstring-ownership-audit-check dual-use-gate geometry-type-gate ilt-ossification-gate vtable-annotation-gate vtable-collision-gate synthetic-gate destructor-placement-gate symbols-integrity-gate repo-hygiene-gate library-identity-gate global-location-gate manual-cruntimeclass-gate structure-audit-gate stub-count-gate class-size-gate noop-gate ctor-placement-gate global-redeclaration-gate boundary-gate agent-rules-gate vtable-abi-gate shadow-stub-gate

# Cross-check modeled class sizes (ASSERT_SIZE) against the RTTI oracle's
# m_nObjectSize. Report-only; pass --strict to fail on mismatches, or
# --show-unasserted to list oracle classes with no size assert yet.
[doc('ASSERT_SIZE vs RTTI-oracle object sizes; --strict to fail on mismatch')]
[group('gates')]
class-size-check *args:
  uv run python -m tools.workflow.check_class_sizes {{args}}

# Report `// VTABLE:` annotations that reccmp does not turn into a matched vtable
# (needs a built binary + reccmp DB, so it is not part of `just gates`). Pass --strict
# to also fail on annotations whose recompiled vtable is missing.
[doc('Report // VTABLE: annotations reccmp did not match (needs built binary)')]
[group('gates')]
vtable-coverage *args:
  uv run python -m tools.workflow.check_vtable_coverage --project-dir "{{build_dir}}" {{args}}

# Report classes whose last original vtable slot resolves to a source-declared
# non-virtual method. This is evidence for manual review, never an automatic gate.
[doc('Report possible unmodelled vtable tail slots for manual verification')]
[group('reports')]
vtable-tail-slots *args:
  uv run python -m tools.workflow.check_vtable_tail_slots {{args}}

[group('gates')]
format-check *paths:
  uv run python -m tools.workflow.format_cpp --check {{paths}}
