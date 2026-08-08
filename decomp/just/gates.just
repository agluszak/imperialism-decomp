[private]
[doc('Validate committed UI semantics, structural invariants, and class bindings')]
[group('gates')]
ui-codegen-check:
  uv run python -m tools.ui_codegen --check

# The complete repository verification sequence in one local command. It includes
# the checks that formerly lived in hosted automation: the lint rejection fixture,
# generated-artifact integrity over the branch/worktree diff, and the asset-backed
[doc('Complete local verification: builds + gates + tests + integrity + runtime suite')]
[group('gates')]
precommit:
  just --jobs 2 _precommit-builds
  just --jobs 4 _precommit-after-build

[private]
[parallel]
_precommit-builds: build runtime-test-build

[private]
[parallel]
_precommit-after-build: _precommit-post-build-checks _precommit-runtime-check

[private]
_precommit-runtime-check:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY to your legally obtained Imperialism.exe}"
  test -f "$ORIGINAL_BINARY"
  uv run python -m tools.runtime.cli suite pr --require-fixtures --jobs 1 \
    --junit build-runtime-tests/runtime-pr.xml

# These checks touch disjoint build/output trees and are read-only over tracked source.
# Running them together hides gate and tooling-test latency without changing what
# precommit proves.
[private]
[parallel]
_precommit-post-build-checks: gates _precommit-independent-checks

[private]
[parallel]
_precommit-independent-checks: runtime-harness-lint lint-warning-gate-test test _precommit-generated-integrity-gate

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
  just vtable
  just decomplint
  just lint-warning-gate

# Named warning gate used by the general checks. Keep it separate from the
# implementation recipe so callers have one stable policy entrypoint.
[private]
[doc('Fail unless every clang-cl lint translation unit compiles warning-free')]
[group('gates')]
lint-warning-gate:
  just lint

# ASSERT_SIZE vs the RTTI oracle. Any mismatch is a hard failure.
[private]
[group('gates')]
class-size-gate:
  uv run python -m tools.workflow.check_class_sizes --strict

# Empty-body hard ban: intentionally-empty
# bodies need a // FUNCTION marker or a `// NOOP: verified empty in original 0xADDR`.
[private]
[group('gates')]
noop-gate:
  uv run python -m tools.workflow.check_empty_bodies --gate

# Report every empty-body finding (audit mode of the noop gate).
# `just noop-audit [--kind empty_but_big|empty_unmarked|empty_unresolved]`
[private]
[group('gates')]
noop-audit *args:
  uv run python -m tools.workflow.check_empty_bodies {{args}}

# Run the Python tooling unit tests (tests/tools).
[group('gates')]
test:
  # Off-screen: a few of these exercise the Wine harness end to end, and without this
  # they map a game window on the developer's desktop and steal focus mid-run.
  IMPERIALISM_RUNTIME_DISPLAY=virtual uv run python -m unittest discover -s tests/tools

[doc('Audit every ported ReadFrom/WriteTo for save-file byte desync against the listing')]
[group('reports')]
serde-audit *args:
  uv run python -m tools.workflow.serde_audit {{args}}

# Raw-vtable source gate (Hard Rule 13); also runs as the first step of `just build`.
[private]
[group('gates')]
vtable-gate:
  uv run python -m tools.workflow.check_no_raw_vtable_calls

[private]
[group('gates')]
marker-gate:
  uv run python -m tools.workflow.check_marker_hygiene --paths src include

# CString is the real VC5/MFC type: reject pseudo/internal models, unpaired mutable
# buffers, and CString objects passed through the stack-indexed string ellipsis.
[private]
[group('gates')]
cstring-gate:
  uv run python -m tools.workflow.check_cstring_usage

# Hard-ban gate against ILT/thunk-name ossification in manual source: rejects ANY
# identifier that starts with thunk_/ILT_/WrapperFor_ or ends with _At<8hex> (calls via
# linker thunks; history-encoded body names). Baseline-free: zero occurrences allowed.
[private]
[group('gates')]
ilt-ossification-gate:
  uv run python -m tools.workflow.check_ilt_ossification

# Ensure every `// VTABLE:` annotation is immediately followed by its class/struct
# (not a forward declaration, comment, or blank line).
[private]
[doc('Every // VTABLE: must be immediately followed by its class/struct')]
[group('gates')]
vtable-annotation-gate:
  uv run python -m tools.workflow.check_vtable_annotations --paths src include

# Ensure no inventory DATA row or `// GLOBAL:` marker collides with a `// VTABLE:`
# address (which would make reccmp drop the vtable entity as a duplicate).
[private]
[doc('No inventory DATA row or // GLOBAL: marker may collide with a // VTABLE: address')]
[group('gates')]
vtable-collision-gate:
  uv run python -m tools.workflow.check_vtable_address_collisions --paths src include

# Ensure synthetic symbol names in source comments match symbols.csv.
[private]
[group('gates')]
synthetic-gate:
  uv run python -m tools.workflow.check_synthetic_names --paths src include

# Structural integrity of config/original_entities.csv: header row exactly at line 1, no
# duplicate headers, parseable hex addresses, no duplicate addresses, no two
# function rows claiming overlapping byte ranges. (Every consumer is a DictReader
# that silently degrades when the header is misplaced.)
[private]
[doc('symbols.csv structural integrity: header at line 1, parseable + unique addresses, no function-range overlaps')]
[group('gates')]
symbols-integrity-gate:
  uv run python -m tools.workflow.check_symbols_integrity

# Reject editor indexes, compiler output, build trees, stray logs, and large non-LFS
# binaries from the tracked tree. Complements .gitignore: ignoring a directory only stops
# the next add of that exact path, which is how 1933 clangd index files under .cache/
# survived until PR #318. Whole-tree rather than diff-scoped, because every category is at
# zero tracked hits -- a diff-scoped check would grandfather whatever slipped in earlier.
[private]
[doc('Reject tracked build/editor artifacts and stray large binaries')]
[group('gates')]
repo-hygiene-gate:
  uv run python -m tools.workflow.check_repo_hygiene

# Reject generated build inputs and retired generated source trees in a branch or
# worktree diff. `precommit` resolves the merge base and includes local changes.
[private]
[doc('Reject generated artifacts relative to a merge base')]
[group('gates')]
generated-integrity-gate *args:
  uv run python -m tools.workflow.check_generated_integrity {{args}}

# Reviewed MSVC500 library identities must be faithfully projected into the current source model.
[private]
[doc('Library-identity gate: reviewed overrides applied + ownership=library')]
[group('gates')]
library-identity-gate:
  uv run python -m tools.workflow.check_library_identity

[private]
[group('gates')]
antipattern-gate:
  uv run python -m tools.workflow.check_construction_antipatterns

# Check the decompilation annotations (// FUNCTION / // VTABLE / // GLOBAL etc.)
# for syntax errors, duplicate addresses, and stray markers.
[doc('reccmp annotation lint: marker syntax, duplicate addresses, stray markers')]
[group('gates')]
decomplint:
  (cd "{{build_dir}}" && uv run reccmp-decomplint --target "{{target}}" --warnfail)

# Shadow-stub gate: non-virtual degenerate methods that hide a real vtable
# slot -- direct calls into do-nothing bodies where the original dispatches virtually.
# Every offender is a hard error.
[private]
[group('gates')]
shadow-stub-gate:
  uv run python -m tools.workflow.check_shadow_stubs

# The binary-free gate subset (no docker/wine/original exe: excludes vtable,
# decomplint, and lint). Keep in sync with `gates`.
[doc('Source-only gate subset; no built binary needed')]
[group('gates')]
source-gates:
  just generate
  just --jobs 4 _source-gates-parallel

[private]
[parallel]
_source-gates-parallel: ui-codegen-check vtable-gate antipattern-gate marker-gate cstring-gate ilt-ossification-gate vtable-annotation-gate vtable-collision-gate synthetic-gate symbols-integrity-gate repo-hygiene-gate library-identity-gate class-size-gate noop-gate shadow-stub-gate runtime-source-policy-gate

# Cross-check modeled class sizes (ASSERT_SIZE) against the RTTI oracle's
# m_nObjectSize. Report-only; pass --strict to fail on mismatches, or
# --show-unasserted to list oracle classes with no size assert yet.
[private]
[doc('ASSERT_SIZE vs RTTI-oracle object sizes; --strict to fail on mismatch')]
[group('gates')]
class-size-check *args:
  uv run python -m tools.workflow.check_class_sizes {{args}}

[group('gates')]
format-check *paths:
  uv run python -m tools.workflow.format_cpp --check {{paths}}
