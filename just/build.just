# ---------------------------------------------------------------------------
# build — compile, lint, run (+ the lint-warning-gate regression test).
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

# Generate the build inputs (source index + linkable stubs) into <build_dir>/generated.
# Read-only over committed state: scans source markers directly (no sync step, no
# committed mutation), so "edit markers -> build" is always safe. `just build` runs it.
[doc('Generate build inputs (source index + stubs) into build-msvc500/generated')]
[group('build')]
generate:
  @for d in src/autogen src/ghidra_autogen include/ghidra_autogen; do test ! -e "$d" || { echo "stale $d exists — generated trees live in the build dir now; delete it to avoid stale-scan corruption" >&2; exit 1; }; done
  uv run python -m tools.generate --gen-dir "{{build_dir}}/generated"

# ---------------------------------------------------------------------------
# build — compile, lint, run.
# ---------------------------------------------------------------------------

# jobs=1 uses the classic serial NMake generator; any other value builds with the
# parallel JOM generator (-j jobs). VC5 has no /MP, so parallelism lives in the make
# layer; /Z7 (see CMakeLists.txt) keeps parallel cl.exe off the shared vc50.pdb.
[doc('Docker MSVC500 build into build-msvc500/ (runs vtable-gate + generate first)')]
[group('build')]
build jobs=num_cpus():
  mkdir -p "{{build_dir}}"
  uv run python -m tools.workflow.msvc_build_lock \
    --lock "{{build_dir}}/.msvc-build.lock" -- just _build-msvc500-unlocked {{jobs}}

# The public `build` target is the only caller. Keeping generation and compilation
# under one lock prevents concurrent agents in this worktree from racing on either.
[private]
_build-msvc500-unlocked jobs:
  just vtable-gate
  just generate
  docker run --rm --network none \
    -e CMAKE_FLAGS="" \
    -e CMAKE_GENERATOR="{{ if jobs == '1' { 'NMake Makefiles' } else { 'NMake Makefiles JOM' } }}" \
    -e BUILD_JOBS="{{ if jobs == '1' { '' } else { jobs } }}" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{build_dir}}":/build \
    "{{docker_image}}"
  just detect

[doc('reccmp-project detect: record the recompiled binary/PDB for comparison')]
[group('build')]
detect:
  (cd "{{build_dir}}" && uv run reccmp-project detect --what recompiled)

# Modern second compiler (clang/MinGW) used ONLY to catch errors early — never
# for reccmp. Compile-only; does not touch the MSVC build, gates, or reccmp
# config. Warning-as-error is forced here as well as defaulted in CMake so an old
# build-clang cache cannot silently retain the former OFF value.
[doc('Compile-only clang/MinGW warning-as-error check; never used for reccmp')]
[group('build')]
lint flags="":
  mkdir -p "{{lint_build_dir}}"
  uv run python -m tools.generate --gen-dir "{{lint_build_dir}}/generated" \
    --chunk-prefix lint_stubs_part --ui-annotation-kind none \
    --stub-annotation-kind none
  docker run --rm --network none \
    -e CMAKE_FLAGS="-DIMPERIALISM_LINT_WERROR=ON -DIMPERIALISM_LINT_WARNING_GATE_TEST=OFF {{flags}}" \
    -e LINT=1 \
    -v "$PWD":/imperialism \
    -v "$PWD/{{lint_build_dir}}":/build \
    "{{docker_image}}"

# Evaluate the scalar-focused clang-tidy checks on a stable sample of manually
# owned TUs. Regenerating the lint database first prevents cached/no-op lint
# builds from leaving the analysis on stale compile flags.
[doc('Run scalar-focused clang-tidy checks on representative manual source')]
[group('build')]
scalar-clang-tidy:
  #!/usr/bin/env bash
  set -euo pipefail
  just gen-compile-commands
  files=()
  for name in TScrollBarView TGreatPower TMapMaker TViewMgr NetMessage; do
    matches=$(find src/game -name "${name}.cpp")
    count=$(printf '%s' "$matches" | grep -c . || true)
    if [ "$count" -ne 1 ]; then
      echo "scalar-clang-tidy: expected exactly one src/game/**/${name}.cpp, found ${count}" >&2
      exit 1
    fi
    files+=("/imperialism/${matches}")
  done
  docker run --rm --network none --entrypoint clang-tidy \
    -v "$PWD":/imperialism \
    -v "$PWD/{{lint_build_dir}}":/build \
    "{{docker_image}}" \
    -p /build \
    --checks='-*,bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions,readability-redundant-casting' \
    --header-filter='^/imperialism/(include|src)/game/' \
    --quiet \
    "${files[@]}"

# Run the reviewed advisory profile from .clang-tidy. The default is the stable
# five-TU evaluation sample; pass a compile-database path regex to expand scope,
# e.g. `just clang-tidy-audit '^/imperialism/src/game/.*[.]cpp$'`.
[doc('Run the reviewed advisory .clang-tidy profile (optional path regex)')]
[group('build')]
clang-tidy-audit filter="/(TScrollBarView|TGreatPower|TMapMaker|TViewMgr|NetMessage)[.]cpp$":
  just gen-compile-commands
  docker run --rm --network none --entrypoint run-clang-tidy \
    -v "$PWD":/imperialism \
    -v "$PWD/{{lint_build_dir}}":/build \
    "{{docker_image}}" \
    -p /build \
    -j 0 \
    -quiet \
    -config-file=/imperialism/.clang-tidy \
    '{{filter}}'

# Assert the recomp PE has .rsrc and SDI template MENU id 128 (0x80).
[group('build')]
resource-check:
  just backdrop-resource --check
  just executable-chrome-resources --check
  uv run python -m tools.workflow.pe_resources check "{{build_dir}}/Imperialism.exe" \
    --menu-id 128 \
    --require 2:281:1033 \
    --require 14:31234:1033 \
    --require 16:1:1033
  uv run python -m tools.workflow.pe_resources direct-resource-parity \
    "$ORIGINAL_BINARY" "{{build_dir}}/Imperialism.exe"

# Generate resource-driven UI factory TUs from committed semantic Mac View IR
# plus the one evidenced Windows-only tree. Normal generation never reads the
# original binary or retail Mac files.
[group('build')]
gen-builder *args:
  uv run python -m tools.ui_codegen {{args}}

[doc('Generate resource-driven turn-event factory TUs into the build tree')]
[group('build')]
ui-codegen *args:
  uv run python -m tools.ui_codegen --gen-dir "{{build_dir}}/generated/ui" {{args}}

# Regression proof: enabling the fixture must make the real project lint gate fail.
# Restore the cache option afterward so subsequent incremental lint runs stay usable.
[doc('Prove the lint warning gate rejects an intentionally warning-producing TU')]
[group('test')]
lint-warning-gate-test:
  #!/usr/bin/env bash
  set -euo pipefail
  if just lint "-DIMPERIALISM_LINT_WARNING_GATE_TEST=ON"; then
    echo "lint warning gate unexpectedly accepted the intentional warning fixture"
    just lint "-DIMPERIALISM_LINT_WARNING_GATE_TEST=OFF"
    exit 1
  fi
  just lint "-DIMPERIALISM_LINT_WARNING_GATE_TEST=OFF"
  echo "lint warning gate regression fixture rejected as expected"
