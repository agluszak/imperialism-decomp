set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

# Project constants. These are not machine-specific; edit here if they ever change.
target := "IMPERIALISM"
build_dir := "build-msvc500"
docker_image := "imperialism-msvc500"
lint_build_dir := "build-clang"
lint_docker_image := "imperialism-clang-mingw"
cmake_flags := "-DCMAKE_BUILD_TYPE=RelWithDebInfo -DIMPERIALISM_LINK_MFC=ON -DIMPERIALISM_MATCH_FLAGS_CSV=/Oy-,/Ob1"
name_overrides := "config/function_name_overrides.csv"
function_ownership := "config/function_ownership.csv"
vtable_gate_baseline := "config/vtable_gate_baseline.csv"
construction_gate_baseline := "config/construction_gate_baseline.csv"
tgreatpower_gate_baseline := "config/tgreatpower_gate_baseline.csv"
class_discovery_classes := "TGreatPower,TAutoGreatPower"

# The Ghidra project is vendored in-repo; only GHIDRA_INSTALL_DIR is machine-specific (.env).
# Exported so every recipe (and the pyghidra tools) use the vendored project authoritatively.
# Do NOT set GHIDRA_PROJECT_DIR/NAME/PROGRAM_NAME in .env — these exports are the source of truth.
export GHIDRA_PROGRAM_NAME := "Imperialism.exe"
export GHIDRA_PROJECT_DIR := justfile_directory() / "vendor/ghidra"
export GHIDRA_PROJECT_NAME := "imperialism-decomp"

# External, machine-specific: the extracted macOS CodeWarrior dump dir. Only needed to
# REGENERATE Mac evidence (already vendored under vendor/macos_codewarrior/evidence).
macos_dump := env_var_or_default("MACOS_IMPERIALISM_DUMP", "")
macos_workspace := env_var_or_default("MACOS_CODEWARRIOR_WORKSPACE", justfile_directory() / "vendor/macos_codewarrior")
macos_pef_datafork := env_var_or_default("MACOS_PEF_DATAFORK", macos_dump + "/Imperialism.datafork")

default:
  @just --list

tooling-check:
  uv run python -m tools.workflow.check_tooling_surface

# Private: fail fast (with a clear message) if the machine-specific Ghidra install
# path is missing. Ghidra recipes depend on this instead of repeating the guard.
_require-ghidra-install:
  : "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR in .env}"

# One-time / fresh clone: recreate the live Ghidra working project from the vendored .gzf.
restore-project *args: _require-ghidra-install
  uv run python -m tools.ghidra.restore_project {{args}}

# Refresh the committed .gzf archive (LFS) from the live project after Ghidra-side changes.
export-project *args: _require-ghidra-install
  uv run python -m tools.ghidra.export_project {{args}}

sync-ghidra: _require-ghidra-install
  uv run python -m tools.ghidra.sync_exports \
    --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
    --ghidra-project-dir "{{GHIDRA_PROJECT_DIR}}" \
    --ghidra-project-name "{{GHIDRA_PROJECT_NAME}}" \
    --ghidra-program-name "{{GHIDRA_PROGRAM_NAME}}" \
    --name-overrides "{{name_overrides}}"
  just prune-ilt-thunks

# Drop incremental-link `jmp` thunk rows (linker artifacts) from config/symbols.csv.
# reccmp auto-detects unannotated jmp thunks and excludes them from the report.
prune-ilt-thunks *args:
  uv run python -m tools.workflow.prune_ilt_thunks {{args}}

# Canonicalize scalar-deleting-destructor spellings in config/symbols.csv and
# `// SYNTHETIC:` source comments to the MSVC500-mangled form. Pass --dry-run
# to preview. `just synthetic-gate` is the mechanical check that the names agree.
correct-scalar-dtors *args:
  uv run python -m tools.workflow.correct_scalar_dtors {{args}}

import-ghidra *args: _require-ghidra-install
  file_in_project="{{GHIDRA_PROGRAM_NAME}}"; \
  [[ "$file_in_project" == /* ]] || file_in_project="/$file_in_project"; \
  (cd "{{build_dir}}" && GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" uv run reccmp-ghidra-import \
    --target "{{target}}" \
    --local-project-name "{{GHIDRA_PROJECT_NAME}}" \
    --local-project-dir "{{GHIDRA_PROJECT_DIR}}" \
    --file "$file_in_project" \
    {{args}})

ghidra-listing *args: _require-ghidra-install
  uv run python -m tools.ghidra.listing_one {{args}}

ghidra-function-slice *args: _require-ghidra-install
  uv run python -m tools.ghidra.function_slice {{args}}

# Classify functions as ecx_this (likely __thiscall) / no_ecx (likely cdecl) / empty (thunk).
# Pass addresses, or pipe addresses to --stdin (e.g. from config/symbols.csv __cdecl rows).
scan-cdecl-thiscall *args: _require-ghidra-install
  uv run python -m tools.ghidra.scan_cdecl_thiscall {{args}}

ghidra-vtable-dump class vtable *args: _require-ghidra-install
  uv run python -m tools.ghidra.vtable_dump "{{class}}" "{{vtable}}" {{args}}

# Scaffold a class+vtable port: resolve slots via Ghidra, then emit a reviewable
# header/.cpp/CSV scaffold (dry-run by default; pass --write to apply).
#   just bootstrap-class TUnitOrderState 0x0066ee18
#   just bootstrap-class TUnitOrderState 0x0066ee18 TObject 0x00653868  # override
# The base is auto-detected from the MFC CRuntimeClass chain (immediate base +
# CObject-vs-TObject root + its vtable for the inherited-vs-override diff); pass
# base name+vtable explicitly only to override the RTTI-recovered edge.
bootstrap-class class vtable base='' base_vtable='' *args: _require-ghidra-install
  #!/usr/bin/env bash
  set -euo pipefail
  slots_json="$(mktemp)"
  trap 'rm -f "$slots_json"' EXIT
  specs=("{{class}}={{vtable}}")
  base_arg=()
  if [[ -n "{{base}}" && -n "{{base_vtable}}" ]]; then
    specs+=("{{base}}={{base_vtable}}")
    base_arg=(--base "{{base}}")
  fi
  uv run python -m tools.ghidra.vtable_slots --decompile "${specs[@]}" > "$slots_json"
  uv run python -m tools.workflow.bootstrap_class \
    --class "{{class}}" "${base_arg[@]}" --slots-json "$slots_json" {{args}}

apply-source-datatypes *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_source_datatypes {{args}}

apply-tview-datatype: _require-ghidra-install
  uv run python -m tools.ghidra.apply_source_datatypes --classes CString,TEventHandler,TView

w32dasm-report: _require-ghidra-install
  uv run python -m tools.w32dasm.parse_alf
  uv run python -m tools.w32dasm.compare_alf_ghidra
  uv run python -m tools.w32dasm.inspect_wpj
  uv run python -m tools.w32dasm.rank_report

regen-stubs:
  uv run python -m tools.stubgen \
    --name-overrides "{{name_overrides}}" \
    --ownership-csv "{{function_ownership}}"

sync-ownership:
  uv run python -m tools.workflow.sync_function_ownership \
    --target "{{target}}" \
    --ownership-csv "{{function_ownership}}"

annotate-globals:
  uv run python -m tools.workflow.annotate_globals_from_symbols --paths src/game include/game --write

annotate-vtables:
  uv run python -m tools.workflow.annotate_vtables_from_symbols --paths include/game --write

annotate-strings:
  uv run python -m tools.workflow.annotate_strings_from_symbols --paths src/game include/game --write

gen-vcall-facades:
  uv run python -m tools.workflow.generate_vcall_facades

vtable-gate:
  uv run python -m tools.workflow.check_no_raw_vtable_calls --baseline "{{vtable_gate_baseline}}"

vtable-gate-update:
  uv run python -m tools.workflow.check_no_raw_vtable_calls --baseline "{{vtable_gate_baseline}}" --write-baseline

normalize-markers:
  uv run python -m tools.workflow.normalize_reccmp_markers --paths src include --write

marker-gate:
  uv run python -m tools.workflow.check_marker_hygiene --paths src include

# Ensure every `// VTABLE:` annotation is immediately followed by its class/struct
# (not a forward declaration, comment, or blank line).
vtable-annotation-gate:
  uv run python -m tools.workflow.check_vtable_annotations --paths src include

# Ensure no symbols.csv DATA row or `// GLOBAL:` marker collides with a `// VTABLE:`
# address (which would make reccmp drop the vtable entity as a duplicate).
vtable-collision-gate:
  uv run python -m tools.workflow.check_vtable_address_collisions --paths src include

# Ensure synthetic symbol names in source comments match symbols.csv.
synthetic-gate:
  uv run python -m tools.workflow.check_synthetic_names --paths src include

# Report `// VTABLE:` annotations that reccmp does not turn into a matched vtable
# (needs a built binary + reccmp DB, so it is not part of `just gates`). Pass --strict
# to also fail on annotations whose recompiled vtable is missing.
vtable-coverage *args:
  uv run python -m tools.workflow.check_vtable_coverage --project-dir "{{build_dir}}" {{args}}

antipattern-gate:
  uv run python -m tools.workflow.check_construction_antipatterns --baseline "{{construction_gate_baseline}}"

antipattern-gate-update:
  uv run python -m tools.workflow.check_construction_antipatterns --baseline "{{construction_gate_baseline}}" --write-baseline

tgreatpower-gate:
  uv run python -m tools.workflow.check_tgreatpower_hygiene --baseline "{{tgreatpower_gate_baseline}}"

tgreatpower-gate-update:
  uv run python -m tools.workflow.check_tgreatpower_hygiene --baseline "{{tgreatpower_gate_baseline}}" --write-baseline

# Run all mechanical source-policy gates (the pre-commit check).
# Run `just format-check <touched paths>` separately on files you edited; the tree
# is not fully clang-formatted, so format-check is per-path, not whole-tree.
gates:
  just vtable-gate
  just antipattern-gate
  just tgreatpower-gate
  just marker-gate
  just vtable-annotation-gate
  just vtable-collision-gate
  just synthetic-gate
  just decomplint

# Check the decompilation annotations (// FUNCTION / // VTABLE / // GLOBAL etc.)
# for syntax errors, duplicate addresses, and stray markers.
decomplint:
  (cd "{{build_dir}}" && uv run reccmp-decomplint --target "{{target}}")

docker-build:
  docker build --network host -t "{{docker_image}}" -f docker/msvc500/Dockerfile docker/msvc500

# Build the lint image (clang + MinGW-w64 i686). One-time / on Dockerfile change.
build-lint-image:
  docker build --network host -t "{{lint_docker_image}}" -f docker/clang-mingw/Dockerfile docker/clang-mingw

# Modern second compiler (clang/MinGW) used ONLY to catch errors early — never
# for reccmp. Compile-only; does not touch the MSVC build, gates, or reccmp
# config. Pass FLAGS=-DIMPERIALISM_LINT_WERROR=ON to fail on warnings.
lint flags="":
  mkdir -p "{{lint_build_dir}}"
  docker run --rm --network none \
    -e CMAKE_FLAGS="{{flags}}" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{lint_build_dir}}":/build \
    "{{lint_docker_image}}"

build:
  just gen-vcall-facades
  just vtable-gate
  mkdir -p "{{build_dir}}"
  docker run --rm --network none \
    -e CMAKE_FLAGS="{{cmake_flags}}" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{build_dir}}":/build \
    "{{docker_image}}"

detect:
  (cd "{{build_dir}}" && uv run reccmp-project detect --what recompiled)

# Compare functions against the original.
#   just compare                  -> full reccmp summary (all functions)
#   just compare 0xADDR           -> verbose asm diff for one function
#   just compare 0xA 0xB 0xC ...  -> batch score table (single PDB parse)
#   just compare --file src/game/foo.cpp [more.cpp]  -> score every // FUNCTION in the file(s)
# Batch/file mode runs one `reccmp --json` parse (~4s for all ~9600 funcs) instead
# of one cold PDB parse per address.
compare *args:
  #!/usr/bin/env bash
  set -euo pipefail
  args=({{args}})
  if [[ ${#args[@]} -eq 0 ]]; then
    (cd "{{build_dir}}" && uv run reccmp-reccmp --target "{{target}}")
  elif [[ ${#args[@]} -eq 1 && "${args[0]}" != "--file" ]]; then
    (cd "{{build_dir}}" && uv run reccmp-reccmp --target "{{target}}" --verbose "${args[0]}")
  else
    uv run python -m tools.reccmp.compare_batch --target "{{target}}" --build-dir "{{build_dir}}" {{args}}
  fi

# Compare vtable layouts against the original.
#   just vtable          -> all vtables
#   just vtable TSound   -> only vtables whose name contains "TSound"
#   just vtable -v        -> pass through reccmp-vtable flags (e.g. --verbose)
vtable *args:
  #!/usr/bin/env bash
  set -euo pipefail
  args=({{args}})
  extra=()
  if [[ ${#args[@]} -gt 0 && "${args[0]}" != -* ]]; then
    extra=(--filter "${args[0]}")
    args=("${args[@]:1}")
  fi
  (cd "{{build_dir}}" && uv run reccmp-vtable --target "{{target}}" "${extra[@]}" "${args[@]}")

# Compare global data values against the original.
#   just datacmp          -> all globals (only ones with a problem)
#   just datacmp -a       -> include matching globals; pass through reccmp-datacmp flags
datacmp *args:
  (cd "{{build_dir}}" && uv run reccmp-datacmp --target "{{target}}" {{args}})

# Compare symbol locations (functions, vtables, data) between original and recompiled.
#   just roadmap          -> full roadmap
#   just roadmap -v       -> pass through reccmp-roadmap flags
roadmap *args:
  (cd "{{build_dir}}" && uv run reccmp-roadmap --target "{{target}}" {{args}})

# Compare the stack layout of a single near-matching function.
#   just stackcmp 0xADDR
stackcmp addr *args:
  (cd "{{build_dir}}" && uv run reccmp-stackcmp --target "{{target}}" {{args}} "{{addr}}")

stats:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled

stats-commit:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled --commit-baseline

inventory:
  uv run python -m tools.reccmp.library_inventory --json-out "{{build_dir}}/library_inventory.json"

generate-ignores:
  uv run python -m tools.reccmp.generate_ignore_functions --target "{{target}}" --apply

session-loop pick='8' top='50' min_size='1':
  uv run python -m tools.reccmp.session_loop --target "{{target}}" --pick "{{pick}}" --top "{{top}}" --min-size "{{min_size}}"

class-discovery classes='':
  discovery_classes="{{class_discovery_classes}}"; \
  if [[ -n "{{classes}}" ]]; then discovery_classes="{{classes}}"; fi; \
  uv run python -m tools.workflow.class_discovery \
    --classes "$discovery_classes" \
    --ownership-csv "{{function_ownership}}"

slice-discovery class address:
  uv run python -m tools.workflow.slice_discovery "{{class}}" --address "{{address}}"

mac-evidence:
  : "${MACOS_IMPERIALISM_DUMP:?Set MACOS_IMPERIALISM_DUMP in .env (extracted macOS dump dir); only needed to regenerate the vendored evidence}"
  uv run python -m tools.workflow.macos_evidence \
    --dump-dir "{{macos_dump}}" \
    --workspace "{{macos_workspace}}"

mac-evidence-check:
  uv run python -m tools.workflow.macos_evidence \
    --workspace "{{macos_workspace}}" \
    --check

import-macos-pef: _require-ghidra-install
  : "${MACOS_IMPERIALISM_DUMP:?Set MACOS_IMPERIALISM_DUMP in .env (extracted macOS dump dir holding Imperialism.datafork)}"
  mkdir -p "{{macos_workspace}}/ghidra"
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "{{macos_workspace}}/ghidra" imperialism-macos \
    -import "{{macos_pef_datafork}}" \
    -overwrite \
    -processor PowerPC:BE:32:default \
    -cspec macosx \
    -postScript PEF_script.java \
    -postScript FindFunctionsUsingTOCinPEFScript.java

bootstrap-reccmp:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run reccmp-project create --originals "$ORIGINAL_BINARY" --scm

promote target_cpp *args:
  uv run python -m tools.workflow.promote_from_autogen \
    --target-cpp "{{target_cpp}}" \
    --ownership-csv "{{function_ownership}}" \
    {{args}}

promote-range target_cpp start end:
  uv run python -m tools.workflow.promote_from_autogen \
    --target-cpp "{{target_cpp}}" \
    --ownership-csv "{{function_ownership}}" \
    --range "{{start}}:{{end}}"

full-sync-build:
  just tooling-check
  just sync-ghidra
  just sync-ownership
  just regen-stubs
  just build
  just detect
  just stats

format *paths:
  uv run python -m tools.workflow.format_cpp {{paths}}

format-check *paths:
  uv run python -m tools.workflow.format_cpp --check {{paths}}

class-owner-probe address *args: _require-ghidra-install
  uv run python -m tools.ghidra.class_owner_probe "{{address}}" {{args}}
