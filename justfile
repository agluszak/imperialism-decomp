set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

# Project constants. These are not machine-specific; edit here if they ever change.
target := "IMPERIALISM"
build_dir := "build-msvc500"
docker_image := "imperialism-msvc500"
lint_build_dir := "build-clang"
lint_docker_image := "imperialism-clang-mingw"
cmake_flags := "-DCMAKE_BUILD_TYPE=RelWithDebInfo -DIMPERIALISM_LINK_MFC=ON -DIMPERIALISM_MATCH_FLAGS_CSV=/Oy,/Ob1"
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

# Transitional aliases for renamed targets (see docs/workflows.md).
alias stats-commit := stats-baseline-update
alias full-sync-build := db-resync

default:
  @just --list

# Private: fail fast (with a clear message) if the machine-specific Ghidra install
# path is missing. Ghidra recipes depend on this instead of repeating the guard.
_require-ghidra-install:
  : "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR in .env}"

# ---------------------------------------------------------------------------
# sync — regenerate derived artifacts (symbols.csv, stubs, ownership, autogen).
# The three canonical playbooks live in docs/workflows.md.
# ---------------------------------------------------------------------------

# MUTATES: Ghidra DB, config/symbols.csv, config/thunk_map.csv, src/+include/ghidra_autogen/.
# Push source names into the DB, re-export symbols/autogen, prune ILT rows, refresh the
# thunk map, normalize autogen, then gate. The DB is modified (push-names --apply), so
# `just export-project` must follow before committing — or run `just db-resync` instead.
[doc('MUTATES: Ghidra DB, symbols.csv, thunk_map.csv, ghidra_autogen/. Re-export pipeline; follow with export-project')]
[group('sync')]
sync-ghidra: _require-ghidra-install
  just push-names --apply --include-library-symbols --library-start 0x005e539c --library-end 0x00626c7d
  just prune-ilt-db-functions --apply --quiet
  uv run python -m tools.ghidra.sync_exports \
    --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
    --ghidra-project-dir "{{GHIDRA_PROJECT_DIR}}" \
    --ghidra-project-name "{{GHIDRA_PROJECT_NAME}}" \
    --ghidra-program-name "{{GHIDRA_PROGRAM_NAME}}" \
    --name-overrides "{{name_overrides}}"
  just prune-ilt-thunks
  just dump-thunk-map
  just normalize-autogen
  just symbols-anchor-gate
  just symbols-integrity-gate
  just vtable-collision-gate
  @echo "sync-ghidra done. The Ghidra DB was modified; run 'just export-project' before committing (or use 'just db-resync' for the full pipeline)."

# MUTATES: everything sync-ghidra touches + ownership/stubs + build tree + vendored .gzf.
# The one-command full resync (docs/ghidra-db-mutations.md procedure): sync-ghidra ->
# ownership/stubs -> build -> gates -> stats -> export-project. Replaces full-sync-build.
[doc('MUTATES: all sync outputs + Ghidra DB + vendored .gzf. One-command full resync incl. build/gates/stats/export')]
[group('sync')]
db-resync:
  just tooling-check
  just sync-ghidra
  just regen-stubs
  just build
  just detect
  just gates
  just stats
  just export-project

# MUTATES: config/function_ownership.csv.
# Reconcile config/function_ownership.csv with source markers (src/ + include/).
# Deletion-reconciling by default: marker_sync rows whose marker disappeared AND whose
# file/header no longer mentions the address are pruned (a stale row silently
# suppresses stub regeneration). Curated notes (e.g. mfc_runtime_macro) are never
# pruned. Pass --no-prune-missing-manual through the module directly to skip pruning.
[doc('MUTATES: function_ownership.csv. Reconcile ownership rows with source markers')]
[group('sync')]
sync-ownership:
  uv run python -m tools.workflow.sync_function_ownership \
    --target "{{target}}" \
    --ownership-csv "{{function_ownership}}"

# MUTATES: src/autogen/stubs/ (+ runs sync-ownership first, which rewrites ownership CSV).
# Regenerate linkable stubs for unowned addresses. Runs sync-ownership and the
# symbols.csv integrity check first, so "edit markers -> regen-stubs -> build" is safe.
[doc('MUTATES: src/autogen/stubs/. Regenerate stubs (runs sync-ownership + symbols-integrity-gate first)')]
[group('sync')]
regen-stubs: sync-ownership symbols-integrity-gate
  uv run python -m tools.stubgen \
    --name-overrides "{{name_overrides}}" \
    --ownership-csv "{{function_ownership}}"

# MUTATES: the target .cpp and config/function_ownership.csv.
# Promote a ghidra_autogen body into manual source.
[doc('MUTATES: target .cpp + function_ownership.csv. Promote a ghidra_autogen body into manual source')]
[group('sync')]
promote target_cpp *args:
  uv run python -m tools.workflow.promote_from_autogen \
    --target-cpp "{{target_cpp}}" \
    --ownership-csv "{{function_ownership}}" \
    {{args}}

# MUTATES: the target .cpp and config/function_ownership.csv.
[group('sync')]
promote-range target_cpp start end:
  uv run python -m tools.workflow.promote_from_autogen \
    --target-cpp "{{target_cpp}}" \
    --ownership-csv "{{function_ownership}}" \
    --range "{{start}}:{{end}}"

# MUTATES: src/ghidra_autogen/ (reference-only files).
# Normalize src/ghidra_autogen so promoted bodies read against real symbols and
# real C++ member signatures: resolve jmp-thunk/alias names, then reshape
# `__thiscall Cls::Method(Cls *this, ...)` heads into `Cls::Method(...)`.
[doc('MUTATES: src/ghidra_autogen/ (reference-only). Resolve thunk names + reshape thiscall heads')]
[group('sync')]
normalize-autogen *args:
  just _resolve-autogen-thunks {{args}}
  just _reshape-autogen-signatures {{args}}

# Rewrite Ghidra jmp-thunk / alias names in src/ghidra_autogen to the real names
# (driven by config/thunk_map.csv). Pass --check to fail without writing.
[private]
_resolve-autogen-thunks *args:
  uv run python -m tools.workflow.resolve_autogen_thunks {{args}}

# Reshape Ghidra `__thiscall Cls::Method(Cls *this, ...)` definition heads in
# src/ghidra_autogen into real C++ member definitions `Cls::Method(...)`.
[private]
_reshape-autogen-signatures *args:
  uv run python -m tools.workflow.reshape_autogen_signatures {{args}}

# MUTATES: config/symbols.csv.
# Drop incremental-link `jmp` thunk rows (linker artifacts) from config/symbols.csv.
# reccmp auto-detects unannotated jmp thunks and excludes them from the report.
[doc('MUTATES: symbols.csv. Drop ILT jmp-thunk function rows (linker artifacts)')]
[group('sync')]
prune-ilt-thunks *args:
  uv run python -m tools.workflow.prune_ilt_thunks {{args}}

# MUTATES: config/thunk_map.csv (DB itself is read-only here).
# Dump the Ghidra thunk-name -> real-name map to config/thunk_map.csv so offline
# body promotion (promote/promote-range, normalize-autogen) can resolve
# jmp-thunk/alias call names without a live Ghidra connection. Idempotent.
[doc('MUTATES: thunk_map.csv. Dump the Ghidra thunk-name -> real-name map')]
[group('sync')]
dump-thunk-map *args: _require-ghidra-install
  uv run python -m tools.ghidra.dump_thunk_map {{args}}

# ---------------------------------------------------------------------------
# build — compile, lint, run.
# ---------------------------------------------------------------------------

[doc('Docker MSVC500 build into build-msvc500/ (runs vtable-gate first)')]
[group('build')]
build:
  just vtable-gate
  mkdir -p "{{build_dir}}"
  docker run --rm --network none \
    -e CMAKE_FLAGS="{{cmake_flags}}" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{build_dir}}":/build \
    "{{docker_image}}"

[doc('reccmp-project detect: record the recompiled binary/PDB for comparison')]
[group('build')]
detect:
  (cd "{{build_dir}}" && uv run reccmp-project detect --what recompiled)

# Modern second compiler (clang/MinGW) used ONLY to catch errors early — never
# for reccmp. Compile-only; does not touch the MSVC build, gates, or reccmp
# config. Pass FLAGS=-DIMPERIALISM_LINT_WERROR=ON to fail on warnings.
[doc('Compile-only clang/MinGW error check; never used for reccmp')]
[group('build')]
lint flags="":
  mkdir -p "{{lint_build_dir}}"
  docker run --rm --network none \
    -e CMAKE_FLAGS="{{flags}}" \
    -e LINT=1 \
    -v "$PWD":/imperialism \
    -v "$PWD/{{lint_build_dir}}":/build \
    "{{docker_image}}"

# Assert the recomp PE has .rsrc and SDI template MENU id 128 (0x80).
[group('build')]
resource-check:
  uv run python -m tools.workflow.pe_resources check "{{build_dir}}/Imperialism.exe" --menu-id 128

# Run the recompiled Imperialism.exe under Wine from the retail install directory.
# ORIGINAL_BINARY in .env must point at an immutable copy of your legally
# obtained Imperialism.exe; its parent directory must contain Data/ and the
# other game assets. Build first with `just build`. Override WINEDEBUG in the
# environment for Wine tracing.
[doc('Run the recompiled exe under Wine from the retail install dir')]
[group('build')]
run *args:
  #!/usr/bin/env bash
  set -euo pipefail
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  game_dir="$(cd "$(dirname "$ORIGINAL_BINARY")" && pwd)"
  recomp="{{justfile_directory()}}/{{build_dir}}/Imperialism.exe"
  if [[ ! -f "$recomp" ]]; then
    echo "Missing $recomp — run 'just build' first." >&2
    exit 1
  fi
  if [[ ! -d "$game_dir/Data" ]]; then
    echo "Missing $game_dir/Data — set ORIGINAL_BINARY to a full game install." >&2
    exit 1
  fi
  export WINEDEBUG="${WINEDEBUG--all}"
  cd "$game_dir"
  exec wine "$recomp" "$@"

# Run the recomp under winedbg from the retail install directory. By default breaks
# on MessageBoxA, continues, prints a backtrace, and quits — useful for tracing
# startup failures (empty error boxes, InitInstance bailouts). Override the
# script: DEBUG_SCRIPT=$'break SomeSymbol\ncont\nbt\nquit\n' just debug
[doc('Run the recomp under winedbg (default script: break MessageBoxA, bt, quit)')]
[group('build')]
debug *args:
  #!/usr/bin/env bash
  set -euo pipefail
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  game_dir="$(cd "$(dirname "$ORIGINAL_BINARY")" && pwd)"
  recomp="{{justfile_directory()}}/{{build_dir}}/Imperialism.exe"
  if [[ ! -f "$recomp" ]]; then
    echo "Missing $recomp — run 'just build' first." >&2
    exit 1
  fi
  if [[ ! -d "$game_dir/Data" ]]; then
    echo "Missing $game_dir/Data — set ORIGINAL_BINARY to a full game install." >&2
    exit 1
  fi
  export WINEDEBUG="${WINEDEBUG--all}"
  cd "$game_dir"
  script="${DEBUG_SCRIPT:-$'break MessageBoxA\ncont\nbt\nquit\n'}"
  printf '%s' "$script" | winedbg "$recomp" "$@"

# Run the debugger with a short timeout. Override with DEBUG_TIMEOUT=10s.
[group('build')]
debug-timeout *args:
  #!/usr/bin/env bash
  set -euo pipefail
  export WINEDEBUG="${WINEDEBUG-err+all,+debugstr,+loaddll}"
  exec timeout --kill-after=2s "${DEBUG_TIMEOUT:-5s}" just debug "$@"

# ---------------------------------------------------------------------------
# compare — reccmp scoring, stats, session planning (read-only).
# ---------------------------------------------------------------------------

# Compare functions against the original.
#   just compare                  -> full reccmp summary (all functions)
#   just compare 0xADDR           -> verbose asm diff for one function
#   just compare 0xA 0xB 0xC ...  -> batch score table (single PDB parse)
#   just compare --file src/game/foo.cpp [more.cpp]  -> score every // FUNCTION in the file(s)
# Batch/file mode runs one `reccmp --json` parse (~4s for all ~9600 funcs) instead
# of one cold PDB parse per address.
[doc('Score vs original: no args=all, 0xADDR=asm diff, multiple addrs/--file=batch')]
[group('compare')]
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

# Score every // FUNCTION marker in src/game/<Class>.cpp (single PDB parse).
[group('compare')]
compare-class cls:
  just compare --file "src/game/{{cls}}.cpp"

# Compare vtable layouts against the original.
#   just vtable          -> all vtables
#   just vtable TSound   -> only vtables whose name contains "TSound"
#   just vtable -v        -> pass through reccmp-vtable flags (e.g. --verbose)
[doc('Compare vtable layouts vs original; optional class-name filter')]
[group('compare')]
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
[group('compare')]
datacmp *args:
  (cd "{{build_dir}}" && uv run reccmp-datacmp --target "{{target}}" {{args}})

# Compare symbol locations (functions, vtables, data) between original and recompiled.
#   just roadmap          -> full roadmap
#   just roadmap -v       -> pass through reccmp-roadmap flags
[group('compare')]
roadmap *args:
  (cd "{{build_dir}}" && uv run reccmp-roadmap --target "{{target}}" {{args}})

# Compare the stack layout of a single near-matching function.
#   just stackcmp 0xADDR
[group('compare')]
stackcmp addr *args:
  (cd "{{build_dir}}" && uv run reccmp-stackcmp --target "{{target}}" {{args}} "{{addr}}")

[group('compare')]
stats:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled

[group('compare')]
inventory:
  uv run python -m tools.reccmp.library_inventory --json-out "{{build_dir}}/library_inventory.json"

# Rank the next porting targets and write build-msvc500/next_loop.{md,json}.
# Read-only by default; pass --refresh-ignore to also rewrite reccmp-project.yml
# ignore lists (previously the default — see Hard Rule 14).
[doc('Rank next porting targets -> build-msvc500/next_loop.md; --refresh-ignore also rewrites ignore lists')]
[group('compare')]
session-loop pick='8' top='50' min_size='1' *args:
  uv run python -m tools.reccmp.session_loop --target "{{target}}" --pick "{{pick}}" --top "{{top}}" --min-size "{{min_size}}" {{args}}

# ---------------------------------------------------------------------------
# ghidra-inspect — read-only evidence from the vendored Ghidra project.
# ---------------------------------------------------------------------------

# Read-only inspect targets run through the long-lived Ghidra daemon
# (tools/ghidra/daemon.py): the first call auto-starts it and pays the one-time JVM +
# project-load cost; every later call reuses the open program and returns fast. Warm it
# eagerly with `just ghidra-daemon`, stop it with `just ghidra-daemon-stop`. Mutating
# Ghidra targets evict the daemon automatically (they need exclusive project access).

# Warm/ping the inspection daemon (auto-starts it if not already running).
[group('ghidra-inspect')]
ghidra-daemon: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client ping

# Stop the inspection daemon and release the project lock.
[group('ghidra-inspect')]
ghidra-daemon-stop:
  uv run python -m tools.ghidra.daemon_client shutdown

[group('ghidra-inspect')]
ghidra-listing *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client listing {{args}}

[group('ghidra-inspect')]
ghidra-function-slice *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client function-slice {{args}}

[group('ghidra-inspect')]
ghidra-decompile *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client decompile {{args}}

# Cross-references to/from an address. `just ghidra-xrefs [to|from|both] 0xADDR [0xADDR ...]`.
[group('ghidra-inspect')]
ghidra-xrefs *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client xrefs {{args}}

# Linear disassembly by address, ignoring Ghidra's (sometimes wrong) function
# boundaries. `just ghidra-linear-disasm 0xADDR [count]`.
[group('ghidra-inspect')]
ghidra-linear-disasm *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client linear-disasm {{args}}

# Whole-binary search for a value in disassembled instruction text or raw data
# (message-map/handler hunting). `just ghidra-search text|dword <value> [limit]`.
[group('ghidra-inspect')]
ghidra-search *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client search {{args}}

# Disassemble raw bytes with capstone, bypassing Ghidra's instruction database
# entirely (for regions Ghidra hasn't disassembled at all).
# `just ghidra-raw-disasm 0xADDR [byte_count]`.
[group('ghidra-inspect')]
ghidra-raw-disasm *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client raw-disasm {{args}}

[group('ghidra-inspect')]
ghidra-vtable-dump class vtable *args: _require-ghidra-install
  uv run python -m tools.ghidra.daemon_client vtable-dump "{{class}}" "{{vtable}}" {{args}}

[group('ghidra-inspect')]
ghidra-vtable-struct-check *args: _require-ghidra-install
  uv run python -m tools.ghidra.vtable_struct_check {{args}}

[group('ghidra-inspect')]
ghidra-datatype-audit *args: _require-ghidra-install
  uv run python -m tools.ghidra.datatype_audit {{args}}

# Decompile benchmark gate: must-keep patterns for curated Ghidra typing work.
# Pass --strict to also fail on missing should-improve patterns.
[doc('Decompile benchmark gate for curated Ghidra typing work')]
[group('ghidra-inspect')]
ghidra-decomp-check *args: _require-ghidra-install
  uv run python -m tools.ghidra.decomp_check {{args}}

# Classify functions as ecx_this (likely __thiscall) / no_ecx (likely cdecl) / empty (thunk).
# Pass addresses, or pipe addresses to --stdin (e.g. from config/symbols.csv __cdecl rows).
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

[group('ghidra-inspect')]
w32dasm-report: _require-ghidra-install
  uv run python -m tools.w32dasm.parse_alf
  uv run python -m tools.w32dasm.compare_alf_ghidra
  uv run python -m tools.w32dasm.inspect_wpj
  uv run python -m tools.w32dasm.rank_report

# ---------------------------------------------------------------------------
# ghidra-db — targets that WRITE the vendored Ghidra database.
# After any of these, `just export-project` must run before committing so the
# LFS .gzf matches the live project (ledger: docs/ghidra-db-mutations.md).
# ---------------------------------------------------------------------------

# One-time / fresh clone: recreate the live Ghidra working project from the vendored .gzf.
[group('ghidra-db')]
restore-project *args: _require-ghidra-install
  uv run python -m tools.ghidra.restore_project {{args}}

# MUTATES: vendor/ghidra/exports/*.gzf (LFS).
# Refresh the committed .gzf archive from the live project after Ghidra-side changes.
[group('ghidra-db')]
export-project *args: _require-ghidra-install
  uv run python -m tools.ghidra.export_project {{args}}

# MUTATES: Ghidra DB (with --apply).
# Push source-owned names into the Ghidra DB so the export below already carries
# them (names converge instead of churning). Source-owned addresses only; dry-run
# by default — pass --apply to write + save the DB.
[doc('MUTATES: Ghidra DB (--apply). Push source-owned names into the DB so exports converge')]
[group('ghidra-db')]
push-names *args: _require-ghidra-install
  uv run python -m tools.ghidra.push_names_to_ghidra {{args}}

# MUTATES: Ghidra DB (with --apply).
# Define real functions Ghidra never created (vtable slot targets, ILT jmp
# targets, symbols.csv rows). Dry-run by default; --apply writes + saves the DB.
# See docs/ghidra-db-mutations.md before applying.
[doc('MUTATES: Ghidra DB (--apply). Define real functions Ghidra never created')]
[group('ghidra-db')]
repair-code-gaps *args: _require-ghidra-install
  uv run python -m tools.ghidra.repair_code_gaps {{args}}

# MUTATES: Ghidra DB (with --apply).
# Remove Function entities sitting on ILT jmp thunks (they block reccmp's thunk
# auto-resolution and collapse vtable matching). The DB-side counterpart of
# prune-ilt-thunks; sync-ghidra runs it automatically before the export.
[doc('MUTATES: Ghidra DB (--apply). Remove Function entities on ILT jmp thunks (runs inside sync-ghidra)')]
[group('ghidra-db')]
prune-ilt-db-functions *args: _require-ghidra-install
  uv run python -m tools.ghidra.prune_ilt_db_functions {{args}}

# MUTATES: Ghidra DB (with --apply).
# One-time Ghidra cleanup: commit Ghidra's `in_stack_*` stack args as real function
# parameters in the DB, so after `just sync-ghidra` + autogen regen no `in_stack_*`
# reads remain anywhere. Read-only by default; pass --apply to write (then sync-ghidra).
[doc('MUTATES: Ghidra DB (--apply). Commit in_stack_* args as real parameters')]
[group('ghidra-db')]
fix-in-stack-params *args: _require-ghidra-install
  uv run python -m tools.ghidra.fix_in_stack_params {{args}}

# MUTATES: Ghidra DB (with --apply).
[group('ghidra-db')]
apply-source-datatypes *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_source_datatypes {{args}}

# MUTATES: Ghidra DB (with --apply).
[group('ghidra-db')]
apply-mfc-datatypes *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_mfc_datatypes {{args}}

# MUTATES: Ghidra DB (with --apply).
[group('ghidra-db')]
apply-mfc-rtti *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_mfc_rtti {{args}}

# MUTATES: Ghidra DB (with --apply).
[group('ghidra-db')]
apply-fidb *args: _require-ghidra-install
  uv run python -m tools.ghidra.apply_fidb {{args}}

# MUTATES: Ghidra DB (with --apply).
# Name + expand a class's <Class>Vtbl struct from its recovered header slot map so
# virtual dispatches through that class decompile as obj->vftable->Method(...).
[doc('MUTATES: Ghidra DB (--apply). Name + expand the <Class>Vtbl struct slots')]
[group('ghidra-db')]
name-vtable-slots *args: _require-ghidra-install
  uv run python -m tools.ghidra.name_vtable_slots {{args}}

# MUTATES: Ghidra DB (with --apply).
[group('ghidra-db')]
gen-vtable-slot-overrides *args: _require-ghidra-install
  uv run python -m tools.ghidra.gen_vtable_slot_overrides {{args}}

# MUTATES: Ghidra DB (with --apply).
[group('ghidra-db')]
propagate-virtual-method-names *args: _require-ghidra-install
  uv run python -m tools.ghidra.propagate_virtual_method_names {{args}}

# MUTATES: Ghidra DB.
# Import source annotations into the Ghidra DB via reccmp-ghidra-import.
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

# Convenience wrapper: apply-source-datatypes for the TEventHandler/TView pair.
[private]
apply-tview-datatype: _require-ghidra-install
  uv run python -m tools.ghidra.apply_source_datatypes --classes TEventHandler,TView

# ---------------------------------------------------------------------------
# gates — mechanical checks (all read-only).
# ---------------------------------------------------------------------------

# The full pre-commit sequence in one command: build (includes vtable-gate),
# all gates, then stats vs baseline. Review the stats delta, then run
# `just stats-baseline-update` if accepted and commit the baseline with the change.
[doc('Pre-commit in one command: build + gates + stats (then review, stats-baseline-update, commit)')]
[group('gates')]
precommit:
  just build
  just gates
  just test
  just stats

# Run all mechanical source-policy gates (the pre-commit check).
# Run `just format-check <touched paths>` separately on files you edited; the tree
# is not fully clang-formatted, so format-check is per-path, not whole-tree.
[doc('Run all mechanical source-policy gates (the pre-commit check)')]
[group('gates')]
gates:
  just vtable
  just datacmp
  just vtable-gate
  just antipattern-gate
  just tgreatpower-gate
  just marker-gate
  just vtable-annotation-gate
  just vtable-collision-gate
  just field-layout-gate
  just synthetic-gate
  just symbols-integrity-gate
  just global-location-gate
  just manual-cruntimeclass-gate
  just decomplint

[group('gates')]
tooling-check:
  uv run python -m tools.workflow.check_tooling_surface

# Run the Python tooling unit tests (tests/tools).
[group('gates')]
test:
  uv run python -m unittest discover -s tests/tools

# Raw-vtable source gate (Hard Rule 13); also runs as the first step of `just build`.
[group('gates')]
vtable-gate:
  uv run python -m tools.workflow.check_no_raw_vtable_calls --baseline "{{vtable_gate_baseline}}"

[group('gates')]
marker-gate:
  uv run python -m tools.workflow.check_marker_hygiene --paths src include

# Ensure every `// VTABLE:` annotation is immediately followed by its class/struct
# (not a forward declaration, comment, or blank line).
[doc('Every // VTABLE: must be immediately followed by its class/struct')]
[group('gates')]
vtable-annotation-gate:
  uv run python -m tools.workflow.check_vtable_annotations --paths src include

# Ensure no symbols.csv DATA row or `// GLOBAL:` marker collides with a `// VTABLE:`
# address (which would make reccmp drop the vtable entity as a duplicate).
[doc('No symbols.csv DATA row or // GLOBAL: marker may collide with a // VTABLE: address')]
[group('gates')]
vtable-collision-gate:
  uv run python -m tools.workflow.check_vtable_address_collisions --paths src include

# Ensure synthetic symbol names in source comments match symbols.csv.
[group('gates')]
synthetic-gate:
  uv run python -m tools.workflow.check_synthetic_names --paths src include

# Structural integrity of config/symbols.csv: header row exactly at line 1, no
# duplicate headers, parseable hex addresses, no duplicate addresses. (Every consumer
# is a DictReader that silently degrades when the header is misplaced.)
[doc('symbols.csv structural integrity: header at line 1, parseable + unique addresses')]
[group('gates')]
symbols-integrity-gate:
  uv run python -m tools.workflow.check_symbols_integrity

# Sanity-check a few reccmp-critical symbols.csv rows after Ghidra export.
[group('gates')]
symbols-anchor-gate:
  uv run python -m tools.workflow.check_symbols_anchors

[group('gates')]
antipattern-gate:
  uv run python -m tools.workflow.check_construction_antipatterns --baseline "{{construction_gate_baseline}}"

[group('gates')]
tgreatpower-gate:
  uv run python -m tools.workflow.check_tgreatpower_hygiene --baseline "{{tgreatpower_gate_baseline}}"

[group('gates')]
field-layout-gate *args:
  uv run python -m tools.workflow.check_field_layout_annotations {{args}}

# Ensure // GLOBAL: markers live in global_data_tables.cpp and declarations in global_data_tables.h
[group('gates')]
global-location-gate:
  uv run python -m tools.workflow.check_global_location --source-dir src --include-dir include

# Ensure manual CRuntimeClass definitions are replaced with MFC macros
[group('gates')]
manual-cruntimeclass-gate:
  uv run python -m tools.workflow.check_manual_cruntimeclass --source-dir src

# Check the decompilation annotations (// FUNCTION / // VTABLE / // GLOBAL etc.)
# for syntax errors, duplicate addresses, and stray markers.
[doc('reccmp annotation lint: marker syntax, duplicate addresses, stray markers')]
[group('gates')]
decomplint:
  (cd "{{build_dir}}" && uv run reccmp-decomplint --target "{{target}}")

[doc('Audit Hard-Rule-9 typedef-cast externs for cross-file signature drift (report-only)')]
[group('gates')]
typedef-cast-audit *args:
  uv run python -m tools.workflow.check_typedef_cast_drift {{args}}

[doc('Mine reccmp asm diffs for orig-address<->recomp-symbol global pairs (read-only report)')]
[group('compare')]
global-xref-oracle *args:
  uv run python -m tools.reccmp.global_xref_oracle {{args}}

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

[group('gates')]
format-check *paths:
  uv run python -m tools.workflow.format_cpp --check {{paths}}

# ---------------------------------------------------------------------------
# baseline-update — targets that REWRITE committed baselines/configs.
# ---------------------------------------------------------------------------

# MUTATES: config/reccmp_progress_baseline.json. (Was `stats-commit`.)
[group('baseline-update')]
stats-baseline-update:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled --commit-baseline

# MUTATES: config/vtable_gate_baseline.csv.
[group('baseline-update')]
vtable-gate-update:
  uv run python -m tools.workflow.check_no_raw_vtable_calls --baseline "{{vtable_gate_baseline}}" --write-baseline

# MUTATES: config/construction_gate_baseline.csv.
[group('baseline-update')]
antipattern-gate-update:
  uv run python -m tools.workflow.check_construction_antipatterns --baseline "{{construction_gate_baseline}}" --write-baseline

# MUTATES: config/tgreatpower_gate_baseline.csv.
[group('baseline-update')]
tgreatpower-gate-update:
  uv run python -m tools.workflow.check_tgreatpower_hygiene --baseline "{{tgreatpower_gate_baseline}}" --write-baseline

# MUTATES: reccmp-project.yml ignore lists (Hard Rule 14).
[group('baseline-update')]
generate-ignores:
  uv run python -m tools.reccmp.generate_ignore_functions --target "{{target}}" --apply

# ---------------------------------------------------------------------------
# rewrite — targets that rewrite source/config from symbols or policy.
# ---------------------------------------------------------------------------

# MUTATES: source files under src/game + include/game.
[group('rewrite')]
annotate-globals:
  uv run python -m tools.workflow.annotate_globals_from_symbols --paths src/game include/game --write

# MUTATES: headers under include/game.
[group('rewrite')]
annotate-vtables:
  uv run python -m tools.workflow.annotate_vtables_from_symbols --paths include/game --write

# MUTATES: source files under src/game + include/game.
[group('rewrite')]
annotate-strings:
  uv run python -m tools.workflow.annotate_strings_from_symbols --paths src/game include/game --write

# MUTATES: reccmp markers in src/ + include/.
[group('rewrite')]
normalize-markers:
  uv run python -m tools.workflow.normalize_reccmp_markers --paths src include --write

# MUTATES: config/symbols.csv + `// SYNTHETIC:` comments (with --apply).
# Canonicalize scalar-deleting-destructor spellings to the MSVC500-mangled form.
# Pass --dry-run to preview. `just synthetic-gate` is the mechanical check.
[doc('MUTATES: symbols.csv + // SYNTHETIC: comments. Canonicalize scalar-dtor spellings')]
[group('rewrite')]
correct-scalar-dtors *args:
  uv run python -m tools.workflow.correct_scalar_dtors {{args}}

# MUTATES: config/symbols.csv + stub manifest (with --write).
# Dry-run-first vtable repair planner. Applies only deterministic fixes with --write:
# manifest slot promotion, scalar-dtor spelling cleanup, and safe ILT thunk pruning.
[doc('MUTATES (--write): symbols.csv + stub manifest. Dry-run-first vtable repair planner')]
[group('rewrite')]
vtable-autofix *args:
  uv run python -m tools.workflow.vtable_autofix {{args}}

# MUTATES: source + config/function_ownership.csv (with --apply).
[group('rewrite')]
mfc-runtime-macros *args:
  uv run python -m tools.workflow.mfc_runtime_macros {{args}}

# MUTATES: config (library region rows).
[group('rewrite')]
apply-msvc500-library-region *args:
  uv run python -m tools.mfc.apply_msvc500_library_region {{args}}

# MUTATES: config/recovered_fields (generated from recovered headers).
[group('rewrite')]
gen-recovered-fields-from-headers *args:
  uv run python -m tools.ghidra.gen_recovered_fields_from_headers {{args}}

# MUTATES: the given paths (clang-format).
[group('rewrite')]
format *paths:
  uv run python -m tools.workflow.format_cpp {{paths}}

# ---------------------------------------------------------------------------
# recovery — class/slice discovery and Mac evidence.
# ---------------------------------------------------------------------------

[group('recovery')]
class-discovery classes='':
  discovery_classes="{{class_discovery_classes}}"; \
  if [[ -n "{{classes}}" ]]; then discovery_classes="{{classes}}"; fi; \
  uv run python -m tools.workflow.class_discovery \
    --classes "$discovery_classes" \
    --ownership-csv "{{function_ownership}}"

[group('recovery')]
slice-discovery class address:
  uv run python -m tools.workflow.slice_discovery "{{class}}" --address "{{address}}"

# MUTATES: vendor/macos_codewarrior/evidence (regenerates the vendored Mac evidence).
[doc('MUTATES: vendor/macos_codewarrior/evidence. Regenerate vendored Mac evidence from the dump')]
[group('recovery')]
mac-evidence:
  : "${MACOS_IMPERIALISM_DUMP:?Set MACOS_IMPERIALISM_DUMP in .env (extracted macOS dump dir); only needed to regenerate the vendored evidence}"
  uv run python -m tools.workflow.macos_evidence \
    --dump-dir "{{macos_dump}}" \
    --workspace "{{macos_workspace}}"

[group('recovery')]
mac-evidence-check:
  uv run python -m tools.workflow.macos_evidence \
    --workspace "{{macos_workspace}}" \
    --check

# ---------------------------------------------------------------------------
# setup — one-time bootstrap / image builds.
# ---------------------------------------------------------------------------

[group('setup')]
docker-build:
  docker build --network host -t "{{docker_image}}" -f docker/msvc500/Dockerfile docker/msvc500

# Build the lint image (clang + MinGW-w64 i686). One-time / on Dockerfile change.
[group('setup')]
build-lint-image:
  docker build --network host -t "{{lint_docker_image}}" -f docker/clang-mingw/Dockerfile docker/clang-mingw

[group('setup')]
bootstrap-reccmp:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run reccmp-project create --originals "$ORIGINAL_BINARY" --scm

[group('setup')]
vendor-msvc500-headers *args:
  uv run python -m tools.workflow.vendor_msvc500_headers {{args}}

# Mirror the DirectX 5 SDK inc/lib (reference copy of C:\dxsdk in the build image).
[group('setup')]
vendor-directx-headers *args:
  uv run python -m tools.workflow.vendor_directx_headers {{args}}

# MUTATES: vendor/macos_codewarrior/ghidra (imports the Mac PEF into its own project).
[group('setup')]
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
