set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

# Project constants. These are not machine-specific; edit here if they ever change.
target := "IMPERIALISM"
build_dir := "build-msvc500"
runtime_test_build_dir := "build-runtime-tests"
docker_image := "imperialism-msvc500"
lint_build_dir := "build-clang"
cmake_flags := "-DCMAKE_BUILD_TYPE=RelWithDebInfo -DIMPERIALISM_LINK_MFC=ON -DIMPERIALISM_MATCH_FLAGS_CSV=/Oy,/Ob1"
vtable_gate_baseline := "config/baselines/vtable_gate_baseline.csv"
construction_gate_baseline := "config/baselines/construction_gate_baseline.csv"
tgreatpower_gate_baseline := "config/baselines/tgreatpower_gate_baseline.csv"
class_discovery_classes := "TGreatPower,TAutoGreatPower"

# The Ghidra project is vendored in-repo; only GHIDRA_INSTALL_DIR is machine-specific (.env).
# Exported so every recipe (and the pyghidra tools) use the vendored project authoritatively.
# Do NOT set GHIDRA_PROJECT_NAME/PROGRAM_NAME in .env — these exports are the source of truth.
# GHIDRA_PROJECT_DIR may be overridden in .env for one case only: a git worktree under a
# dot-directory (e.g. .claude/worktrees/...), whose path Ghidra's ProjectLocator rejects
# ("Path element starting with '.' is not permitted"). Point it at any dot-free directory
# and `just restore-project` recreates the live project there from the vendored .gzf.
export GHIDRA_PROGRAM_NAME := "Imperialism.exe"
export GHIDRA_PROJECT_DIR := env_var_or_default("GHIDRA_PROJECT_DIR", justfile_directory() / "vendor/ghidra")
export GHIDRA_PROJECT_NAME := "imperialism-decomp"

# External, machine-specific: the extracted macOS CodeWarrior dump dir. Only needed to
# REGENERATE Mac evidence (already vendored under vendor/macos_codewarrior/evidence).
macos_dump := env_var_or_default("MACOS_IMPERIALISM_DUMP", "")
macos_workspace := env_var_or_default("MACOS_CODEWARRIOR_WORKSPACE", justfile_directory() / "vendor/macos_codewarrior")

# Transitional aliases for renamed targets (see docs/workflows.md).

default:
  @just --list

# ---------------------------------------------------------------------------
# agent workflow — the only documented entrypoint for porting tasks.
# ---------------------------------------------------------------------------

# Investigate + claim-check target(s) and write build-msvc500/agent-task.json:
# verifies worktree/base freshness, refuses already-implemented targets, then runs
# tooling-check, func-status, ghidra-portprep, the initial compare, and
# library-identify for library-shaped addresses. `just agent-start port 0xADDR...`.
[doc('Start a porting task: investigate, claim-check, write the task receipt')]
[group('agent')]
agent-start mode +addrs:
  uv run python -m tools.workflow.agent_task start {{mode}} {{addrs}}

# Diff-aware verification: derives the right steps from the actual git diff
# (marker changes always regenerate build inputs; hand-edited generated files -> hard error),
# then format-check on touched C++, build, detect, batch compare + triage of every
# touched address, gates, tests, stats. Reruns are cheap — fix forward and rerun.
[doc('Verify the current diff: regen/format/build/compare/triage/gates/tests/stats')]
[group('agent')]
agent-check *args:
  uv run python -m tools.workflow.agent_task check {{args}}

[doc('Render the task receipt + diff into a PR-ready summary (CI still recomputes)')]
[group('agent')]
agent-finish *args:
  uv run python -m tools.workflow.agent_task finish {{args}}

# Select the 5-10 most relevant active rules from config/agent_rules.yml for a
# target (uses the agent-task receipt's portprep dossier) or the current diff.
[doc('Relevant active rules for a target or the current diff')]
[group('agent')]
advice *args:
  uv run python -m tools.workflow.advice {{args}}

[doc('Release this task: delete the claim refs for the receipt targets')]
[group('agent')]
agent-release *args:
  uv run python -m tools.workflow.agent_task release {{args}}

# Private: fail fast (with a clear message) if the machine-specific Ghidra install
# path is missing. Ghidra recipes depend on this instead of repeating the guard.
_require-ghidra-install:
  : "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR in .env}"

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

# Generate the build inputs (source index + linkable stubs) into <build_dir>/generated.
# Read-only over committed state: scans source markers directly (no sync step, no
# committed mutation), so "edit markers -> build" is always safe. `just build` runs it.
[doc('Generate build inputs (source index + stubs) into build-msvc500/generated')]
[group('build')]
generate:
  @for d in src/autogen src/ghidra_autogen include/ghidra_autogen; do test ! -e "$d" || { echo "stale $d exists — generated trees live in the build dir now; delete it to avoid stale-scan corruption" >&2; exit 1; }; done
  uv run python -m tools.generate --gen-dir "{{build_dir}}/generated"

# MUTATES: config/original_entities.csv.
# Drop incremental-link `jmp` thunk rows (linker artifacts) from config/original_entities.csv.
# reccmp auto-detects unannotated jmp thunks and excludes them from the report.
[private]
[doc('MUTATES: original_entities.csv. Drop ILT jmp-thunk function rows (linker artifacts)')]
[group('sync')]
prune-ilt-thunks *args:
  uv run python -m tools.workflow.prune_ilt_thunks {{args}}

# ---------------------------------------------------------------------------
# build — compile, lint, run.
# ---------------------------------------------------------------------------

[doc('Docker MSVC500 build into build-msvc500/ (runs vtable-gate + generate first)')]
[group('build')]
build:
  mkdir -p "{{build_dir}}"
  uv run python -m tools.workflow.msvc_build_lock \
    --lock "{{build_dir}}/.msvc-build.lock" -- just _build-msvc500-unlocked

# The public `build` target is the only caller. Keeping generation and compilation
# under one lock prevents concurrent agents in this worktree from racing on either.
[private]
_build-msvc500-unlocked:
  just vtable-gate
  just generate
  docker run --rm --network none \
    -e CMAKE_FLAGS="{{cmake_flags}}" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{build_dir}}":/build \
    "{{docker_image}}"

# Test-instrumented build. It deliberately shares build-msvc500's lock with the
# byte-matching build so two VC5 builds cannot race in one worktree even though
# their build products live in separate directories.
[doc('Build the native semantic runtime-test executable into build-runtime-tests/')]
[group('build')]
runtime-test-build:
  mkdir -p "{{runtime_test_build_dir}}"
  uv run python -m tools.workflow.msvc_build_lock \
    --lock "{{build_dir}}/.msvc-build.lock" -- just _build-runtime-tests-unlocked

[private]
_build-runtime-tests-unlocked:
  just vtable-gate
  uv run python -m tools.generate --gen-dir "{{runtime_test_build_dir}}/generated"
  docker run --rm --network none \
    -e CMAKE_FLAGS="{{cmake_flags}} -DIMPERIALISM_RUNTIME_TESTS=ON" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{runtime_test_build_dir}}":/build \
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
  uv run python -m tools.generate --gen-dir "{{lint_build_dir}}/generated" \
    --chunk-prefix lint_stubs_part --annotation-kind none
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

# Run the ORIGINAL retail binary the same way — the runtime oracle. Verified
# 2026-07-05: it reaches the full main menu under this Wine setup (logo -> intro
# movie -> menu), so any recomp divergence is a decomp bug, never "maybe Wine".
[doc('Run the original retail exe under Wine (the runtime oracle)')]
[group('build')]
run-original *args:
  #!/usr/bin/env bash
  set -euo pipefail
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  game_dir="$(cd "$(dirname "$ORIGINAL_BINARY")" && pwd)"
  export WINEDEBUG="${WINEDEBUG--all}"
  cd "$game_dir"
  exec wine "$ORIGINAL_BINARY" "$@"

# Run one compiled semantic test through the instrumented executable. The host
# runner only owns process lifetime and result transport; game actions execute
# inside Imperialism.exe on the UI thread.
[doc('Run one native semantic runtime test (default: boot_managers)')]
[group('build')]
runtime-test name='boot_managers' *args:
  uv run python tools/runtime/runtime_tests.py "{{name}}" {{args}}

# Kill any stale game/wineserver state, then launch the recomp detached and confirm
# it is alive. Replaces the error-prone manual three-command dance (kill+settle,
# nohup launch, pgrep) — chaining kill and relaunch in one shell command silently
# races about half the time. Log: build-msvc500/run.log.
# `just run-fresh run-original` launches the oracle instead of the recomp.
[doc('Fresh detached game launch: kill stale wine state, launch, confirm alive')]
[group('build')]
run-fresh target='run':
  #!/usr/bin/env bash
  set -euo pipefail
  pkill -9 -f -i Imperialism.exe 2>/dev/null || true
  sleep 1
  wineserver -k 2>/dev/null || true
  sleep 2
  log="{{justfile_directory()}}/{{build_dir}}/run.log"
  nohup just {{target}} > "$log" 2>&1 &
  disown
  sleep 8
  if pgrep -f -i Imperialism.exe > /dev/null; then
    echo "game running (pid $(pgrep -f -i Imperialism.exe | head -1)); log: $log"
  else
    echo "game did not stay up; log tail:" >&2
    tail -20 "$log" >&2
    exit 1
  fi

# Run with Wine SEH/debugstr tracing and surface unhandled faults. The blank-frame
# failure mode where a page fault is silently swallowed (process stays alive, UI
# dead) is invisible under plain `just run` — this catches it.
[doc('Timed run with +seh tracing; prints any unhandled exceptions/page faults')]
[group('build')]
run-trace timeout='30s':
  #!/usr/bin/env bash
  set -euo pipefail
  pkill -9 -f Imperialism.exe 2>/dev/null || true
  sleep 1
  wineserver -k 2>/dev/null || true
  sleep 2
  log="{{justfile_directory()}}/{{build_dir}}/run-trace.log"
  WINEDEBUG="err+all,+seh,+debugstr" timeout --kill-after=2s "{{timeout}}" just run > "$log" 2>&1 || true
  echo "--- unhandled exceptions / page faults ---"
  grep -n -i -E "unhandled|page fault|stack overflow|access violation" "$log" | head -20 || echo "(none found)"
  echo "--- last debugstr/err lines ---"
  tail -15 "$log"
  echo "full log: $log"

# Screenshot the running game window by window ID (root grabs BadMatch under
# nested/Wayland X servers). Auto-discovers the window; window IDs go stale on
# every relaunch so discovery beats hardcoding. `just screenshot [out.png]`.
[doc('Capture the running game window to a PNG (auto-discovers the window ID)')]
[group('build')]
screenshot *args:
  uv run --with python-xlib --with pillow python tools/runtime/screenshot.py {{args}}

# Synthetic input via XTest (xdotool is not installed here; python-xlib is, and
# a fake click verifiably skips the intro movie). Coordinates are relative to
# the game window. `just click 320 400`, `just key Return`.
[doc('Click the game window at window-relative X Y (XTest fake input)')]
[group('build')]
click *args:
  uv run --with python-xlib python tools/runtime/input.py click {{args}}

[doc('Press a key in the game (X keysym name, e.g. Return, space, Escape)')]
[group('build')]
key *args:
  uv run --with python-xlib python tools/runtime/input.py key {{args}}

# The bring-up smoke ladder: launch the recomp under winedbg's gdb proxy, plant
# tracepoint breakpoints on the startup milestones (dispatch -> view realize ->
# CMcWindow ctor -> OnDraw -> blit), report which fired plus a non-black-pixel
# measurement of the frame. Exit 1 if an expected milestone regressed. This
# distinguishes the three black-screen causes (silent crash / tree never
# attached / blit stub) that plain screenshots cannot.
[doc('Milestone smoke ladder: which startup stages fire + non-black pixel check')]
[group('build')]
smoke *args:
  uv run --with python-xlib --with pillow python tools/runtime/smoke.py run {{args}}

# Scripted gdb session against the recomp (winedbg --gdb proxy; real gdb front
# end: conditional breakpoints, set var, inferior calls, raw memory reads).
# gdb sees no PDB symbols — use recomp VAs from `just addr 0xORIG`.
#   just gdb-script --ex 'break *0x452af0' --ex 'continue' --ex 'bt'
#   just gdb-script --script session.gdb --seconds 60
[doc('Scripted gdb session on the recomp via the winedbg gdb proxy')]
[group('build')]
gdb-script *args:
  uv run --with python-xlib --with pillow python tools/runtime/smoke.py gdb {{args}}

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
  # Stale wineserver state makes winedbg hang until the outer timeout kills it
  # with no output at all; a clean server each session avoids that failure mode.
  wineserver -k 2>/dev/null || true
  sleep 1
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
    (cd "{{build_dir}}" && PYTHONPATH=.. uv run python -m tools.reccmp.compare_cli --target "{{target}}")
  elif [[ ${#args[@]} -eq 1 && "${args[0]}" != "--file" ]]; then
    (cd "{{build_dir}}" && PYTHONPATH=.. uv run python -m tools.reccmp.compare_cli --target "{{target}}" --verbose "${args[0]}")
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
  filter_name=""
  if [[ ${#args[@]} -gt 0 && "${args[0]}" != -* ]]; then
    filter_name="${args[0]}"
    extra=(--filter "${filter_name}")
    args=("${args[@]:1}")
  fi
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  set +e
  (cd "{{build_dir}}" && uv run reccmp-vtable --target "{{target}}" "${extra[@]}" "${args[@]}") | tee "$tmp"
  rc=${PIPESTATUS[0]}
  set -e
  # reccmp-vtable prints "Vtables found: 0.\n100% match." when the name filter matches no
  # reccmp-paired vtable. That "100% match" is vacuous (nothing was compared) and has
  # misled us into thinking unmarked/unpaired classes were verified. Turn it into a failure.
  if grep -qE "Vtables found: 0\." "$tmp"; then
    echo "" >&2
    if [[ -n "$filter_name" ]]; then
      echo "ERROR: no reccmp-paired vtable matched '${filter_name}' — 0 vtables compared." >&2
      echo "       The '100% match' above is vacuous, not a verification." >&2
      echo "       Cause: the class has no '// VTABLE: IMPERIALISM 0x...' marker, or its" >&2
      echo "       marked vtable is not being paired by reccmp (name/address mismatch)." >&2
    else
      echo "ERROR: 0 vtables were compared — the '100% match' above is vacuous." >&2
    fi
    exit 1
  fi
  exit "$rc"

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

# Translate original-binary addresses to recomp addresses and back (for winedbg
# breakpoints, crash addresses, etc.). Direction auto-detected; result cached next
# to the build until the binary/PDB changes.
#   just addr 0x491cc0 [0x...]
[doc('orig<->recomp address lookup with name + match % (cached reccmp parse)')]
[group('compare')]
addr *args:
  uv run python -m tools.reccmp.addr_translate --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

# Compare the stack layout of a single near-matching function.
#   just stackcmp 0xADDR
[group('compare')]
stackcmp addr *args:
  (cd "{{build_dir}}" && uv run reccmp-stackcmp --target "{{target}}" {{args}} "{{addr}}")

# Interpret reccmp's trusted semantic proof or first structured machine-level
# divergence with Imperialism-specific source/layout advice.
# `just triage 0xADDR [...]` or `--file SRC.cpp`.
[group('compare')]
triage *args:
  uv run python -m tools.reccmp.triage --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

# Batch stack-layout triage: run reccmp-stackcmp over near-match functions and
# rank layout suspects. `just stackcmp-triage [--min 0.4] [--max 0.999] [--limit 12]`.
[group('compare')]
stackcmp-triage *args:
  uv run python -m tools.reccmp.stackcmp_triage --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

[group('compare')]
stats *args:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled {{args}}

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

# Core-impact candidate ranking (the third session-loop artifact) as a first-class
# target. `just core-impact [--top N] [--min-size N]`.
[group('compare')]
core-impact *args:
  uv run python -m tools.reccmp.core_impact_ranking --target "{{target}}" --top 50 --min-size 1 {{args}}

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

[group('ghidra-inspect')]
ghidra-listing *args: _require-ghidra-install
  uv run python -m tools.ghidra.query listing {{args}}

# Read-only vtable evidence dump: resolve each slot of one or more vtables to its real
# body (ILT thunks chased) as JSON on stdout — target address, Ghidra name, size,
# listing signature, optional decompile. Inspection only; never writes source/symbols.
# Manual class recovery is source-first; use this as evidence, not a generator.
#   just class-vtable-dump TMapUberPicture=0x00668f08[:COUNT] [Base=0x... ...] [--decompile]
[doc('Read-only: dump a vtable class resolved slot targets as JSON (evidence only)')]
[group('ghidra-inspect')]
class-vtable-dump *args: _require-ghidra-install
  uv run python -m tools.ghidra.vtable_slots {{args}}

# One-shot porting dossier for a stub: identity+owner, callers, direct calls with
# ILT thunks chased (and each target's owner), vtable-slot/IAT calls, named globals,
# jump tables, and the decompile. `just ghidra-portprep 0xADDR [--no-decompile]`.
[group('ghidra-inspect')]
ghidra-portprep *args: _require-ghidra-install
  uv run python -m tools.ghidra.query portprep {{args}}

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

[doc('Query the committed Mac control class/tag/screen semantic index')]
[group('ghidra-inspect')]
mac-control-usage *args:
  uv run python -m tools.workflow.mac_control_usage {{args}}

[doc('Reject stale Mac control class/tag/screen semantic metadata')]
[group('gates')]
mac-control-usage-check:
  uv run python -m tools.workflow.mac_control_usage --check

[doc('Query the committed file-scoped Mac resource reference graph')]
[group('ghidra-inspect')]
mac-resource-xrefs *args:
  uv run python -m tools.workflow.mac_resource_xrefs {{args}}

[doc('MUTATES: regenerate the committed Mac resource reference graph')]
[group('recovery')]
mac-resource-xrefs-update:
  uv run python -m tools.workflow.mac_resource_xrefs --write

[doc('Reject stale resource xrefs and unexplained dangling edges')]
[group('gates')]
mac-resource-xrefs-check:
  uv run python -m tools.workflow.mac_resource_xrefs --check

[doc('Inspect differential Mac widget payload evidence for one effective class')]
[group('ghidra-inspect')]
mac-payload-diff class_name *args:
  uv run python -m tools.workflow.mac_payload_diff "{{class_name}}" {{args}}

[doc('MUTATES: regenerate the committed Mac widget payload differential report')]
[group('recovery')]
mac-payload-diff-update:
  uv run python -m tools.workflow.mac_payload_diff --write

[doc('Reject stale Mac widget payload differential evidence')]
[group('gates')]
mac-payload-diff-check:
  uv run python -m tools.workflow.mac_payload_diff --check

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

[doc('MUTATES: regenerate the committed Mac-to-Windows string crosswalk')]
[group('recovery')]
mac-string-crosswalk-update:
  uv run python -m tools.workflow.mac_string_crosswalk --write

[doc('Reject stale Mac-to-Windows string crosswalk metadata')]
[group('gates')]
mac-string-crosswalk-check:
  uv run python -m tools.workflow.mac_string_crosswalk --check

[doc('Report Mac-resource versus generated Windows UI semantic deltas')]
[group('ghidra-inspect')]
ui-platform-diff *args:
  uv run python -m tools.workflow.ui_platform_diff {{args}}

[doc('MUTATES: regenerate the committed UI platform-delta report')]
[group('recovery')]
ui-platform-diff-update:
  uv run python -m tools.workflow.ui_platform_diff --write

[doc('Reject undeclared or stale UI platform deltas')]
[group('gates')]
ui-platform-diff-check:
  uv run python -m tools.workflow.ui_platform_diff --check

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

# Cross-references for an address. Direction `to` (default): callers, jumps,
# address-taken/data refs, hopping through ILT `jmp` thunks automatically so body
# addresses answer "who calls this" in one query. Direction `from`: the containing
# function's callees + data reads without decompiling. `both` prints both.
# `just xrefs [to|from|both] 0xADDR [0xADDR ...] [--no-thunk-hop] [--limit N]`.
[group('ghidra-inspect')]
xrefs *args: _require-ghidra-install
  uv run python -m tools.ghidra.query xrefs {{args}}

# Signature facts per function: Ghidra cc/params (hypothesis) + RET-imm purge bytes
# (ground truth). `just func-sig 0xADDR [0xADDR ...]`.
[group('ghidra-inspect')]
func-sig *args: _require-ghidra-install
  uv run python -m tools.ghidra.query func-sig {{args}}

# Which member functions touch `this+offset`? `just field-xrefs <Class> [0xOFF] [--limit N]`
# (no offset = histogram of all this-relative offsets the class touches).
[group('ghidra-inspect')]
field-xrefs *args: _require-ghidra-install
  uv run python -m tools.ghidra.query field-xrefs {{args}}

# Unported functions that reference (near-)unique string literals — self-naming
# port targets. `just string-oracle [--min-len N] [--max-refs N] [--limit N] [--all]`.
[group('ghidra-inspect')]
string-oracle *args: _require-ghidra-install
  uv run python -m tools.ghidra.query string-oracle {{args}}

alias ghidra-xrefs := xrefs

# Read memory at an address as a typed value (float/double/dword/ptr/str/bytes/...).
# `just ghidra-read-data 0xADDR [type] [count]`.
[group('ghidra-inspect')]
ghidra-read-data *args: _require-ghidra-install
  uv run python -m tools.ghidra.query read-data {{args}}

# Decode an MSVC500 switch jump table (works inside Ghidra code gaps).
# `just ghidra-jumptable 0xJMPADDR` or `--table 0xADDR [--cases N]`.
[group('ghidra-inspect')]
ghidra-jumptable *args: _require-ghidra-install
  uv run python -m tools.ghidra.query jumptable {{args}}

# Call/offset slice of a function: callers, callees, this+offset field accesses.
# `just ghidra-function-slice 0xADDR [0xADDR ...]`.
[group('ghidra-inspect')]
ghidra-function-slice *args: _require-ghidra-install
  uv run python -m tools.ghidra.query function-slice {{args}}

[group('ghidra-inspect')]
ghidra-decompile *args: _require-ghidra-install
  uv run python -m tools.ghidra.query decompile {{args}}

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

# Linear disassembly by address, ignoring Ghidra's (sometimes wrong) function
# boundaries. `just ghidra-linear-disasm 0xADDR [count]`.
[group('ghidra-inspect')]
ghidra-linear-disasm *args: _require-ghidra-install
  uv run python -m tools.ghidra.query linear-disasm {{args}}

# Whole-binary search for a value in disassembled instruction text, raw data, or
# instruction immediates (message-map/handler/event-code hunting).
# `just ghidra-search text|dword|imm <value> [limit]`.
[group('ghidra-inspect')]
ghidra-search *args: _require-ghidra-install
  uv run python -m tools.ghidra.query search {{args}}

# Disassemble raw bytes with capstone, bypassing Ghidra's instruction database
# entirely (for regions Ghidra hasn't disassembled at all).
# `just ghidra-raw-disasm 0xADDR [byte_count]`.
[group('ghidra-inspect')]
ghidra-raw-disasm *args: _require-ghidra-install
  uv run python -m tools.ghidra.query raw-disasm {{args}}

[group('ghidra-inspect')]
ghidra-vtable-dump class vtable *args: _require-ghidra-install
  uv run python -m tools.ghidra.query vtable-dump "{{class}}" "{{vtable}}" {{args}}

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

# Run all mechanical source-policy gates (the pre-commit check).
# Run `just format-check <touched paths>` separately on files you edited; the tree
# is not fully clang-formatted, so format-check is per-path, not whole-tree.
[doc('Run all mechanical source-policy gates (the pre-commit check)')]
[group('gates')]
gates:
  just source-gates
  just stats --ui-codegen-gate
  just vtable
  just datacmp-gate
  just decomplint
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
  uv run python -m unittest discover -s tests/tools

# Raw-vtable source gate (Hard Rule 13); also runs as the first step of `just build`.
[group('gates')]
vtable-gate:
  uv run python -m tools.workflow.check_no_raw_vtable_calls --baseline "{{vtable_gate_baseline}}"

# Vtable ABI audit: current source declarations vs the binary's immutable
# calling-convention evidence (config/vtable_abi_evidence.json). Catches wrong
# signatures that `just vtable` (slot->address matching) cannot see.
#   just vtable-abi-audit                 -> ranked report, conflict classes only
#   just vtable-abi-audit TMapMaker -v    -> one class, all slots
[doc('Audit vtable slot declarations against binary ABI evidence (RET imm, pushes, ret-use)')]
[group('gates')]
vtable-abi-audit *args:
  uv run python -m tools.workflow.vtable_abi_audit {{args}}

# Ratchet gate over the ABI audit: fails on NEW proven declaration conflicts
# (address+class not in config/baselines/vtable_abi_gate_baseline.csv and not covered by a
# reviewed config/vtable_signature_overrides.csv row). Pure source + static
# evidence; no Ghidra needed.
[group('gates')]
vtable-abi-gate:
  uv run python -m tools.workflow.vtable_abi_audit --gate

# MUTATES: config/baselines/vtable_abi_gate_baseline.csv. Refresh after fixing conflicts.
[group('gates')]
vtable-abi-gate-update:
  uv run python -m tools.workflow.vtable_abi_audit --write-baseline

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

# Ratchet gate against ILT/thunk-name ossification in manual source: rejects NEW
# identifiers that start with thunk_/ILT_/WrapperFor_ or end with _At<8hex> (calls
# via linker thunks; history-encoded body names). Existing debt is grandfathered in
# config/baselines/ilt_ossification_baseline.csv — a finite, shrink-only migration queue.
# Rejects "dual-use"/"dual-purpose"/"reused as" hand-waving and raw pointer<->int member
# storage (reinterpret_cast<int>(ptr), int-member->class-pointer casts). A purported dual-use
# field is an unresolved modelling defect: prove one model (union/record/accessors) or mark it
# // UNRESOLVED_FIELD_ATTRIBUTION: with both readings + evidence. Existing debt grandfathered in
# config/baselines/dual_use_baseline.csv (shrink-only migration queue).
[group('gates')]
dual-use-gate:
  uv run python -m tools.workflow.check_dual_use

# Enforce the recovered geometry boundary: game-owned APIs use CPoint/CRect, while
# POINT/RECT remain at verified Win32/MFC boundaries. Reject cast bridges; only a
# locally documented GEOMETRY_RAW_BUFFER packed payload may require one.
[group('gates')]
geometry-type-gate:
  uv run python -m tools.workflow.check_geometry_types

# MUTATES: config/baselines/dual_use_baseline.csv. Ratchet down after resolving a field's
# attribution. Never run to silence a new offender.
[group('gates')]
dual-use-gate-update:
  uv run python -m tools.workflow.check_dual_use --write-baseline

[group('gates')]
ilt-ossification-gate:
  uv run python -m tools.workflow.check_ilt_ossification

# MUTATES: config/baselines/ilt_ossification_baseline.csv. Ratchet down after migrating a thunk
# or renaming a WrapperFor_/_At body. Never run to silence a new offender.
[group('gates')]
ilt-ossification-gate-update:
  uv run python -m tools.workflow.check_ilt_ossification --write-baseline

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

# Structural integrity of config/original_entities.csv: header row exactly at line 1, no
# duplicate headers, parseable hex addresses, no duplicate addresses, no two
# function rows claiming overlapping byte ranges. (Every consumer is a DictReader
# that silently degrades when the header is misplaced.)
[doc('symbols.csv structural integrity: header at line 1, parseable + unique addresses, no function-range overlaps')]
[group('gates')]
symbols-integrity-gate:
  uv run python -m tools.workflow.check_symbols_integrity

# Reject generated build inputs and retired generated source trees in a PR's diff. CI supplies
# the merge base and --no-worktree so only committed branch changes are inspected.
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
  uv run python -m tools.workflow.check_construction_antipatterns --baseline "{{construction_gate_baseline}}"

[group('gates')]
tgreatpower-gate:
  uv run python -m tools.workflow.check_tgreatpower_hygiene --baseline "{{tgreatpower_gate_baseline}}"

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

# Strict forms of the two typedef audits, run as part of `just gates`: signature
# drift across files and dropped-args/convention bugs vs binary evidence both fail.
[group('gates')]
typedef-cast-gate:
  uv run python -m tools.workflow.check_typedef_cast_drift

[group('gates')]
typedef-args-gate:
  uv run python -m tools.workflow.check_typedef_ghidra_args --strict

# No local `extern` redeclarations of globals already in global_data_tables.h.
[group('gates')]
global-redeclaration-gate:
  uv run python -m tools.workflow.check_global_redeclarations

# Manual/autogen boundary report: every autogen stub referenced from manual
# sources, with call/address-take split, caller counts, original size, and
# (when Ghidra is available) cc/params/RET-imm facts + a porting classification.
[doc('Report every manual-source reference to an autogen stub, classified for porting')]
[group('analysis')]
boundary-audit *args:
  uv run python -m tools.workflow.boundary_audit {{args}}

# Embedded-MFC-collection audit for an owner ctor (0xADDR or class name): member
# offset, vtable family/slot-0 identity, block size, ctor/dtor copy census, and a
# normalized-body twin scan for per-TU duplicate template COMDATs. See the
# mfc-collections skill's three-problem taxonomy (rules MFC-EMBED-029/MFC-TWIN-030).
[doc('Audit an embedded MFC collection member: identity, offsets, duplicate-COMDAT twins')]
[group('analysis')]
mfc-collection-audit *args:
  uv run python -m tools.workflow.mfc_collection_audit {{args}}

# Template-emission compiler matrix (docs/toolchain.md): compile the probe TUs in
# the msvc500 container per cell (/Ob levels, TU splits, wrapper/init/dtor axes)
# and inventory the CList COMDATs each TU emits (host-side COFF parse).
[doc('Run the template-emission matrix and report per-TU CList COMDAT inventories')]
[group('analysis')]
template-emission-matrix *args:
  uv run python -m tools.workflow.template_emission_matrix {{args}}

# Re-verify every row of config/template_aliases.csv: alias and canonical bodies
# must be identical modulo relocations (tools.binary.body_hash).
[doc('Validate template-COMDAT alias rows in config/template_aliases.csv')]
[group('analysis')]
template-alias-check:
  uv run python -m tools.workflow.template_alias_check

# Ratchet gate over the boundary report: no new manual->stub call/cast references
# and no new function-pointer casts of named symbols (both counts must not rise).
[group('gates')]
boundary-gate:
  uv run python -m tools.workflow.check_boundary_ratchet

# Lint the structured agent rule KB (config/agent_rules.yml): ids, supersedes,
# required/forbidden contradictions, just-only tools, derivable triggers.
[group('gates')]
agent-rules-gate:
  uv run python -m tools.workflow.check_agent_rules

# The binary-free gate subset CI runs on every PR (no docker/wine/original exe:
# excludes vtable, datacmp-gate, decomplint, lint). Keep in sync with `gates`.
[doc('Source-only gate subset (what CI enforces; no built binary needed)')]
[group('gates')]
source-gates:
  just generate
  just --jobs 4 _source-gates-parallel

[private]
[parallel]
_source-gates-parallel: ui-codegen-check ui-view-coverage-check mac-control-usage-check mac-resource-xrefs-check mac-payload-diff-check mac-string-crosswalk-check ui-platform-diff-check tooling-check vtable-gate antipattern-gate tgreatpower-gate marker-gate generated-marker-gate dual-use-gate geometry-type-gate ilt-ossification-gate vtable-annotation-gate vtable-collision-gate synthetic-gate symbols-integrity-gate library-identity-gate global-location-gate manual-cruntimeclass-gate stub-count-gate class-size-gate noop-gate typedef-cast-gate typedef-args-gate global-redeclaration-gate boundary-gate agent-rules-gate vtable-abi-gate

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

# MUTATES: the aggregate JSON and per-function CSV reccmp progress baselines.
[group('baseline-update')]
stats-baseline-update:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled --commit-baseline

[doc('MUTATES: config/tooling_surface.csv. Appends placeholder rows for justfile modules missing from the manifest (fill in each note); never removes stale rows')]
[group('baseline-update')]
tooling-surface-update:
  uv run python -m tools.workflow.check_tooling_surface --write

# MUTATES: config/baselines/vtable_gate_baseline.csv.
[group('baseline-update')]
vtable-gate-update:
  @test "${ALLOW_POLICY_BASELINE_UPDATE:-}" = "1" || { echo "REFUSED: this rewrites an architecture-policy baseline (blessing new debt)."; echo "If a human approved the exception, rerun with ALLOW_POLICY_BASELINE_UPDATE=1."; exit 2; }
  uv run python -m tools.workflow.check_no_raw_vtable_calls --baseline "{{vtable_gate_baseline}}" --write-baseline

# MUTATES: config/baselines/construction_gate_baseline.csv.
[group('baseline-update')]
antipattern-gate-update:
  @test "${ALLOW_POLICY_BASELINE_UPDATE:-}" = "1" || { echo "REFUSED: this rewrites an architecture-policy baseline (blessing new debt)."; echo "If a human approved the exception, rerun with ALLOW_POLICY_BASELINE_UPDATE=1."; exit 2; }
  uv run python -m tools.workflow.check_construction_antipatterns --baseline "{{construction_gate_baseline}}" --write-baseline

# MUTATES: config/baselines/tgreatpower_gate_baseline.csv.
[group('baseline-update')]
tgreatpower-gate-update:
  @test "${ALLOW_POLICY_BASELINE_UPDATE:-}" = "1" || { echo "REFUSED: this rewrites an architecture-policy baseline (blessing new debt)."; echo "If a human approved the exception, rerun with ALLOW_POLICY_BASELINE_UPDATE=1."; exit 2; }
  uv run python -m tools.workflow.check_tgreatpower_hygiene --baseline "{{tgreatpower_gate_baseline}}" --write-baseline

# MUTATES: config/baselines/stub_count_baseline.json.
[group('baseline-update')]
stub-count-gate-update:
  @test "${ALLOW_POLICY_BASELINE_UPDATE:-}" = "1" || { echo "REFUSED: this rewrites an architecture-policy baseline (blessing new debt)."; echo "If a human approved the exception, rerun with ALLOW_POLICY_BASELINE_UPDATE=1."; exit 2; }
  uv run python -m tools.workflow.check_stub_count --write-baseline

# MUTATES: config/baselines/boundary_baseline.json.
[group('baseline-update')]
boundary-gate-update:
  @test "${ALLOW_POLICY_BASELINE_UPDATE:-}" = "1" || { echo "REFUSED: this rewrites an architecture-policy baseline (blessing new debt)."; echo "If a human approved the exception, rerun with ALLOW_POLICY_BASELINE_UPDATE=1."; exit 2; }
  uv run python -m tools.workflow.check_boundary_ratchet --write-baseline

# MUTATES: config/baselines/datacmp_baseline.csv.
[group('baseline-update')]
datacmp-gate-update:
  @test "${ALLOW_POLICY_BASELINE_UPDATE:-}" = "1" || { echo "REFUSED: this rewrites an architecture-policy baseline (blessing new debt)."; echo "If a human approved the exception, rerun with ALLOW_POLICY_BASELINE_UPDATE=1."; exit 2; }
  uv run python -m tools.workflow.check_datacmp_baseline --target "{{target}}" --build-dir "{{build_dir}}" --write-baseline

# MUTATES: config/baselines/empty_body_baseline.csv.
[group('baseline-update')]
noop-gate-update:
  @test "${ALLOW_POLICY_BASELINE_UPDATE:-}" = "1" || { echo "REFUSED: this rewrites an architecture-policy baseline (blessing new debt)."; echo "If a human approved the exception, rerun with ALLOW_POLICY_BASELINE_UPDATE=1."; exit 2; }
  uv run python -m tools.workflow.check_empty_bodies --write-baseline config/baselines/empty_body_baseline.csv

# MUTATES: reccmp-project.yml ignore lists (Hard Rule 14).
[group('baseline-update')]
generate-ignores:
  uv run python -m tools.reccmp.generate_ignore_functions --target "{{target}}" --apply

# ---------------------------------------------------------------------------
# rewrite — targets that rewrite source/config from symbols or policy.
# ---------------------------------------------------------------------------

# MUTATES: source files under src/game + include/game.
[private]
[group('rewrite')]
annotate-globals:
  uv run python -m tools.workflow.annotate_globals_from_symbols --paths src/game include/game --write

# MUTATES: reccmp markers in src/ + include/.
[private]
[group('rewrite')]
normalize-markers:
  uv run python -m tools.workflow.normalize_reccmp_markers --paths src include --write

# MUTATES: config/original_entities.csv + `// SYNTHETIC:` comments (with --apply).
# Canonicalize scalar-deleting-destructor spellings to the MSVC500-mangled form.
# Pass --dry-run to preview. `just synthetic-gate` is the mechanical check.
[doc('MUTATES: symbols.csv + // SYNTHETIC: comments. Canonicalize scalar-dtor spellings')]
[private]
[group('rewrite')]
correct-scalar-dtors *args:
  uv run python -m tools.workflow.correct_scalar_dtors {{args}}

# MUTATES: config/original_entities.csv + stub manifest (with --write).
# Dry-run-first vtable repair planner. Applies only deterministic fixes with --write:
# manifest slot promotion, scalar-dtor spelling cleanup, and safe ILT thunk pruning.
[private]
[doc('MUTATES (--write): original_entities.csv. Dry-run-first vtable repair planner')]
[group('rewrite')]
vtable-autofix *args:
  uv run python -m tools.workflow.vtable_autofix {{args}}

# Diagnostic: aggregate every identity signal for one address (symbols, ownership,
# reviewed override, cached FID match, object-matcher oracle) into a verdict.
# Run before behaviourally naming any MSVC/MFC-range or CRT-shaped function:
# a missing FID result is NOT evidence of game ownership. `just library-identify 0xADDR`.
[group('ghidra-inspect')]
library-identify address:
  uv run python -m tools.mfc.library_identify "{{address}}"

# Rebuild the relocation-masked object-matcher report into build evidence (uncommitted).
# identity oracle by matching the original executable against the vendored
# libcmt.lib/nafxcw.lib COFF members. Needs the original binary (ORIGINAL_BINARY).
[group('rewrite')]
build-library-oracle *args:
  uv run python -m tools.mfc.build_library_oracle {{args}}

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
    --classes "$discovery_classes"

[group('recovery')]
slice-discovery class address:
  uv run python -m tools.workflow.slice_discovery "{{class}}" --address "{{address}}"

# MUTATES: vendor/macos_codewarrior/evidence (regenerates the vendored Mac evidence).
[doc('MUTATES: vendor/macos_codewarrior/evidence. Regenerate symbol and resource evidence from the Mac retail files')]
[group('recovery')]
mac-evidence:
  : "${MACOS_IMPERIALISM_DUMP:?Set MACOS_IMPERIALISM_DUMP in .env (Mac retail root or extracted dump dir); only needed to regenerate the vendored evidence}"
  uv run python -m tools.workflow.macos_evidence \
    --dump-dir "{{macos_dump}}" \
    --workspace "{{macos_workspace}}"
  uv run python -m tools.workflow.macos_resource_evidence \
    --source "{{macos_dump}}" \
    --workspace "{{macos_workspace}}"

[doc('MUTATES: vendor/macos_codewarrior/evidence/resources. Regenerate the Mac UI resource oracle')]
[group('recovery')]
mac-resource-evidence source=macos_dump:
  uv run python -m tools.workflow.macos_resource_evidence \
    --source "{{source}}" \
    --workspace "{{macos_workspace}}"

[group('recovery')]
mac-evidence-check:
  uv run python -m tools.workflow.macos_evidence \
    --workspace "{{macos_workspace}}" \
    --check
  uv run python -m tools.workflow.macos_resource_evidence \
    --workspace "{{macos_workspace}}" \
    --check

[group('recovery')]
mac-resource-evidence-check:
  uv run python -m tools.workflow.macos_resource_evidence \
    --workspace "{{macos_workspace}}" \
    --check

# ---------------------------------------------------------------------------
# setup — one-time bootstrap / image builds.
# ---------------------------------------------------------------------------

[group('setup')]
docker-build:
  docker build --network host -t "{{docker_image}}" -f docker/msvc500/Dockerfile docker/msvc500

[group('setup')]
bootstrap-reccmp:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run reccmp-project create --originals "$ORIGINAL_BINARY" --scm

[doc('Install the local generated-reccmp-baseline merge driver (tracked hooks regenerate after conflicts)')]
[group('setup')]
install-reccmp-merge-driver:
  uv run python -m tools.workflow.reccmp_baseline_merge install

# Generate ./compile_commands.json (clang-lint flavor, host paths) for clangd/LSP
# navigation. Not for matching questions — the reccmp build is MSVC500. The lint
# *build* may fail (advisory); the database comes from the CMake configure step.
[group('setup')]
gen-compile-commands:
  -just lint "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
  uv run python -m tools.workflow.gen_compile_commands

[group('setup')]
vendor-msvc500-headers *args:
  uv run python -m tools.workflow.vendor_msvc500_headers {{args}}

# Mirror the DirectX 5 SDK inc/lib (reference copy of C:\dxsdk in the build image).
[group('setup')]
vendor-directx-headers *args:
  uv run python -m tools.workflow.vendor_directx_headers {{args}}
