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
    -e CMAKE_FLAGS="{{cmake_flags}}" \
    -e CMAKE_GENERATOR="{{ if jobs == '1' { 'NMake Makefiles' } else { 'NMake Makefiles JOM' } }}" \
    -e BUILD_JOBS="{{ if jobs == '1' { '' } else { jobs } }}" \
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
# config. Warning-as-error is forced here as well as defaulted in CMake so an old
# build-clang cache cannot silently retain the former OFF value.
[doc('Compile-only clang/MinGW warning-as-error check; never used for reccmp')]
[group('build')]
lint flags="":
  mkdir -p "{{lint_build_dir}}"
  uv run python -m tools.generate --gen-dir "{{lint_build_dir}}/generated" \
    --chunk-prefix lint_stubs_part --annotation-kind none
  docker run --rm --network none \
    -e CMAKE_FLAGS="-DIMPERIALISM_LINT_WERROR=ON {{flags}}" \
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
  just gen-compile-commands
  docker run --rm --network none --entrypoint clang-tidy \
    -v "$PWD":/imperialism \
    -v "$PWD/{{lint_build_dir}}":/build \
    "{{docker_image}}" \
    -p /build \
    --checks='-*,bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions,readability-redundant-casting' \
    --header-filter='^/imperialism/(include|src)/game/' \
    --quiet \
    /imperialism/src/game/TScrollBarView.cpp \
    /imperialism/src/game/TGreatPower.cpp \
    /imperialism/src/game/TMapMaker.cpp \
    /imperialism/src/game/TViewMgr.cpp \
    /imperialism/src/game/NetMessage.cpp

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
  uv run python tools/runtime/smoke.py run {{args}}

# Differential startup oracle: run the SAME milestone ladder against the retail
# binary and the recomp in isolated Wine prefixes; the original's reached set is
# the expectation and any milestone it reaches that the recomp misses fails.
[doc('Differential startup oracle: original vs recomp milestone ladder')]
[group('build')]
smoke-diff *args:
  uv run python tools/runtime/smoke.py diff {{args}}

# Scripted gdb session against the recomp (winedbg --gdb proxy; real gdb front
# end: conditional breakpoints, set var, inferior calls, raw memory reads).
# gdb sees no PDB symbols — use recomp VAs from `just addr 0xORIG`.
#   just gdb-script --ex 'break *0x452af0' --ex 'continue' --ex 'bt'
#   just gdb-script --script session.gdb --seconds 60
[doc('Scripted gdb session on the recomp via the winedbg gdb proxy')]
[group('build')]
gdb-script *args:
  uv run python tools/runtime/smoke.py gdb {{args}}

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
