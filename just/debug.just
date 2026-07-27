# Manual launch, debugger, and differential startup tools.

# Run the recompiled Imperialism.exe under Wine from the retail install directory.
# ORIGINAL_BINARY in .env must point at an immutable copy of your legally
# obtained Imperialism.exe; its parent directory must contain Data/ and the
# other game assets. Build first with `just build`. Override WINEDEBUG in the
# environment for Wine tracing.
[doc('Run the recompiled exe under Wine from the retail install dir')]
[group('debug')]
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
[group('debug')]
run-original *args:
  #!/usr/bin/env bash
  set -euo pipefail
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  game_dir="$(cd "$(dirname "$ORIGINAL_BINARY")" && pwd)"
  export WINEDEBUG="${WINEDEBUG--all}"
  cd "$game_dir"
  exec wine "$ORIGINAL_BINARY" "$@"

# The bring-up smoke ladder: launch the recomp under winedbg's gdb proxy, plant
# tracepoint breakpoints on the startup milestones (dispatch -> view realize ->
# CMcWindow ctor -> OnDraw -> blit), report which fired plus a non-black-pixel
# measurement of the frame. Exit 1 if an expected milestone regressed. This
# distinguishes the three black-screen causes (silent crash / tree never
# attached / blit stub) that plain screenshots cannot.
[doc('Milestone smoke ladder: which startup stages fire + non-black pixel check')]
[group('debug')]
smoke *args:
  uv run python tools/runtime/smoke.py run {{args}}

# Differential startup oracle: run the SAME milestone ladder against the retail
# binary and the recomp in isolated Wine prefixes; the original's reached set is
# the expectation and any milestone it reaches that the recomp misses fails.
[doc('Differential startup oracle: original vs recomp milestone ladder')]
[group('debug')]
smoke-diff *args:
  uv run python tools/runtime/smoke.py diff {{args}}

# Run the recomp through its native semantic driver and observe the retail binary
# through the narrow GDB tape, then compare their normalized semantic checkpoint.
[doc('Compare one native recomp checkpoint against the retail GDB oracle')]
[group('debug')]
diff-run scenario *args:
  just runtime-test-build
  uv run python -m tools.runtime.differential "{{scenario}}" {{args}}

# Scripted gdb session against the recomp (winedbg --gdb proxy; real gdb front
# end: conditional breakpoints, set var, inferior calls, raw memory reads).
# gdb sees no PDB symbols — use recomp VAs from `just addr 0xORIG`.
#   just gdb-script --ex 'break *0x452af0' --ex 'continue' --ex 'bt'
#   just gdb-script --script session.gdb --seconds 60
[doc('Scripted gdb session on the recomp via the winedbg gdb proxy')]
[group('debug')]
gdb-script *args:
  uv run python tools/runtime/smoke.py gdb {{args}}

# Run the recomp under winedbg from the retail install directory. By default breaks
# on MessageBoxA, continues, prints a backtrace, and quits — useful for tracing
# startup failures (empty error boxes, InitInstance bailouts). Override the
# script: DEBUG_SCRIPT=$'break SomeSymbol\ncont\nbt\nquit\n' just debug
[doc('Run the recomp under winedbg (default script: break MessageBoxA, bt, quit)')]
[group('debug')]
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
[group('debug')]
debug-timeout *args:
  #!/usr/bin/env bash
  set -euo pipefail
  export WINEDEBUG="${WINEDEBUG-err+all,+debugstr,+loaddll}"
  exec timeout --kill-after=2s "${DEBUG_TIMEOUT:-5s}" just debug "$@"
