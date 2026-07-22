#!/usr/bin/env bash
# Run `just debug` with a hard timeout and reap all wine processes afterward,
# so a hit breakpoint (which leaves winedbg interactive) can't wedge the shell.
set -u
secs="${1:-8}"; shift || true
export WINEDEBUG="${WINEDEBUG--all}"
timeout --kill-after=2s "${secs}s" just debug "$@"
rc=$?
# Reap anything wine left behind.
wineserver -k 2>/dev/null || true
pkill -9 -f winedbg 2>/dev/null || true
pkill -9 -f Imperialism.exe 2>/dev/null || true
echo "[dbg.sh] exit=$rc"
exit 0
