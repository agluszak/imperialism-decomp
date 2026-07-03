#!/usr/bin/env python3
"""Thin client for the Ghidra inspection daemon (tools/ghidra/daemon.py).

Forwards one command to the daemon and prints its output, auto-starting the daemon on the
first call (paying the one-time JVM + project-load cost once; every later call is fast).

usage: daemon_client <cmd> [args ...]
       daemon_client shutdown          # stop the daemon

Set GHIDRA_DAEMON_NOSPAWN=1 to fail instead of auto-starting (used by control targets).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from tools.common import ghidra_env

REPO_ROOT = ghidra_env.REPO_ROOT
STARTUP_TIMEOUT_S = 240.0


def _connect(sock_path: Path) -> socket.socket | None:
    if not sock_path.exists():
        return None
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(str(sock_path))
        return s
    except OSError:
        s.close()
        return None


def _request(sock: socket.socket, payload: dict) -> dict:
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            break
        chunks.append(data)
    sock.close()
    raw = b"".join(chunks)
    if not raw:
        raise ConnectionError("daemon closed the connection without a response")
    return json.loads(raw.decode("utf-8"))


def _spawn_daemon(sock_path: Path) -> None:
    log_path = REPO_ROOT / ".ghidra-daemon.log"
    log = open(log_path, "ab")  # noqa: SIM115 - handed to the child; closed on our exit
    print(
        "ghidra-daemon: not running — starting it (one-time project load, "
        f"~15-30s; log: {log_path.name})...",
        file=sys.stderr,
        flush=True,
    )
    subprocess.Popen(
        [sys.executable, "-m", "tools.ghidra.daemon"],
        cwd=str(REPO_ROOT),
        stdout=log,
        stderr=log,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env=os.environ.copy(),
    )


def _wait_for_daemon(sock_path: Path) -> socket.socket:
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    while time.monotonic() < deadline:
        s = _connect(sock_path)
        if s is not None:
            try:
                if _request(s, {"cmd": "ping"}).get("out") == "pong":
                    reconnected = _connect(sock_path)
                    if reconnected is not None:
                        return reconnected
            except (OSError, ConnectionError, json.JSONDecodeError):
                pass
        time.sleep(0.5)
    raise TimeoutError(f"Ghidra daemon did not become ready within {STARTUP_TIMEOUT_S:.0f}s")


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: daemon_client <cmd> [args ...]", file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    sock_path = ghidra_env.socket_path()

    sock = _connect(sock_path)
    if sock is None:
        if cmd == "shutdown":
            print("ghidra-daemon: not running", file=sys.stderr)
            return 0
        if os.getenv("GHIDRA_DAEMON_NOSPAWN") == "1":
            print("ghidra-daemon: not running", file=sys.stderr)
            return 1
        _spawn_daemon(sock_path)
        sock = _wait_for_daemon(sock_path)

    resp = _request(sock, {"cmd": cmd, "args": args})
    if resp.get("out"):
        sys.stdout.write(resp["out"])
        if not resp["out"].endswith("\n"):
            sys.stdout.write("\n")
    if resp.get("err"):
        sys.stderr.write(resp["err"])
    return int(resp.get("rc", 0))


if __name__ == "__main__":
    raise SystemExit(main())
