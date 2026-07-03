#!/usr/bin/env python3
"""Persistent read-only Ghidra query daemon: pay the JVM startup once per session.

Every one-shot `just ghidra-*` invocation spends ~60-90s starting pyghidra/the JVM
and opening the vendored project before running a query that itself takes
milliseconds. Research sessions issue dozens of such queries; this daemon keeps one
JVM + read-only program handle alive behind a unix socket so `tools.ghidra.query`
(and therefore the `just ghidra-listing`/`xrefs`/`ghidra-search`/... targets)
answer instantly while it runs.

Protocol: newline-delimited JSON over a unix socket in the repo root.
  request:  {"cmd": "listing", "args": ["0x491cc0"]}\n
  response: {"ok": true, "rc": 0, "output": "..."}\n
Special cmds: "ping" (liveness) and "shutdown".

LOCKING: the daemon holds the vendored Ghidra project open (read-only program, but
the *project* lock is exclusive). Stop it before any mutating [ghidra-db]/[sync]
target — `just sync-ghidra` and `just restore-project` do this automatically via
`just ghidra-daemon-stop`. The daemon also exits on its own after
GHIDRA_DAEMON_IDLE_SECS (default 4h) without queries.

usage: daemon start|stop|status|serve
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import socket
import subprocess
import sys
import time

from tools.common import ghidra_env

SOCKET_PATH = ghidra_env.REPO_ROOT / ".ghidra-query.sock"
PID_PATH = ghidra_env.REPO_ROOT / ".ghidra-query.pid"
LOG_PATH = ghidra_env.REPO_ROOT / ".ghidra-query.log"
DEFAULT_IDLE_SECS = 4 * 60 * 60
START_TIMEOUT_SECS = 240
_ACCEPT_POLL_SECS = 30


def encode_request(cmd: str, args: list[str]) -> bytes:
    return (json.dumps({"cmd": cmd, "args": args}) + "\n").encode("utf-8")


def decode_request(line: bytes) -> tuple[str, list[str]]:
    obj = json.loads(line.decode("utf-8"))
    cmd = str(obj.get("cmd", ""))
    args = [str(a) for a in obj.get("args", [])]
    return cmd, args


def encode_response(ok: bool, rc: int, output: str) -> bytes:
    return (json.dumps({"ok": ok, "rc": rc, "output": output}) + "\n").encode("utf-8")


def decode_response(line: bytes) -> dict:
    return json.loads(line.decode("utf-8"))


def _read_line(conn: socket.socket, max_bytes: int = 1 << 22) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if chunk.endswith(b"\n") or total > max_bytes:
            break
    return b"".join(chunks)


def request(cmd: str, args: list[str], timeout: float = 600.0) -> dict | None:
    """Send one request to a running daemon; None when no daemon is listening."""
    if not SOCKET_PATH.exists():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(str(SOCKET_PATH))
            conn.sendall(encode_request(cmd, args))
            conn.shutdown(socket.SHUT_WR)
            line = _read_line(conn)
    except (ConnectionError, socket.timeout, OSError):
        return None
    if not line:
        return None
    try:
        return decode_response(line)
    except json.JSONDecodeError:
        return None


def _cleanup_files() -> None:
    for path in (SOCKET_PATH, PID_PATH):
        with contextlib.suppress(OSError):
            path.unlink()


def serve() -> int:
    from tools.ghidra.query_registry import COMMANDS

    idle_limit = int(os.getenv("GHIDRA_DAEMON_IDLE_SECS", str(DEFAULT_IDLE_SECS)))

    _cleanup_files()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET_PATH))
    server.listen(4)
    server.settimeout(_ACCEPT_POLL_SECS)
    PID_PATH.write_text(str(os.getpid()), encoding="utf-8")

    def _terminate(signum, frame):  # noqa: ARG001 — signal handler signature
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _terminate)

    print(f"[daemon] opening Ghidra project (pid {os.getpid()})...", flush=True)
    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project)
    print("[daemon] ready", flush=True)

    idle_since = time.monotonic()
    try:
        while True:
            try:
                conn, _ = server.accept()
            except socket.timeout:
                if time.monotonic() - idle_since > idle_limit:
                    print("[daemon] idle timeout, exiting", flush=True)
                    return 0
                continue
            idle_since = time.monotonic()
            with conn:
                line = _read_line(conn)
                if not line:
                    continue
                try:
                    cmd, args = decode_request(line)
                except json.JSONDecodeError:
                    conn.sendall(encode_response(False, 2, "malformed request"))
                    continue
                if cmd == "ping":
                    conn.sendall(encode_response(True, 0, "pong"))
                    continue
                if cmd == "shutdown":
                    conn.sendall(encode_response(True, 0, "bye"))
                    return 0
                handler = COMMANDS.get(cmd)
                if handler is None:
                    conn.sendall(encode_response(False, 2, f"unknown command: {cmd}"))
                    continue
                buf = io.StringIO()
                try:
                    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                        rc = int(handler(program, args) or 0)
                    conn.sendall(encode_response(True, rc, buf.getvalue()))
                except Exception as exc:  # noqa: BLE001 — report, keep serving
                    conn.sendall(encode_response(False, 1, buf.getvalue() + f"\nerror: {exc!r}"))
    finally:
        with contextlib.suppress(Exception):
            program.release(consumer)
        with contextlib.suppress(Exception):
            project.close()
        server.close()
        _cleanup_files()


def start() -> int:
    if request("ping", [], timeout=5.0):
        print(f"daemon already running (socket {SOCKET_PATH})")
        return 0
    _cleanup_files()
    with LOG_PATH.open("ab") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "tools.ghidra.daemon", "serve"],
            cwd=ghidra_env.REPO_ROOT,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    print(f"starting daemon (pid {proc.pid}, log {LOG_PATH.name})... ", end="", flush=True)
    deadline = time.monotonic() + START_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            print(f"\ndaemon exited early (rc={proc.returncode}); see {LOG_PATH}")
            return 1
        if request("ping", [], timeout=5.0):
            print("ready")
            return 0
        time.sleep(2)
    print(f"\ntimed out after {START_TIMEOUT_SECS}s; see {LOG_PATH}")
    return 1


def stop(quiet: bool = False) -> int:
    resp = request("shutdown", [], timeout=10.0)
    if resp:
        if not quiet:
            print("daemon stopped")
        # Give the serve loop a moment to unlink its socket/pidfile.
        time.sleep(0.5)
        return 0
    if PID_PATH.exists():
        with contextlib.suppress(ValueError, OSError, ProcessLookupError):
            os.kill(int(PID_PATH.read_text().strip()), signal.SIGTERM)
    _cleanup_files()
    if not quiet:
        print("no daemon was running")
    return 0


def status() -> int:
    if request("ping", [], timeout=5.0):
        pid = PID_PATH.read_text().strip() if PID_PATH.exists() else "?"
        print(f"running (pid {pid}, socket {SOCKET_PATH})")
        return 0
    print("not running")
    return 1


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action == "serve":
        return serve()
    if action == "start":
        return start()
    if action == "stop":
        return stop(quiet="--quiet" in sys.argv[2:])
    if action == "status":
        return status()
    print("usage: daemon start|stop|status|serve", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
