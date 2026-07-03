#!/usr/bin/env python3
"""Long-lived Ghidra inspection daemon.

Starts pyghidra and opens the vendored project/program *once*, then serves read-only
inspection commands over a Unix-domain socket. Each request runs one of the existing
`tools/ghidra/*` entrypoints in-process against the already-open program (their
open_project/open_program transparently return the shared instance via
`ghidra_env.install_shared`), so callers skip the ~10-20s JVM + project-load cost on
every `just ghidra-*` invocation.

Protocol (one request per connection): the client sends a single JSON line
    {"cmd": "listing", "args": ["0x52a670"]}
and reads the JSON response back until EOF:
    {"ok": true, "rc": 0, "out": "...", "err": ""}

Control commands: {"cmd": "ping"} and {"cmd": "shutdown"}.

The daemon holds the project open, so mutating tools (sync-ghidra, apply-*, export-project)
that need exclusive write access must stop it first (`just ghidra-daemon-stop`).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import socket
import sys
import traceback
from pathlib import Path

from tools.common import ghidra_env

# Friendly command name -> module path providing a `main() -> int` entrypoint.
COMMANDS = {
    "listing": "tools.ghidra.listing_one",
    "decompile": "tools.ghidra.decompile_one",
    "raw-disasm": "tools.ghidra.raw_disasm",
    "linear-disasm": "tools.ghidra.linear_disasm",
    "vtable-dump": "tools.ghidra.vtable_dump",
    "xrefs": "tools.ghidra.xrefs",
    "search": "tools.ghidra.search_whole_binary",
    "function-slice": "tools.ghidra.function_slice",
}
# Note: tools that read addresses from stdin (scan_cdecl_thiscall) are intentionally NOT
# served here — the daemon runs in its own process and can't see the client's stdin.

_MODULE_CACHE: dict[str, object] = {}


def _import(module_path: str):
    mod = _MODULE_CACHE.get(module_path)
    if mod is None:
        import importlib

        mod = importlib.import_module(module_path)
        _MODULE_CACHE[module_path] = mod
    return mod


def _run_command(cmd: str, args: list[str]) -> dict:
    module_path = COMMANDS.get(cmd)
    if module_path is None:
        return {"ok": False, "rc": 2, "out": "", "err": f"unknown command: {cmd!r}"}

    mod = _import(module_path)
    out_buf, err_buf = io.StringIO(), io.StringIO()
    saved_argv = sys.argv
    sys.argv = [cmd, *args]
    rc = 0
    try:
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            result = mod.main()
            rc = int(result) if result is not None else 0
    except SystemExit as exc:  # tools that call sys.exit()
        rc = int(exc.code) if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except Exception:  # noqa: BLE001 - surface any tool error to the client
        return {
            "ok": False,
            "rc": 1,
            "out": out_buf.getvalue(),
            "err": err_buf.getvalue() + traceback.format_exc(),
        }
    finally:
        sys.argv = saved_argv
    return {"ok": rc == 0, "rc": rc, "out": out_buf.getvalue(), "err": err_buf.getvalue()}


def _serve(sock: socket.socket, sock_path: Path) -> None:
    running = True
    while running:
        conn, _ = sock.accept()
        try:
            chunks = []
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
            raw = b"".join(chunks).split(b"\n", 1)[0]
            if not raw.strip():
                continue
            try:
                req = json.loads(raw.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                resp = {"ok": False, "rc": 2, "out": "", "err": f"bad request: {exc}"}
                conn.sendall(json.dumps(resp).encode("utf-8"))
                continue

            cmd = req.get("cmd", "")
            if cmd == "ping":
                conn.sendall(json.dumps({"ok": True, "rc": 0, "out": "pong", "err": ""}).encode())
                continue
            if cmd == "shutdown":
                conn.sendall(json.dumps({"ok": True, "rc": 0, "out": "bye", "err": ""}).encode())
                running = False
                continue

            resp = _run_command(cmd, list(req.get("args", [])))
            conn.sendall(json.dumps(resp).encode("utf-8"))
        finally:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_WR)
            conn.close()


def main() -> int:
    sock_path = ghidra_env.socket_path()

    # Refuse to start if another live daemon already owns the socket.
    if sock_path.exists():
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(str(sock_path))
            probe.sendall(b'{"cmd": "ping"}\n')
            probe.close()
            print(f"daemon already running at {sock_path}", file=sys.stderr)
            return 0
        except OSError:
            sock_path.unlink(missing_ok=True)  # stale socket
        finally:
            probe.close()

    print("starting Ghidra daemon: loading project (this pays the one-time cost)...",
          file=sys.stderr, flush=True)
    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project)
    ghidra_env.install_shared(project, program)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(str(sock_path))
    sock.listen(16)

    def _cleanup(*_a):
        with contextlib.suppress(Exception):
            program.release(consumer)
        with contextlib.suppress(Exception):
            project.close()
        with contextlib.suppress(OSError):
            sock.close()
        with contextlib.suppress(OSError):
            sock_path.unlink(missing_ok=True)

    signal.signal(signal.SIGTERM, lambda *_a: (_cleanup(), os._exit(0)))
    signal.signal(signal.SIGINT, lambda *_a: (_cleanup(), os._exit(0)))

    print(f"Ghidra daemon ready (pid {os.getpid()}) at {sock_path}", file=sys.stderr, flush=True)
    try:
        _serve(sock, sock_path)
    finally:
        _cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
