#!/usr/bin/env python3
"""Scripted gdb against the recomp via the winedbg gdb proxy."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
DEFAULT_PORT = 47632

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.runtime.display import virtual_display
from tools.runtime.wine import ensure_template_prefix, prefix_environment

_DISPLAY_HANDLES: dict[str, object] = {}
from tools.runtime.debug.session import WineGdbProxy


def game_dir() -> Path:
    original = os.environ.get("ORIGINAL_BINARY")
    if not original:
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    return Path(original).resolve().parent


def create_wine_prefix() -> tuple[Path, dict[str, str]]:
    """Per-invocation WINEPREFIX so concurrent runs never share a wineserver.

    Cloned from the seeded per-Wine-version template (see runtime_tests) —
    ~0.6s instead of a ~6.5s wineboot.

    Honours IMPERIALISM_RUNTIME_DISPLAY the same way the semantic runner does, so a
    debug session can go off-screen instead of mapping a window on the developer's desktop.
    The Xvfb handle is stashed on the returned environment and released by
    shut_down_wine_prefix.
    """
    parent = Path(tempfile.mkdtemp(prefix="imperialism-runtime-wine-"))
    prefix = parent / "prefix"
    environment = prefix_environment(prefix)
    display = virtual_display(environment)
    display.__enter__()
    _DISPLAY_HANDLES[str(prefix)] = display
    template = ensure_template_prefix(
        bool(environment.get("IMPERIALISM_WINE_VIRTUAL_DESKTOP"))
    )
    subprocess.run(
        ["cp", "-a", "--reflink=auto", str(template), str(prefix)],
        check=True,
        capture_output=True,
        timeout=180,
    )
    return parent, environment


def shut_down_wine_prefix(prefix: Path, environment: dict[str, str]) -> None:
    """Scoped cleanup: kill only this run's wineserver, then drop the prefix."""
    subprocess.run(["wineserver", "-k"], env=environment, capture_output=True)
    subprocess.run(
        ["wineserver", "--wait"], env=environment, capture_output=True, timeout=60
    )
    shutil.rmtree(prefix, ignore_errors=True)
    # After wineserver is gone: it has to reach the same X display the run used.
    for key in [k for k in _DISPLAY_HANDLES if k.startswith(str(prefix))]:
        _DISPLAY_HANDLES.pop(key).__exit__(None, None, None)


def launch_proxy(
    port: int, environment: dict[str, str], executable: Path | None = None
) -> WineGdbProxy:
    if executable is None:
        executable = BUILD_DIR / "Imperialism.exe"
    if not executable.exists():
        raise SystemExit(f"Missing {executable}; run `just build` first")
    proxy = WineGdbProxy(executable, game_dir(), environment, port=port)
    proxy.start()
    return proxy


def run_gdb(port: int, script: str, seconds: float) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as script_file:
        script_file.write(script)
        script_path = Path(script_file.name)
    try:
        completed = subprocess.run(
            [
                "timeout",
                "--kill-after=2s",
                f"{seconds}s",
                "gdb",
                "-batch",
                "-nx",
                "-ex",
                "set pagination off",
                "-ex",
                "set confirm off",
                "-ex",
                f"target remote localhost:{port}",
                "-x",
                str(script_path),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.stdout + completed.stderr
    finally:
        script_path.unlink()



def cmd_gdb(args: argparse.Namespace) -> int:
    if args.script:
        script = Path(args.script).read_text(encoding="utf-8")
    elif args.ex:
        script = "\n".join(args.ex) + "\n"
    else:
        raise SystemExit("pass --script FILE or one or more --ex commands")
    prefix, environment = create_wine_prefix()
    proxy = launch_proxy(args.port, environment)
    try:
        print(run_gdb(args.port, script, args.seconds))
    finally:
        if args.keep_running:
            proxy_pid = proxy.process.pid if proxy.process is not None else "unknown"
            print(
                "leaving reconnectable Wine debug target running:\n"
                f"  proxy PID: {proxy_pid}\n"
                f"  reconnect: gdb -ex 'target remote localhost:{args.port}'\n"
                f"  WINEPREFIX={environment['WINEPREFIX']}\n"
                f"  cleanup: WINEPREFIX={environment['WINEPREFIX']} wineserver -k; "
                f"kill {proxy_pid}"
            )
        else:
            proxy.close()
            shut_down_wine_prefix(prefix, environment)
    return 0



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script")
    parser.add_argument("--ex", action="append")
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--keep-running", action="store_true")
    args = parser.parse_args()
    return cmd_gdb(args)


if __name__ == "__main__":
    raise SystemExit(main())
