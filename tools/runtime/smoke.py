#!/usr/bin/env python3
"""Observe recomp runtime milestones through Wine's GDB proxy."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
DEFAULT_PORT = 47632

STARTUP_MILESTONES = [
    ("dispatch-4c", 0x5D7240, "turn-event dispatch alive"),
    ("child-realize", 0x48DE00, "view tree realizes"),
    ("mcwindow-ctor", 0x493470, "native paint host constructed"),
    ("view-init", 0x483750, "main view initialized"),
    ("on-draw", 0x482C90, "paint recursion runs"),
    ("picture-blit", 0x48F3C0, "picture blit reached"),
    ("dib-blit", 0x47BDE0, "pixels copied"),
]

DEFAULT_EXPECTED = "dispatch-4c,child-realize,view-init,on-draw,picture-blit,dib-blit"


def game_dir() -> Path:
    original = os.environ.get("ORIGINAL_BINARY")
    if not original:
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    return Path(original).resolve().parent


def resolve_recomp_addr(original_address: int) -> int:
    completed = subprocess.run(
        ["just", "addr", f"0x{original_address:08x}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"recomp (0x[0-9a-f]+)", completed.stdout)
    if not match:
        raise SystemExit(
            f"just addr 0x{original_address:08x} produced no recomp address:\n"
            f"{completed.stdout}{completed.stderr}"
        )
    return int(match.group(1), 16)


def create_wine_prefix() -> tuple[Path, dict[str, str]]:
    """Per-invocation WINEPREFIX so concurrent runs never share a wineserver."""
    prefix = Path(tempfile.mkdtemp(prefix="imperialism-smoke-wine-"))
    environment = dict(os.environ, WINEDEBUG=os.environ.get("WINEDEBUG", "-all"))
    environment["WINEPREFIX"] = str(prefix)
    # Skip the Mono/Gecko installers in the fresh prefix.
    environment.setdefault("WINEDLLOVERRIDES", "mscoree,mshtml=")
    subprocess.run(
        ["wineboot", "--init"],
        env=environment,
        check=True,
        capture_output=True,
        timeout=180,
    )
    # First-run settings the game otherwise prompts for: without a saved AutoRes,
    # ShowAutoResolutionDialogIfNeeded (ImperialismApp.cpp) blocks startup on a
    # modal resolution dialog; Language pins deterministic .irg selection.
    settings_key = "HKCU\\Software\\SSI\\Imperialism\\Settings"
    for value_args in (
        ["/v", "AutoRes", "/t", "REG_DWORD", "/d", "0"],
        ["/v", "Language", "/d", "ENGLISH"],
    ):
        subprocess.run(
            ["wine", "reg", "add", settings_key, *value_args, "/f"],
            env=environment,
            check=True,
            capture_output=True,
            timeout=60,
        )
    subprocess.run(
        ["wineserver", "--wait"],
        env=environment,
        capture_output=True,
        timeout=180,
    )
    return prefix, environment


def shut_down_wine_prefix(prefix: Path, environment: dict[str, str]) -> None:
    """Scoped cleanup: kill only this run's wineserver, then drop the prefix."""
    subprocess.run(["wineserver", "-k"], env=environment, capture_output=True)
    subprocess.run(
        ["wineserver", "--wait"], env=environment, capture_output=True, timeout=60
    )
    shutil.rmtree(prefix, ignore_errors=True)


def launch_proxy(port: int, environment: dict[str, str]) -> subprocess.Popen[bytes]:
    executable = BUILD_DIR / "Imperialism.exe"
    if not executable.exists():
        raise SystemExit(f"Missing {executable}; run `just build` first")
    process = subprocess.Popen(
        ["winedbg", "--gdb", "--no-start", "--port", str(port), str(executable)],
        cwd=game_dir(),
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    port_suffix = f":{port:04X}"
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"winedbg --gdb exited early with {process.returncode}")
        for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
            try:
                lines = table.read_text(encoding="ascii").splitlines()[1:]
            except OSError:
                continue
            if any(
                fields[1].endswith(port_suffix) and fields[3] == "0A"
                for line in lines
                if len(fields := line.split()) >= 4
            ):
                return process
        time.sleep(0.5)
    process.kill()
    raise SystemExit("winedbg --gdb did not open its port")


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


def ladder_script(addresses: dict[str, int]) -> str:
    lines: list[str] = []
    for index, (name, _, _) in enumerate(STARTUP_MILESTONES, start=1):
        lines.extend(
            [
                f"break *0x{addresses[name]:x}",
                f"commands {index}",
                "silent",
                f'printf "MILESTONE {name}\\n"',
                f"disable {index}",
                "continue",
                "end",
            ]
        )
    lines.extend(["handle SIGSEGV nostop print pass", "continue"])
    return "\n".join(lines) + "\n"


def cmd_run(args: argparse.Namespace) -> int:
    addresses = {
        name: resolve_recomp_addr(original) for name, original, _ in STARTUP_MILESTONES
    }
    for name, original, _ in STARTUP_MILESTONES:
        print(f"{name:14s} orig 0x{original:08x} -> recomp 0x{addresses[name]:08x}")

    prefix, environment = create_wine_prefix()
    proxy = launch_proxy(args.port, environment)
    try:
        output = run_gdb(args.port, ladder_script(addresses), args.seconds)
    finally:
        proxy.kill()
        shut_down_wine_prefix(prefix, environment)

    reached = {
        name for name, _, _ in STARTUP_MILESTONES if f"MILESTONE {name}" in output
    }
    print("\n=== startup smoke milestones ===")
    for name, _, meaning in STARTUP_MILESTONES:
        print(f"  [{'REACHED' if name in reached else 'missing'}] {name:14s} {meaning}")

    expected = [name for name in args.expect.split(",") if name]
    missing = [name for name in expected if name not in reached]
    crash_lines = [
        line
        for line in output.splitlines()
        if "received signal" in line or "Remote connection closed" in line
    ]
    if missing or crash_lines:
        if missing:
            print(f"missing milestone(s): {', '.join(missing)}")
        for line in crash_lines[:5]:
            print(line)
        return 1
    return 0


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
        proxy.kill()
        if args.keep_running:
            print(f"leaving Wine session running in WINEPREFIX={prefix}")
        else:
            shut_down_wine_prefix(prefix, environment)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="observe startup milestones")
    run.add_argument("--seconds", type=float, default=45)
    run.add_argument("--port", type=int, default=DEFAULT_PORT)
    run.add_argument("--expect", default=DEFAULT_EXPECTED)
    run.set_defaults(func=cmd_run)

    gdb = commands.add_parser("gdb", help="run a custom observer script")
    gdb.add_argument("--script")
    gdb.add_argument("--ex", action="append")
    gdb.add_argument("--seconds", type=float, default=30)
    gdb.add_argument("--port", type=int, default=DEFAULT_PORT)
    gdb.add_argument("--keep-running", action="store_true")
    gdb.set_defaults(func=cmd_gdb)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
