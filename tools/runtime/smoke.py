#!/usr/bin/env python3
"""Observe recomp runtime milestones through Wine's GDB proxy."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
DEFAULT_PORT = 47632

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.runtime.wine import ensure_template_prefix, prefix_environment

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


def resolve_recomp_addr(original_address: int) -> int | None:
    """Original -> recomp address, or None when reccmp's report drops the
    pairing (known report-pairing gap; see the addr_translate fallback bead)."""
    completed = subprocess.run(
        ["just", "addr", f"0x{original_address:08x}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"recomp (0x[0-9a-f]+)", completed.stdout)
    if not match:
        print(f"WARNING: no recomp pairing for 0x{original_address:08x}; milestone untracked")
        return None
    return int(match.group(1), 16)


def create_wine_prefix() -> tuple[Path, dict[str, str]]:
    """Per-invocation WINEPREFIX so concurrent runs never share a wineserver.

    Cloned from the seeded per-Wine-version template (see runtime_tests) —
    ~0.6s instead of a ~6.5s wineboot.
    """
    parent = Path(tempfile.mkdtemp(prefix="imperialism-smoke-wine-"))
    prefix = parent / "prefix"
    template = ensure_template_prefix()
    subprocess.run(
        ["cp", "-a", "--reflink=auto", str(template), str(prefix)],
        check=True,
        capture_output=True,
        timeout=180,
    )
    return parent, prefix_environment(prefix)


def shut_down_wine_prefix(prefix: Path, environment: dict[str, str]) -> None:
    """Scoped cleanup: kill only this run's wineserver, then drop the prefix."""
    subprocess.run(["wineserver", "-k"], env=environment, capture_output=True)
    subprocess.run(
        ["wineserver", "--wait"], env=environment, capture_output=True, timeout=60
    )
    shutil.rmtree(prefix, ignore_errors=True)


def launch_proxy(
    port: int, environment: dict[str, str], executable: Path | None = None
) -> subprocess.Popen[bytes]:
    if executable is None:
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
    tracked = [entry for entry in STARTUP_MILESTONES if entry[0] in addresses]
    for index, (name, _, _) in enumerate(tracked, start=1):
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


def run_milestone_ladder(
    binary: str, port: int, seconds: float
) -> tuple[set[str], set[str], str]:
    """Run the startup ladder against one binary.

    Returns (reached, tracked, gdb_output): milestones whose breakpoints
    fired, the ones that could be armed at all, and the raw session output.
    `binary` is "recomp" (build-msvc500, addresses translated through reccmp)
    or "original" (the retail exe, milestone addresses used verbatim).
    """
    if binary == "original":
        executable = Path(os.environ["ORIGINAL_BINARY"]).resolve()
        addresses = {name: original for name, original, _ in STARTUP_MILESTONES}
    else:
        executable = None
        addresses = {
            name: resolved
            for name, original, _ in STARTUP_MILESTONES
            if (resolved := resolve_recomp_addr(original)) is not None
        }
    for name, original, _ in STARTUP_MILESTONES:
        target = f"0x{addresses[name]:08x}" if name in addresses else "(untracked)"
        print(f"{name:14s} orig 0x{original:08x} -> {binary} {target}")

    prefix, environment = create_wine_prefix()
    proxy = launch_proxy(port, environment, executable)
    try:
        output = run_gdb(port, ladder_script(addresses), seconds)
    finally:
        proxy.kill()
        shut_down_wine_prefix(prefix, environment)
    reached = {name for name in addresses if f"MILESTONE {name}" in output}
    return reached, set(addresses), output


def cmd_diff(args: argparse.Namespace) -> int:
    """Differential startup oracle: the retail binary's reached milestones are
    the expectation; the recomp must reach every one of them."""
    original, _, _ = run_milestone_ladder("original", args.port, args.seconds)
    recomp, recomp_tracked, _ = run_milestone_ladder(
        "recomp", args.port + 1, args.seconds
    )
    print("\n=== differential startup milestones (original vs recomp) ===")
    regressions = []
    for name, _, meaning in STARTUP_MILESTONES:
        orig_mark = "REACHED" if name in original else "missing"
        if name not in recomp_tracked:
            recomp_mark = "untrackd"
        elif name in recomp:
            recomp_mark = "REACHED"
        else:
            recomp_mark = "missing"
        print(f"  orig[{orig_mark:7s}] recomp[{recomp_mark:8s}] {name:14s} {meaning}")
        if name in original and name in recomp_tracked and name not in recomp:
            regressions.append(name)
    if regressions:
        print(f"recomp missing milestone(s) the original reaches: {', '.join(regressions)}")
        return 1
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    reached, tracked, output = run_milestone_ladder("recomp", args.port, args.seconds)
    print("\n=== startup smoke milestones ===")
    for name, _, meaning in STARTUP_MILESTONES:
        if name not in tracked:
            mark = "untrackd"
        else:
            mark = "REACHED" if name in reached else "missing"
        print(f"  [{mark:8s}] {name:14s} {meaning}")

    expected = [name for name in args.expect.split(",") if name]
    untracked = [name for name in expected if name not in tracked]
    if untracked:
        print(
            "untracked expected milestone(s) (no reccmp pairing, not enforced): "
            + ", ".join(untracked)
        )
    missing = [name for name in expected if name in tracked and name not in reached]
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
            print(
                "leaving Wine session running in "
                f"WINEPREFIX={environment['WINEPREFIX']}"
            )
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

    diff = commands.add_parser(
        "diff", help="differential startup oracle: original vs recomp milestones"
    )
    diff.add_argument("--seconds", type=float, default=45)
    diff.add_argument("--port", type=int, default=DEFAULT_PORT)
    diff.set_defaults(func=cmd_diff)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
