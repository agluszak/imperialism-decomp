#!/usr/bin/env python3
"""Bring-up smoke ladder + scripted gdb sessions for the recomp under Wine.

Replaces eyeball-screenshot verification with observable milestones. The
recomp is launched under winedbg's gdb proxy (`winedbg --gdb --no-start`);
real gdb (installed 2026-07-05) connects over TCP and plants tracepoint-style
breakpoints (commands: printf + disable + continue), so the message pump never
stays frozen and each milestone prints exactly once. gdb cannot read PDB
symbols, so milestones are original addresses resolved to recomp VAs via
`just addr` (cached, instant after the first call).

Subcommands:
  run   — the milestone ladder: launch, trace milestones for N seconds,
          screenshot while still running, report + exit code (regression =
          an --expect milestone that did not fire).
  gdb   — same launch plumbing, but run YOUR gdb commands (--script FILE or
          --ex CMD ...). This is the state-forcing hook: `set var`, inferior
          calls, conditional breakpoints, raw memory reads.

Run via `just smoke` / `just gdb-script` — deps (python-xlib, pillow) come
from `uv run --with`; they are deliberately not project dependencies.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
DEFAULT_PORT = 47632

# (name, original address, what reaching it proves). Ordered by startup flow.
MILESTONES = [
    ("dispatch-4c", 0x5D7240, "TViewMgr::DispatchTurnEventSlot4C — turn-event dispatch alive"),
    ("child-realize", 0x48DE00, "TWindow::DispatchSlot9CToLinkedChildren — view tree realizes"),
    ("mcwindow-ctor", 0x493470, "CMcWindow constructed — native paint host exists"),
    ("view-init", 0x483750, "CIncludeView::OnInitialUpdate — CDib + tick timer created"),
    ("on-draw", 0x482C90, "CIncludeView::OnDraw — paint recursion runs"),
    ("picture-blit", 0x48F3C0, "TPicture::ApplyRectSlot110 — picture blit reached"),
    ("dib-blit", 0x47BDE0, "CDib::BlitSurfaceRectSkippingTransparentColor — pixels copied"),
]

# Milestones that current main is known to reach; missing one of these is a
# regression (nonzero exit). Extend as bring-up work lands. mcwindow-ctor is
# deliberately NOT expected: CIncludeView is the startup paint host and no
# CMcWindow is constructed on the way to the title screen (verified 2026-07-05).
DEFAULT_EXPECTED = "dispatch-4c,child-realize,view-init,on-draw,picture-blit,dib-blit"


def game_dir() -> Path:
    orig = os.environ.get("ORIGINAL_BINARY")
    if not orig:
        sys.exit("Set ORIGINAL_BINARY in .env (run through `just smoke`, which loads it)")
    return Path(orig).resolve().parent


def resolve_recomp_addr(orig_addr: int) -> int:
    """Original VA -> recomp VA via `just addr` (reccmp pairing)."""
    out = subprocess.run(
        ["just", "addr", f"0x{orig_addr:08x}"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    ).stdout
    m = re.search(r"recomp (0x[0-9a-f]+)", out)
    if not m:
        sys.exit(f"just addr 0x{orig_addr:08x} produced no recomp address:\n{out}")
    return int(m.group(1), 16)


def kill_stale() -> None:
    subprocess.run(["pkill", "-9", "-f", "Imperialism.exe"], capture_output=True)
    time.sleep(1)
    subprocess.run(["wineserver", "-k"], capture_output=True)
    time.sleep(2)


def launch_proxy(port: int) -> subprocess.Popen:
    """Start the recomp under winedbg's gdb server; wait until it listens.

    winedbg full-buffers its "target remote" announcement when piped, so watch
    /proc/net/tcp for the listener instead of parsing stdout. (Do NOT probe by
    connecting: the proxy serves exactly one connection and quits when it drops —
    a probe connect would consume gdb's slot.)
    """
    recomp = BUILD_DIR / "Imperialism.exe"
    if not recomp.exists():
        sys.exit(f"Missing {recomp} — run 'just build' first.")
    env = dict(os.environ, WINEDEBUG=os.environ.get("WINEDEBUG", "-all"))
    proc = subprocess.Popen(
        ["winedbg", "--gdb", "--no-start", "--port", str(port), str(recomp)],
        cwd=game_dir(), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    hex_port = f":{port:04X} "
    deadline = time.time() + 45
    while time.time() < deadline:
        if proc.poll() is not None:
            sys.exit(f"winedbg --gdb exited early (rc={proc.returncode})")
        for tcp in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                for line in Path(tcp).read_text().splitlines()[1:]:
                    fields = line.split()
                    if fields[1].endswith(hex_port.strip()) and fields[3] == "0A":
                        return proc
            except OSError:
                pass
        time.sleep(0.5)
    proc.kill()
    sys.exit("winedbg --gdb never opened its port (stale wine state? just run-fresh once)")


def run_gdb(port: int, script: str, seconds: float) -> str:
    """Run gdb -batch against the proxy for `seconds`, return its output."""
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(script)
        script_path = f.name
    try:
        proc = subprocess.run(
            ["timeout", "--kill-after=2s", f"{seconds}s",
             "gdb", "-batch", "-nx",
             "-ex", "set pagination off",
             "-ex", "set confirm off",
             "-ex", f"target remote localhost:{port}",
             "-x", script_path],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        return proc.stdout + proc.stderr
    finally:
        os.unlink(script_path)


def ladder_script(addrs: dict[str, int]) -> str:
    lines = []
    for i, (name, _, _) in enumerate(MILESTONES, start=1):
        lines += [
            f"break *0x{addrs[name]:x}",
            f"commands {i}",
            "silent",
            f'printf "MILESTONE {name}\\n"',
            f"disable {i}",
            "continue",
            "end",
        ]
    lines.append("continue")
    return "\n".join(lines) + "\n"


def screenshot_stats(out_png: str) -> str:
    """Capture the game window and measure non-black content."""
    from screenshot import capture, find_window

    found = find_window("imperialism")
    if found is None:
        return "screenshot: no game window found"
    win_id, _, _ = found
    try:
        w, h = capture(win_id, out_png)
    except Exception as exc:  # window can die mid-capture
        return f"screenshot failed: {exc}"

    from PIL import Image

    img = Image.open(out_png).convert("RGB")
    px = img.load()

    def nonblack_pct(x0: int, y0: int, x1: int, y1: int) -> float:
        total = nonblack = 0
        for y in range(y0, min(y1, h), 4):  # 4x4 subsample; plenty for a %-figure
            for x in range(x0, min(x1, w), 4):
                total += 1
                if max(px[x, y]) > 16:
                    nonblack += 1
        return 100.0 * nonblack / max(total, 1)

    whole = nonblack_pct(0, 0, w, h)
    client = nonblack_pct(0, 0, 640, 480)  # recomp places the client view top-left
    return (f"screenshot {out_png} ({w}x{h}): "
            f"non-black {whole:.1f}% of frame, {client:.1f}% of top-left 640x480")


def cmd_run(args) -> int:
    print("resolving milestone addresses (just addr)...")
    addrs = {name: resolve_recomp_addr(orig) for name, orig, _ in MILESTONES}
    for name, orig, _ in MILESTONES:
        print(f"  {name:14s} orig 0x{orig:08x} -> recomp 0x{addrs[name]:08x}")

    kill_stale()
    print(f"launching under gdb proxy on :{args.port} ...")
    proxy = launch_proxy(args.port)

    shot = str(BUILD_DIR / "smoke.png")
    out_holder: dict[str, str] = {}

    import threading

    def gdb_thread():
        out_holder["gdb"] = run_gdb(args.port, ladder_script(addrs), args.seconds)

    t = threading.Thread(target=gdb_thread)
    t.start()
    # Screenshot late in the run window, while the game is still alive.
    time.sleep(max(args.seconds - 5, 5))
    shot_report = screenshot_stats(shot)
    t.join(timeout=args.seconds + 15)
    proxy.kill()
    kill_stale()

    gdb_out = out_holder.get("gdb", "")
    hit = {m for m in (name for name, _, _ in MILESTONES)
           if f"MILESTONE {m}" in gdb_out}
    crash_lines = [l for l in gdb_out.splitlines()
                   if "received signal" in l or "Remote connection closed" in l]

    print("\n=== smoke ladder ===")
    for name, _, proves in MILESTONES:
        mark = "REACHED " if name in hit else "not hit "
        print(f"  [{mark}] {name:14s} {proves}")
    for line in crash_lines[:5]:
        print(f"  [signal ] {line.strip()}")
    print(f"  {shot_report}")

    expected = [e for e in args.expect.split(",") if e]
    missing = [e for e in expected if e not in hit]
    if missing:
        print(f"\nREGRESSION: expected milestone(s) not reached: {', '.join(missing)}")
        print(f"full gdb output tail:\n" + "\n".join(gdb_out.splitlines()[-15:]))
        return 1
    print("\nall expected milestones reached")
    return 0


def cmd_gdb(args) -> int:
    if args.script:
        script = Path(args.script).read_text()
    elif args.ex:
        script = "\n".join(args.ex) + "\n"
    else:
        sys.exit("pass --script FILE or one or more --ex 'gdb command'")
    kill_stale()
    print(f"launching under gdb proxy on :{args.port} ...")
    proxy = launch_proxy(args.port)
    out = run_gdb(args.port, script, args.seconds)
    proxy.kill()
    if not args.keep_running:
        kill_stale()
    print(out)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="milestone smoke ladder")
    p_run.add_argument("--seconds", type=float, default=45,
                       help="how long to let startup run (default 45)")
    p_run.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_run.add_argument("--expect", default=DEFAULT_EXPECTED,
                       help="comma-separated milestones that MUST fire (exit 1 otherwise)")
    p_run.set_defaults(func=cmd_run)

    p_gdb = sub.add_parser("gdb", help="scripted gdb session against the recomp")
    p_gdb.add_argument("--script", help="gdb command file")
    p_gdb.add_argument("--ex", action="append", help="gdb command (repeatable)")
    p_gdb.add_argument("--seconds", type=float, default=30)
    p_gdb.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_gdb.add_argument("--keep-running", action="store_true",
                       help="leave the game process up after gdb exits")
    p_gdb.set_defaults(func=cmd_gdb)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
