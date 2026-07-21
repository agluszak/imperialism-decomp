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
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
DEFAULT_PORT = 47632

# (name, original address, what reaching it proves). Ordered by runtime flow.
STARTUP_MILESTONES = [
    ("dispatch-4c", 0x5D7240, "TViewMgr::DispatchTurnEventSlot4C — turn-event dispatch alive"),
    ("child-realize", 0x48DE00, "TWindow::Open — view tree realizes"),
    ("mcwindow-ctor", 0x493470, "CMcWindow constructed — native paint host exists"),
    ("view-init", 0x483750, "CIncludeView::OnInitialUpdate — CDib + tick timer created"),
    ("on-draw", 0x482C90, "CIncludeView::OnDraw — paint recursion runs"),
    ("picture-blit", 0x48F3C0, "TPicture::Draw — picture blit reached"),
    ("dib-blit", 0x47BDE0, "CDib::BlitSurfaceRectSkippingTransparentColor — pixels copied"),
]

RANDOM_GAME_MILESTONES = [
    ("start-game", 0x577E40, "TSetupRandomMapPicture::StartGame — Start accepted"),
    ("rebuild-nations", 0x57CAD0,
     "TSimMgr::RebuildNationStateSlotsAndAvailability — nation construction entered"),
    ("dispatch-map", 0x5D7240,
     "TViewMgr::DispatchTurnEventSlot4C — event 0x3b8 observed"),
    ("include-lifecycle", 0x48CFD0, "TIncludeView::DoPostCreate — factory tree attached"),
    ("map-lifecycle", 0x596A80,
     "TMapUberPicture::DoPostCreate — strategic-map root initialized"),
    ("map-dialog-ctor", 0x519B50, "TMapDialog::TMapDialog — map dialog constructed"),
    ("create-tool-window", 0x599CF0,
     "TMapUberPicture::CreateToolWindow — tool/minimap construction entered"),
]

LADDERS = {
    "startup": STARTUP_MILESTONES,
    "random-game": RANDOM_GAME_MILESTONES,
}

# Milestones that current main is known to reach; missing one of these is a
# regression (nonzero exit). Extend as bring-up work lands. mcwindow-ctor is
# deliberately NOT expected: CIncludeView is the startup paint host and no
# CMcWindow is constructed on the way to the title screen (verified 2026-07-05).
DEFAULT_EXPECTED = "dispatch-4c,child-realize,view-init,on-draw,picture-blit,dib-blit"
RANDOM_GAME_EXPECTED = ",".join(name for name, _, _ in RANDOM_GAME_MILESTONES)

DISPATCH_EVENT_RE = re.compile(
    r"EVENT dispatch-4c eventCode=0x([0-9a-fA-F]+) payload=0x([0-9a-fA-F]+)"
)


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


def run_gdb(port: int, script: str, seconds: float, on_line=None) -> str:
    """Run gdb -batch against the proxy for `seconds`, streaming its output."""
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(script)
        script_path = f.name
    try:
        proc = subprocess.Popen(
            ["timeout", "--kill-after=2s", f"{seconds}s",
             "gdb", "-batch", "-nx",
             "-ex", "set pagination off",
             "-ex", "set confirm off",
             "-ex", f"target remote localhost:{port}",
             "-x", script_path],
            cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        output = []
        assert proc.stdout is not None
        for line in proc.stdout:
            output.append(line)
            if on_line is not None:
                on_line(line.rstrip("\n"))
        proc.wait()
        return "".join(output)
    finally:
        os.unlink(script_path)


def ladder_script(milestones, addrs: dict[str, int], trace_dispatch: bool = False,
                  automation_addrs: dict[str, int] | None = None) -> str:
    lines = []
    for i, (name, _, _) in enumerate(milestones, start=1):
        lines += [f"break *0x{addrs[name]:x}", f"commands {i}", "silent"]
        if trace_dispatch and name == "dispatch-map":
            lines += [
                "set $eventCode = *(unsigned int*)($esp + 4)",
                "set $payload = *(unsigned int*)($esp + 8)",
                'printf "EVENT dispatch-4c eventCode=0x%x payload=0x%x\\n", '
                "$eventCode, $payload",
                "if $eventCode == 0x3b8",
                f'  printf "MILESTONE {name}\\n"',
                f"  disable {i}",
                "end",
            ]
        else:
            lines += [f'printf "MILESTONE {name}\\n"', f"disable {i}"]
        lines += ["continue", "end"]
    for i, (name, address) in enumerate((automation_addrs or {}).items(),
                                        start=len(milestones) + 1):
        lines += [
            f"break *0x{address:x}",
            f"commands {i}",
            "silent",
            f'printf "AUTOMATION {name}\\n"',
            f"disable {i}",
            "continue",
            "end",
        ]
    # Wine translates Windows access violations through SIGSEGV. Log them but
    # let Wine's SEH run so the ladder can reveal later milestones; any signal
    # still fails the smoke acceptance below.
    lines.append("handle SIGSEGV nostop print pass")
    lines.append("continue")
    return "\n".join(lines) + "\n"


def click_window(x: int, y: int) -> None:
    """Use the sibling XTest driver without starting another uv environment."""
    import input as input_driver

    args = argparse.Namespace(x=x, y=y, button=1, abs=False, match="imperialism")
    input_driver.do_click(args)


def click_window_when_available(x: int, y: int, timeout: float = 10) -> None:
    from screenshot import find_window

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if find_window("imperialism") is not None:
            click_window(x, y)
            return
        time.sleep(0.5)
    raise RuntimeError("game window unavailable for scripted click")


def click_window_center() -> None:
    from screenshot import find_window

    found = find_window("imperialism")
    if found is None:
        raise RuntimeError("no game window found for intro click")
    _, width, height = found
    click_window_when_available(width // 2, height // 2)


def drive_random_game(dispatch_events: dict[int, threading.Event], setup_ready: threading.Event,
                      difficulty: int, failures: list[str]) -> None:
    """Drive intro -> main menu -> random setup from observed dispatch events."""
    try:
        if not dispatch_events[0x11F8].wait(35):
            raise RuntimeError("title/intro event 0x11f8 was not observed")
        time.sleep(2)
        click_window_center()

        if not dispatch_events[0x5DC].wait(20):
            raise RuntimeError("main-menu event 0x5dc was not observed after intro click")
        time.sleep(2)
        # Event 0x5dc's 'rand' control: (0x0e,0xd1) size (0x8a,0xab).
        click_window_when_available(0x0E + 0x8A // 2, 0xD1 + 0xAB // 2)

        if not dispatch_events[0x5DD].wait(20):
            raise RuntimeError("random-map event 0x5dd was not observed after Random click")
        if not setup_ready.wait(20):
            raise RuntimeError("random-map setup lifecycle did not finish after event 0x5dd")
        time.sleep(1)
        # 'stuf' begins at (0x120,4); 'diff' begins at (0x19,0x12a), and
        # each 0x10-high 'difN' row begins at y=2 + N*0x10.
        difficulty_x = 0x120 + 0x19 + 0x20
        difficulty_y = 4 + 0x12A + 2 + difficulty * 0x10 + 8
        click_window_when_available(difficulty_x, difficulty_y)
        time.sleep(0.5)
        # 'okay' under 'stuf': (0x80,0x1a2) size (0x60,0x1e).
        click_window_when_available(0x120 + 0x80 + 0x60 // 2, 4 + 0x1A2 + 0x1E // 2)
    except (Exception, SystemExit) as exc:
        failures.append(str(exc))


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
    milestones = LADDERS[args.ladder]
    seconds = args.seconds
    if seconds is None:
        seconds = 90 if args.ladder == "random-game" else 45
    expected_csv = args.expect
    if expected_csv is None:
        expected_csv = RANDOM_GAME_EXPECTED if args.ladder == "random-game" else DEFAULT_EXPECTED

    print("resolving milestone addresses (just addr)...")
    addrs = {name: resolve_recomp_addr(orig) for name, orig, _ in milestones}
    automation_addrs = {}
    if args.ladder == "random-game":
        automation_addrs["random-setup-ready"] = resolve_recomp_addr(0x577030)
    for name, orig, _ in milestones:
        print(f"  {name:14s} orig 0x{orig:08x} -> recomp 0x{addrs[name]:08x}")

    kill_stale()
    print(f"launching under gdb proxy on :{args.port} ...")
    proxy = launch_proxy(args.port)

    shot = str(BUILD_DIR / "smoke.png")
    out_holder: dict[str, str] = {}
    milestone_events = {name: threading.Event() for name, _, _ in milestones}
    milestone_times: dict[str, float] = {}
    dispatch_events = {code: threading.Event() for code in (0x11F8, 0x5DC, 0x5DD, 0x3B8)}
    dispatch_args: list[tuple[int, int]] = []
    input_failures: list[str] = []
    gdb_done = threading.Event()
    setup_ready = threading.Event()

    def on_gdb_line(line: str) -> None:
        if line.startswith("MILESTONE "):
            name = line.split(None, 1)[1]
            if name in milestone_events:
                milestone_times.setdefault(name, time.monotonic())
                milestone_events[name].set()
        elif line == "AUTOMATION random-setup-ready":
            setup_ready.set()
        match = DISPATCH_EVENT_RE.search(line)
        if match:
            event_code = int(match.group(1), 16)
            payload = int(match.group(2), 16)
            dispatch_args.append((event_code, payload))
            if event_code in dispatch_events:
                dispatch_events[event_code].set()

    def gdb_thread():
        try:
            out_holder["gdb"] = run_gdb(
                args.port,
                ladder_script(
                    milestones,
                    addrs,
                    trace_dispatch=args.ladder == "random-game",
                    automation_addrs=automation_addrs,
                ),
                seconds,
                on_gdb_line,
            )
        except Exception as exc:
            out_holder["gdb-error"] = str(exc)
        finally:
            gdb_done.set()

    t = threading.Thread(target=gdb_thread)
    t.start()

    driver = None
    if args.ladder == "random-game":
        driver = threading.Thread(
            target=drive_random_game,
            args=(dispatch_events, setup_ready, args.difficulty, input_failures),
        )
        driver.start()
        # Capture immediately after the map root lifecycle. If it never fires,
        # retain a late diagnostic screenshot of whatever screen was reached.
        screenshot_deadline = time.monotonic() + max(seconds - 10, 5)
        while (not milestone_events["map-lifecycle"].is_set() and
               not gdb_done.is_set() and time.monotonic() < screenshot_deadline):
            milestone_events["map-lifecycle"].wait(0.5)
        time.sleep(1)
    else:
        # Screenshot late in the startup run window, while the game is still alive.
        time.sleep(max(seconds - 5, 5))
    shot_report = screenshot_stats(shot)

    alive_30_seconds = True
    if args.ladder == "random-game":
        start_time = milestone_times.get("start-game")
        if start_time is not None:
            remaining = 30 - (time.monotonic() - start_time)
            if remaining > 0:
                time.sleep(remaining)
            alive_30_seconds = t.is_alive() and proxy.poll() is None
        else:
            alive_30_seconds = False

    t.join(timeout=seconds + 15)
    if driver is not None:
        driver.join(timeout=1)
    proxy.kill()
    kill_stale()

    gdb_out = out_holder.get("gdb", "")
    hit = {m for m in (name for name, _, _ in milestones)
           if f"MILESTONE {m}" in gdb_out}
    crash_lines = [l for l in gdb_out.splitlines()
                   if "received signal" in l or "Remote connection closed" in l]

    print("\n=== smoke ladder ===")
    for name, _, proves in milestones:
        mark = "REACHED " if name in hit else "not hit "
        print(f"  [{mark}] {name:14s} {proves}")
    if args.ladder == "random-game":
        for event_code, payload in dispatch_args:
            print(f"  [dispatch] eventCode=0x{event_code:x} payload=0x{payload:x}")
        print(f"  [{'alive  ' if alive_30_seconds else 'not alive'}] process 30s after Start")
        for failure in input_failures:
            print(f"  [input  ] {failure}")
    if "gdb-error" in out_holder:
        print(f"  [gdb    ] {out_holder['gdb-error']}")
    for line in crash_lines[:5]:
        print(f"  [signal ] {line.strip()}")
    print(f"  {shot_report}")

    expected = [e for e in expected_csv.split(",") if e]
    missing = [e for e in expected if e not in hit]
    if (missing or input_failures or not alive_30_seconds or crash_lines or
            "gdb-error" in out_holder):
        reasons = []
        if missing:
            reasons.append(f"missing milestone(s): {', '.join(missing)}")
        if input_failures:
            reasons.append("input automation failed")
        if not alive_30_seconds:
            reasons.append("process did not remain alive for 30 seconds after Start")
        if crash_lines:
            reasons.append("debugger observed a signal")
        if "gdb-error" in out_holder:
            reasons.append("gdb worker failed")
        print(f"\nREGRESSION: {'; '.join(reasons)}")
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
    p_run.add_argument("--ladder", choices=sorted(LADDERS), default="startup",
                       help="milestone ladder to run (default startup)")
    p_run.add_argument("--seconds", type=float,
                       help="run deadline (default 45s startup, 90s random-game)")
    p_run.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_run.add_argument("--expect",
                       help="comma-separated milestones that MUST fire (exit 1 otherwise)")
    p_run.add_argument("--difficulty", type=int, choices=(2, 3, 4), default=2,
                       help="random-game difficulty (default 2; deterministic 0x3b8 route)")
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
