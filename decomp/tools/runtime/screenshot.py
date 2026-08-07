#!/usr/bin/env python3
"""Capture the running game window to a PNG (X11, by window ID — not root grab).

Root-window capture fails with BadMatch under nested/Wayland X servers, and the
window ID goes stale on every relaunch, so the previously-documented recipe was
re-typed by hand each session (xwininfo | grep, then an inline python-xlib
snippet). This automates it: find the largest visible window whose class matches
the game, grab its ZPixmap, save.

Used internally by the semantic runtime runner for best-effort failure artifacts. Its
python-xlib and Pillow dependencies are part of the repository tooling environment, so
failure capture performs no dependency resolution.

usage: screenshot.py [out.png] [--win 0xWINDOWID] [--match imperialism]
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

# Matches xwininfo -tree rows like:
#   0x4a00001 (has no name): ("imperialism.exe" "imperialism.exe")  2560x1440+0+0  +0+0
WININFO_LINE_RE = re.compile(
    r'^\s*(0x[0-9a-f]+)\b.*?\("([^"]*)"[^)]*\).*?\s(\d+)x(\d+)\+', re.IGNORECASE
)


def window_owner_pid(window_id: int) -> int | None:
    completed = subprocess.run(
        ["xprop", "-id", f"0x{window_id:x}", "_NET_WM_PID"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"=\s*(\d+)\s*$", completed.stdout)
    return int(match.group(1)) if match is not None else None


def process_wineprefix(pid: int) -> Path | None:
    try:
        entries = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    except OSError:
        return None
    for entry in entries:
        if entry.startswith(b"WINEPREFIX="):
            return Path(entry.split(b"=", 1)[1].decode(errors="replace")).resolve()
    return None


def select_window(
    rows: str,
    match: str,
    *,
    owner_pid: int | None,
    wineprefix: Path | None,
) -> tuple[int, int, int] | None:
    """Choose the largest matching window whose process ownership is proven."""
    expected_prefix = wineprefix.resolve() if wineprefix is not None else None
    if owner_pid is None and expected_prefix is None:
        return None
    best: tuple[int, int, int] | None = None
    for line in rows.splitlines():
        parsed = WININFO_LINE_RE.match(line)
        if not parsed:
            continue
        win_id_text, wm_class, width, height = parsed.groups()
        if match.lower() not in wm_class.lower():
            continue
        window_id = int(win_id_text, 16)
        pid = window_owner_pid(window_id)
        if pid is None:
            continue
        if owner_pid is not None and pid != owner_pid:
            continue
        if expected_prefix is not None and process_wineprefix(pid) != expected_prefix:
            continue
        w, h = int(width), int(height)
        if w * h < 4:
            continue
        if best is None or w * h > best[1] * best[2]:
            best = (window_id, w, h)
    return best


def find_window(
    match: str, *, owner_pid: int | None = None, wineprefix: Path | None = None
) -> tuple[int, int, int] | None:
    """Return the largest matching X11 window owned by this runtime run."""
    out = subprocess.run(
        ["xwininfo", "-root", "-tree"], capture_output=True, text=True, check=True
    ).stdout
    return select_window(out, match, owner_pid=owner_pid, wineprefix=wineprefix)


def capture(win_id: int, out_path: str) -> tuple[int, int]:
    from PIL import Image
    from Xlib import X, display

    d = display.Display()
    win = d.create_resource_object("window", win_id)
    g = win.get_geometry()
    raw = win.get_image(0, 0, g.width, g.height, X.ZPixmap, 0xFFFFFFFF)
    # 32bpp TrueColor arrives as BGRX.
    Image.frombytes("RGB", (g.width, g.height), raw.data, "raw", "BGRX").save(out_path)
    return g.width, g.height


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out", nargs="?", default="/tmp/imperialism.png")
    ap.add_argument("--win", help="explicit window ID (hex), skips discovery")
    ap.add_argument("--match", default="imperialism", help="window-class substring")
    ap.add_argument("--pid", type=int, help="require the X11 window to belong to this PID")
    ap.add_argument("--wineprefix", type=Path, help="require the owner process to use this WINEPREFIX")
    args = ap.parse_args()

    if args.win:
        win_id = int(args.win, 16)
    else:
        found = find_window(args.match, owner_pid=args.pid, wineprefix=args.wineprefix)
        if found is None:
            print(f"no owned visible window matching '{args.match}' — is the game running?",
                  file=sys.stderr)
            return 1
        win_id, w, h = found
        print(f"window 0x{win_id:x} ({w}x{h})")

    width, height = capture(win_id, args.out)
    print(f"saved {args.out} ({width}x{height})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
