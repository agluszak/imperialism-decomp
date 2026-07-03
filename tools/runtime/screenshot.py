#!/usr/bin/env python3
"""Capture the running game window to a PNG (X11, by window ID — not root grab).

Root-window capture fails with BadMatch under nested/Wayland X servers, and the
window ID goes stale on every relaunch, so the previously-documented recipe was
re-typed by hand each session (xwininfo | grep, then an inline python-xlib
snippet). This automates it: find the largest visible window whose class matches
the game, grab its ZPixmap, save.

Run via `just screenshot [out.png]` — the recipe supplies the python-xlib/pillow
deps with `uv run --with`; they are deliberately not project dependencies.

usage: screenshot.py [out.png] [--win 0xWINDOWID] [--match imperialism]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Matches xwininfo -tree rows like:
#   0x4a00001 (has no name): ("imperialism.exe" "imperialism.exe")  2560x1440+0+0  +0+0
WININFO_LINE_RE = re.compile(
    r'^\s*(0x[0-9a-f]+)\b.*?\("([^"]*)"[^)]*\).*?\s(\d+)x(\d+)\+', re.IGNORECASE
)


def find_window(match: str) -> tuple[int, int, int] | None:
    """Return (window_id, width, height) of the largest matching X11 window."""
    out = subprocess.run(
        ["xwininfo", "-root", "-tree"], capture_output=True, text=True, check=True
    ).stdout
    best: tuple[int, int, int] | None = None
    for line in out.splitlines():
        m = WININFO_LINE_RE.match(line)
        if not m:
            continue
        win_id, wm_class, width, height = m.groups()
        if match.lower() not in wm_class.lower():
            continue
        w, h = int(width), int(height)
        if w * h < 4:  # skip 1x1 helper/IME windows
            continue
        if best is None or w * h > best[1] * best[2]:
            best = (int(win_id, 16), w, h)
    return best


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
    args = ap.parse_args()

    if args.win:
        win_id = int(args.win, 16)
    else:
        found = find_window(args.match)
        if found is None:
            print(f"no visible window matching '{args.match}' — is the game running?",
                  file=sys.stderr)
            return 1
        win_id, w, h = found
        print(f"window 0x{win_id:x} ({w}x{h})")

    width, height = capture(win_id, args.out)
    print(f"saved {args.out} ({width}x{height})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
