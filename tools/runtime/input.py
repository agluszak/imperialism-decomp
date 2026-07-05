#!/usr/bin/env python3
"""Send synthetic mouse/keyboard input to the running game window (XTest).

xdotool is not installed in this sandbox; XTest via python-xlib is, and was
verified live 2026-07-05 (a fake click skipped the original's intro movie).
Coordinates are relative to the discovered game window by default, so scripts
stay valid whether the 640x480 view sits at the frame's top-left (current
recomp) or centered (original).

Run via `just click X Y` / `just key NAME` — the recipes supply python-xlib
with `uv run --with`; it is deliberately not a project dependency.

usage: input.py click X Y [--button 1] [--abs] [--match imperialism]
       input.py move  X Y [--abs] [--match imperialism]
       input.py key   NAME [--match imperialism]   (keysym name, e.g. Return, space, a)
"""

from __future__ import annotations

import argparse
import sys
import time

from screenshot import find_window  # sibling module; sys.path[0] is tools/runtime


def window_origin(win_id: int) -> tuple[int, int]:
    """Absolute screen position of the window's top-left corner."""
    from Xlib import display

    d = display.Display()
    win = d.create_resource_object("window", win_id)
    g = win.get_geometry()
    abs_pos = win.translate_coords(d.screen().root, 0, 0)
    # translate_coords maps root(0,0) into window space; negate to get origin.
    return -abs_pos.x, -abs_pos.y


def resolve_target(args) -> tuple[int, int, int]:
    """Return (win_id, origin_x, origin_y); origin is (0,0) in --abs mode."""
    found = find_window(args.match)
    if found is None:
        print(f"no visible window matching '{args.match}' — is the game running?",
              file=sys.stderr)
        raise SystemExit(1)
    win_id = found[0]
    if getattr(args, "abs", False):
        return win_id, 0, 0
    ox, oy = window_origin(win_id)
    return win_id, ox, oy


def do_click(args) -> None:
    from Xlib import X, display
    from Xlib.ext import xtest

    _, ox, oy = resolve_target(args)
    d = display.Display()
    xtest.fake_input(d, X.MotionNotify, x=ox + args.x, y=oy + args.y)
    d.sync()
    time.sleep(0.05)  # let the pump see the motion before the press
    xtest.fake_input(d, X.ButtonPress, args.button)
    d.sync()
    time.sleep(0.05)
    xtest.fake_input(d, X.ButtonRelease, args.button)
    d.sync()
    print(f"clicked button {args.button} at window-relative ({args.x},{args.y})")


def do_move(args) -> None:
    from Xlib import X, display
    from Xlib.ext import xtest

    _, ox, oy = resolve_target(args)
    d = display.Display()
    xtest.fake_input(d, X.MotionNotify, x=ox + args.x, y=oy + args.y)
    d.sync()
    print(f"moved pointer to window-relative ({args.x},{args.y})")


def do_key(args) -> None:
    from Xlib import X, XK, display
    from Xlib.ext import xtest

    d = display.Display()
    keysym = XK.string_to_keysym(args.name)
    if keysym == 0:
        print(f"unknown keysym '{args.name}'", file=sys.stderr)
        raise SystemExit(1)
    keycode = d.keysym_to_keycode(keysym)
    if keycode == 0:
        print(f"keysym '{args.name}' has no keycode on this display", file=sys.stderr)
        raise SystemExit(1)
    xtest.fake_input(d, X.KeyPress, keycode)
    d.sync()
    time.sleep(0.05)
    xtest.fake_input(d, X.KeyRelease, keycode)
    d.sync()
    print(f"pressed {args.name}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_click = sub.add_parser("click", help="click at window-relative coordinates")
    p_click.add_argument("x", type=int)
    p_click.add_argument("y", type=int)
    p_click.add_argument("--button", type=int, default=1)
    p_click.add_argument("--abs", action="store_true", help="treat X Y as screen coords")
    p_click.add_argument("--match", default="imperialism")
    p_click.set_defaults(func=do_click)

    p_move = sub.add_parser("move", help="move pointer to window-relative coordinates")
    p_move.add_argument("x", type=int)
    p_move.add_argument("y", type=int)
    p_move.add_argument("--abs", action="store_true")
    p_move.add_argument("--match", default="imperialism")
    p_move.set_defaults(func=do_move)

    p_key = sub.add_parser("key", help="press a key by X keysym name")
    p_key.add_argument("name")
    p_key.add_argument("--match", default="imperialism")
    p_key.set_defaults(func=do_key)

    args = ap.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
