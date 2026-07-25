"""Off-screen X display for runtime-test sessions.

Wine maps a real window for every run. On a developer's desktop that steals focus for
the second or two the game lives, which makes the suite unusable while working -- and on
a headless host (CI, a cloud session) there is no display to map into at all. Both are
solved the same way: give each session its own Xvfb server and point `DISPLAY` at it.

Selected with `IMPERIALISM_RUNTIME_DISPLAY`:

  virtual   private Xvfb per session (off-screen; needs an Xvfb binary on PATH)
  host      the inherited DISPLAY -- the default, and what CI-less desktops get today
  :5        a specific display that is already running

Off-screen runs seed `Managed=N` into the prefix (see tools/runtime/wine.py). With no
window manager present, Wine's managed-window path waits on a WM that never answers;
owning its windows outright is what makes the game paint normally, and it fixed the
whole render-cache failure class off-screen.

**The default is still `host`.** Two scenarios that pick a capital by screen coordinate
-- `random_game_enters_map` and `save_load_roundtrip` -- select a slightly different
tile off-screen, because window decorations shift the mapping from pixel to tile. Their
map-state expectations are therefore display-specific, and the difference is real game
state (a few terrain counts move) rather than a harness artifact. Committing a second
set of expectations would just move the problem, so the honest fix is to make those
scenarios address tiles rather than pixels. Tracked as imperialism-decomp-0kr0.

Everything else passes off-screen: the whole serialization suite, load_saved_game,
random_game_easy_skips_capital, and the manager/boot tests -- the ones worth running
repeatedly while working. `just test` uses the virtual display unconditionally.

Screenshots keep working: `tools.runtime.screenshot` captures by window id against
whatever `DISPLAY` names, so it reads the virtual server without changes.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
import shutil
import subprocess
import time

# Xvfb writes the display number it chose to a pipe, which avoids racing another
# session for a hard-coded number -- several runtime tests can run concurrently.
# `pass_fds` keeps the descriptor at its original number in the child, so that number
# is what -displayfd receives; there is no need to renumber it.
_STARTUP_TIMEOUT_SECONDS = 10.0
_SCREEN_GEOMETRY = "1920x1080x24"


def _xvfb_binary() -> str | None:
    return shutil.which("Xvfb")


@contextmanager
def virtual_display(environment: dict[str, str], log_path: Path | None = None):
    """Point `environment["DISPLAY"]` at a private Xvfb for the duration.

    Yields the display string in use, or None when running on the host display. Never
    fails the run: if Xvfb cannot start, the session falls back to the inherited
    DISPLAY, because a missing off-screen server is a comfort problem, not a
    correctness one.
    """
    requested = os.environ.get("IMPERIALISM_RUNTIME_DISPLAY", "host").strip() or "host"
    if requested == "host":
        yield None
        return
    if requested.startswith(":"):
        environment["DISPLAY"] = requested
        yield requested
        return
    if requested != "virtual":
        raise SystemExit(
            "IMPERIALISM_RUNTIME_DISPLAY must be 'virtual', 'host' or a display like ':5'; "
            f"got {requested!r}"
        )

    binary = _xvfb_binary()
    if binary is None:
        yield None
        return

    log_handle = log_path.open("wb") if log_path is not None else None
    read_fd, write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        os.set_inheritable(write_fd, True)
        process = subprocess.Popen(
            [
                binary,
                "-displayfd",
                str(write_fd),
                "-screen",
                "0",
                _SCREEN_GEOMETRY,
                "-nolisten",
                "tcp",
            ],
            pass_fds=(write_fd,),
            stdout=log_handle if log_handle is not None else subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        os.close(write_fd)
        write_fd = -1

        display_number = _read_display_number(read_fd, process)
        if display_number is None:
            yield None
            return

        display = f":{display_number}"
        environment["DISPLAY"] = display
        environment["IMPERIALISM_WINE_VIRTUAL_DESKTOP"] = "1"
        try:
            yield display
        finally:
            environment.pop("DISPLAY", None)
            environment.pop("IMPERIALISM_WINE_VIRTUAL_DESKTOP", None)
    finally:
        if write_fd != -1:
            os.close(write_fd)
        os.close(read_fd)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if log_handle is not None:
            log_handle.close()


def _read_display_number(read_fd: int, process: subprocess.Popen[bytes]) -> str | None:
    """Wait for Xvfb to announce its display number; None if it never does."""
    deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
    collected = b""
    os.set_blocking(read_fd, False)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return None
        try:
            chunk = os.read(read_fd, 32)
        except BlockingIOError:
            time.sleep(0.05)
            continue
        if not chunk:
            time.sleep(0.05)
            continue
        collected += chunk
        if b"\n" in collected:
            number = collected.split(b"\n", 1)[0].decode("ascii", "ignore").strip()
            return number or None
    return None
