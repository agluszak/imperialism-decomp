"""Off-screen X display for runtime-test sessions.

Wine maps a real window for every run. On a developer's desktop that steals focus for
the second or two the game lives, which makes the suite unusable while working -- and on
a headless host (CI, a cloud session) there is no display to map into at all. Both are
solved the same way: give each session its own Xvfb server and point `DISPLAY` at it.

Selected with `IMPERIALISM_RUNTIME_DISPLAY`:

  virtual   private Xvfb per session (off-screen; needs an Xvfb binary on PATH)
  host      the inherited DISPLAY (explicit opt-in for visual/debugging work)
  :5        a specific display that is already running

Off-screen runs seed `Managed=N` into the prefix (see tools/runtime/wine.py). With no
window manager present, Wine's managed-window path waits on a WM that never answers;
owning its windows outright is what makes the game paint normally, and it fixed the
whole render-cache failure class off-screen.

The default is `virtual`, so normal runtime-test runs cannot map a window on the
developer's desktop or steal focus. Set `IMPERIALISM_RUNTIME_DISPLAY=host` explicitly
for visual/debugging work. Two scenarios that pick a capital by screen coordinate --
`random_game_enters_map` and `save_load_roundtrip` -- select a slightly different tile
off-screen, because window decorations shift the mapping from pixel to tile. Their
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
import json
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

    Yields the display string in use, or None when running on the explicitly selected
    host display. Virtual mode is isolation policy, not a best-effort convenience: a
    missing or failed Xvfb aborts before Wine can touch an inherited desktop.
    """
    requested = os.environ.get("IMPERIALISM_RUNTIME_DISPLAY", "virtual").strip() or "virtual"
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

    # A live worktree-scoped Xvfb is reused rather than restarted. wineserver is kept
    # warm across runs and stays bound to whatever display it started on, so a per-run
    # display would leave it pointing at a dead server on the next test.
    reused = _live_worktree_display()
    if reused is not None:
        environment["DISPLAY"] = reused
        environment["IMPERIALISM_WINE_VIRTUAL_DESKTOP"] = "1"
        yield reused
        return

    binary = _xvfb_binary()
    if binary is None:
        raise RuntimeError(
            "IMPERIALISM_RUNTIME_DISPLAY=virtual requires Xvfb on PATH; "
            "use IMPERIALISM_RUNTIME_DISPLAY=host explicitly for the desktop"
        )

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
            raise RuntimeError(
                f"Xvfb failed to start for virtual runtime display; see {log_path}"
            )

        display = f":{display_number}"
        environment["DISPLAY"] = display
        environment["IMPERIALISM_WINE_VIRTUAL_DESKTOP"] = "1"
        _record_worktree_display(display, process.pid)
        try:
            yield display
        finally:
            environment.pop("DISPLAY", None)
            environment.pop("IMPERIALISM_WINE_VIRTUAL_DESKTOP", None)
    finally:
        if write_fd != -1:
            os.close(write_fd)
        os.close(read_fd)
        # Deliberately left running: it is worktree-scoped and the warm wineserver is
        # bound to it. `just runtime-clean` reaps it.
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


def _display_state_path() -> Path:
    from tools.runtime.wine import BUILD_DIR

    return BUILD_DIR / "xvfb-display.json"


def _live_worktree_display() -> str | None:
    """Return this worktree's Xvfb display if its server is still running."""
    try:
        state = json.loads(_display_state_path().read_text(encoding="utf-8"))
        pid = int(state["pid"])
        display = str(state["display"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return display


def _record_worktree_display(display: str, pid: int) -> None:
    path = _display_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"display": display, "pid": pid}), encoding="utf-8")
