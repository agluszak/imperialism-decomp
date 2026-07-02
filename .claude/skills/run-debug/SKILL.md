---
name: run-debug
description: Run and debug the recompiled Imperialism.exe under Wine — launch it from the retail install dir, drive winedbg with a scripted breakpoint, pick WINEDEBUG channels, and capture a screenshot of the game window for visual verification. Use when asked to run the game, verify a UI/paint/init change visually, trace a startup failure or empty error box, or grab a screenshot.
---

# Run & debug the recomp

`ORIGINAL_BINARY` in `.env` must point at a retail `Imperialism.exe` whose directory
holds `Data/` and the other assets; `just build` first. Current startup/rendering
blockers are tracked in `docs/TODO.md`.

## Launch

- `just run` — runs the recomp under Wine from the retail dir (`WINEDEBUG=-all` by
  default; override in the environment).
- **Backgrounding is flaky when chained**: `pkill`/`wineserver -k` + launch in one
  compound command silently fails to start about half the time. Use three separate
  commands: (1) kill + settle, (2) `nohup just run > /tmp/…/run.log 2>&1 &` alone,
  (3) sleep then `pgrep -fa Imperialism.exe` to confirm it's alive.

## Debug

- `just debug` — winedbg with a scripted session; default script breaks on
  `MessageBoxA`, continues, prints a backtrace, quits (made for empty-error-box
  startup failures). Override:
  `DEBUG_SCRIPT=$'break SomeSymbol\ncont\nbt\nquit\n' just debug`.
- `just debug-timeout` — same with a deadline (`DEBUG_TIMEOUT=10s …`); its default
  `WINEDEBUG=err+all,+debugstr,+loaddll` is the useful starting channel set.
- OutputDebugString from the game shows up under the `debugstr` channel.

## Screenshot the game window

Root-window capture can fail with `BadMatch` under nested/Wayland X servers —
capture the game window by ID instead (portable either way):

1. `xwininfo -root -tree | grep -i imperialism` → top-level window ID (e.g.
   `0x2e00001`). The ID goes stale on every relaunch; re-run after each launch.
2. ```
   uv run --with python-xlib --with pillow python3 - <<'EOF'
   from Xlib import display, X
   from PIL import Image
   WIN_ID = 0x2e00001  # from xwininfo
   d = display.Display()
   win = d.create_resource_object('window', WIN_ID)
   g = win.get_geometry()
   raw = win.get_image(0, 0, g.width, g.height, X.ZPixmap, 0xffffffff)
   Image.frombytes('RGB', (g.width, g.height), raw.data, 'raw', 'BGRX').save('/tmp/imperialism.png')
   EOF
   ```
   Note the `BGRX` pixel order (32bpp TrueColor).
3. Read the PNG back to inspect it visually.

## Verifying a change end-to-end

Build → launch → screenshot → compare against the expectation (e.g. title bitmap
present, no stray popup, window not blank). A blank-but-alive window usually means
an init-sequence or paint-dispatch blocker, not a crash — check `docs/TODO.md`
before digging.
