---
name: run-debug
description: Run and debug the recompiled Imperialism.exe under Wine — launch it from the retail install dir, drive winedbg with a scripted breakpoint, pick WINEDEBUG channels, and capture a screenshot of the game window for visual verification. Use when asked to run the game, verify a UI/paint/init change visually, trace a startup failure or empty error box, or grab a screenshot.
---

# Run & debug the recomp

`ORIGINAL_BINARY` in `.env` must point at a retail `Imperialism.exe` whose directory
holds `Data/` and the other assets; `just build` first.

## Launch

- `just run-fresh` — the default way to (re)launch: kills stale game/wineserver
  state, settles, launches detached, and confirms the process is alive (log:
  `build-msvc500/run.log`). Do NOT hand-roll `pkill` + launch in one compound
  command — that silently races about half the time; this target sequences it
  correctly.
- `just run` — foreground run without the hygiene (`WINEDEBUG=-all` by default;
  override in the environment).
- `just run-trace [timeout]` — timed run with `+seh,+debugstr` tracing that then
  greps the log for unhandled exceptions/page faults. **Use this whenever the
  window is blank or behavior silently stops**: crashes swallowed by an exception
  handler (process alive, UI dead — e.g. a call through a null function pointer)
  are invisible under plain `just run` and show up here.

## Debug

- `just debug` — winedbg with a scripted session; default script breaks on
  `MessageBoxA`, continues, prints a backtrace, quits (made for empty-error-box
  startup failures). Override:
  `DEBUG_SCRIPT=$'break SomeSymbol\ncont\nbt\nquit\n' just debug`.
  The recipe kills any stale wineserver first (stale state used to hang winedbg
  until the timeout with zero output).
- `just debug-timeout` — same with a deadline (`DEBUG_TIMEOUT=10s …`); its default
  `WINEDEBUG=err+all,+debugstr,+loaddll` is the useful starting channel set.
- `just addr 0xADDR` — translate an original-binary address to the recomp
  address/symbol (and back; cached, instant after the first call). Use it to set
  winedbg breakpoints from `// FUNCTION` markers, memory notes, or crash
  addresses when `break SymbolName` won't resolve (free functions, renamed
  bodies).
- OutputDebugString from the game shows up under the `debugstr` channel.
- winedbg pitfalls: breakpoints freeze the message pump (step, don't free-run,
  once inside), and named-parameter printing at a function's first instruction is
  unreliable — cross-check with a raw stack read (`print *(short*)($esp+4)`).

## Screenshot the game window

```sh
just screenshot [out.png]        # default /tmp/imperialism.png
```

Auto-discovers the game window by class (largest match wins; window IDs go stale
on every relaunch, so discovery beats hardcoding) and captures it by ID —
root-window grabs fail with `BadMatch` under nested/Wayland X servers. Pass
`--win 0xID` to force a specific window. Read the PNG back to inspect it
visually.

## Verifying a change end-to-end

Build → `just run-fresh` → `just screenshot` → compare against the expectation
(e.g. title bitmap present, no stray popup, window not blank). A blank-but-alive
window can be an init/paint blocker **or a silently-swallowed crash** — run
`just run-trace` to tell the two apart before digging.
