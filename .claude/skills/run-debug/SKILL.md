---
name: run-debug
description: Run and debug the recompiled Imperialism.exe under Wine — launch it from the retail install dir, drive winedbg with a scripted breakpoint, pick WINEDEBUG channels, and capture a screenshot of the game window for visual verification. Use when asked to run the game, verify a UI/paint/init change visually, trace a startup failure or empty error box, or grab a screenshot.
---

# Run & debug the recomp

`ORIGINAL_BINARY` in `.env` must point at a retail `Imperialism.exe` whose directory
holds `Data/` and the other assets; `just build` first.

## Launch

- `just run` — foreground run without the hygiene (`WINEDEBUG=-all` by default;
  override in the environment).

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

## Verifying a change end-to-end

Use `just runtime-test <name>` for assertions and isolated Wine execution. Failed
or timed-out semantic runs capture a screenshot internally when possible, but pixels
are diagnostic only and never influence pass/fail. Use `just smoke`, `just smoke-diff`,
or `just gdb-script` for startup and debugger observation independent of native test
instrumentation.

### Running off-screen

Wine maps a real window per session, which steals focus while you work. Give the session
its own `Xvfb` instead:

```sh
IMPERIALISM_RUNTIME_DISPLAY=virtual just runtime-test <name>   # off-screen
IMPERIALISM_RUNTIME_DISPLAY=host    just runtime-test <name>   # default: real desktop
IMPERIALISM_RUNTIME_DISPLAY=:5      just runtime-test <name>   # your own server
```

The display actually used is reported as `host.display` in the result. Needs an `Xvfb`
binary on PATH (`brew install xorg-server`, no root); without one the session falls back
to the inherited `DISPLAY`.

**Known limitation, and why `host` is still the default.** The render-cache scenarios --
`random_game_enters_map`, `random_game_easy_skips_capital`, `load_saved_game` -- fail
under a bare Xvfb with "primed city-site hover tile is not present in the render cache",
while passing on the host display. A larger virtual screen and Wine's own virtual desktop
both failed to fix it, so the missing ingredient is not resolution and not window
management alone. Everything else passes off-screen, including the whole serialization
suite. Tracked as `imperialism-decomp-0kr0`.

Screenshot capture is unaffected either way: it captures by window id against `DISPLAY`.
