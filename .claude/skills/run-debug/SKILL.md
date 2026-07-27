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
- `IMPERIALISM_RUNTIME_GDB_WATCH='0xADDR:<cond>;0xADDR' just runtime-test <name> --gdb`
  — drive a whole scenario under gdb and stop at your own breakpoints. Entries are
  `;`-separated so a condition may contain spaces; addresses are RECOMP addresses in
  the runtime build (`build-runtime-tests/Imperialism.map`), not original ones. Each hit
  is captured like any other stop (registers, `x/256wx $sp`, `x/32i $pc-32`, symbolized
  against the map) and the run continues. Use a condition: an unconditional breakpoint on
  a hot helper is captured once (identical stops are deduped) and then only slows the run.
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

Each semantic attempt runs from `<attempt>/game`, never from the retail installation.
That tree hard-links a read-only, content-addressed asset cache and supplies fresh
writable `Save`, log, result, and fixture locations. The worktree Wine prefix stays warm,
but the game registry key is deleted and deterministically reseeded before every
attempt. `host.provenance` records the Git commit, recomp/retail executable hashes, Wine
version, retail-asset manifest hash, fixture hash, and display mode. A local retail save
fixture is accepted only with an adjacent `.imp.json` sidecar binding its hash, format
version, scenario, and reproduction instructions.

### Running off-screen

Wine maps a real window per session, which steals focus while you work. Give the session
its own `Xvfb` instead:

```sh
just runtime-test <name>                                      # default: off-screen
IMPERIALISM_RUNTIME_DISPLAY=virtual just runtime-test <name>   # explicit off-screen
IMPERIALISM_RUNTIME_DISPLAY=host    just runtime-test <name>   # opt-in real desktop
IMPERIALISM_RUNTIME_DISPLAY=:5      just runtime-test <name>   # your own server
```

The display actually used is reported as `host.display` in the result. Virtual mode
requires an `Xvfb` binary on PATH (`brew install xorg-server`, no root) and fails closed
if it cannot start one; it never falls back to the inherited `DISPLAY`.

Off-screen runs seed `Managed=N` into the prefix: with no window manager present, Wine's
managed-window path waits on a WM that never answers, and owning its windows outright is
what makes the game paint normally off-screen.

**Known limitation.** `random_game_enters_map` and
`save_load_roundtrip` pick a capital by screen coordinate, and window decorations shift
which tile that pixel lands on -- so off-screen they found a slightly different city and
a few terrain counts move. That is real game state, not a harness artifact, which is why
committing a second set of expectations would only move the problem; the fix is to make
those scenarios address tiles rather than pixels. Everything else passes off-screen.
Tracked as `imperialism-decomp-0kr0`.

Runtime-test game code must use the production `/Oy /Ob1` optimization and linker flags.
Compiling it with `/Oy-` changes stack-frame shape and can mask exactly the ABI defects the
suite is meant to catch: a one-argument call through a two-argument virtual slot survived
under `/Oy-` but corrupted the caller's saved argument under `just debug`'s `/Oy` build.
Keep linker maps and register/memory stop captures for symbolization instead of weakening
the tested ABI to obtain frame-pointer backtraces.

`just test` always uses the virtual display -- the Wine-touching tooling tests have no
such pixel dependency.

Screenshot capture is unaffected either way: it captures by window id against `DISPLAY`.
