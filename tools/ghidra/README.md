# Ghidra Sync

This directory intentionally uses a single export entrypoint:

- `sync_exports.py` (Python CLI, runs through `pyghidra`)
- `SyncExports_Ghidra.py` (script executed inside Ghidra runtime)

## Version Pin

The single source of truth is `ghidra.toml` in the repository root:

- `[ghidra].version`
- `[ghidra].release`
- `[ghidra].program_name`

`sync_exports.py` validates both:

- local `pyghidra` version (`3.1.0`)
- target Ghidra install version/release from `application.properties`

## Usage

```bash
uv run python -m tools.ghidra.sync_exports \
  --ghidra-install-dir /path/to/ghidra_12.1_PUBLIC \
  --ghidra-project-dir /path/to/ghidra/projects \
  --ghidra-project-name imperialism-decomp \
  --ghidra-program-name Imperialism.exe \
  --output-dir config \
  --decomp-output-dir src/ghidra_autogen \
  --types-output-dir include/ghidra_autogen \
  --decomp-max-functions-per-file 250 \
  --name-overrides config/function_name_overrides.csv
```

Outputs:

- `config/symbols.ghidra.txt`
- `config/symbols.csv`
- `src/ghidra_autogen/*.cpp` (+ manifest/index)
- `include/ghidra_autogen/*.h` (+ manifest/index)

Function exports in `src/ghidra_autogen/*.cpp` include:

- decompiler C output (or explicit decompilation-failed marker)
- `GHIDRA_NAME` / `GHIDRA_PROTO`
- `GHIDRA_COMMENT` and `GHIDRA_REPEATABLE_COMMENT` blocks from function comments

If `config/function_name_overrides.csv` exists, `sync_exports.py` reapplies overrides after export to:

- `config/symbols.csv`
- `config/symbols.ghidra.txt` (function names only; whitespace names are skipped)
- `src/ghidra_autogen/index.csv`

## Read-only inspection daemon

The hot-path read-only inspect commands (`listing`, `decompile`, `xrefs` (thunk-hopping TO),
`jumptable`, `search`, `linear-disasm`, `raw-disasm`, `vtable-dump` — see
`query_registry.COMMANDS`) each used to pay the full pyghidra JVM + project-load cost
(~15-30s) on every call. `daemon.py` opens the project/program **once** and serves those
commands over a Unix-domain socket, so every call after the first is sub-second.

- `daemon.py` — the server (`start`/`stop`/`status`/`serve`); holds the shared program open
  behind `.ghidra-query.sock` and answers registry commands via `query_registry.COMMANDS`.
- `query.py` — the one front door the `just ghidra-*` inspect targets call: routes to the
  daemon when it's listening, otherwise falls back to a one-shot pyghidra open/run/close with
  identical output (no auto-spawn side effect).

```bash
just ghidra-daemon          # warm it explicitly (optional; each call also tries the daemon)
just ghidra-listing 0xADDR  # sub-second once warm
just xrefs 0xADDR           # references TO an address, thunk-hop TO-only
just ghidra-daemon-stop     # stop it and release the project lock
```

Because the daemon holds the project lock, **mutating** Ghidra tools (`sync-ghidra`, `apply-*`,
`export-project`, `db-resync`, …) must stop it first — those targets call
`just ghidra-daemon-stop` automatically. Re-warm with `just ghidra-daemon` afterwards.
Socket/pid/log live at `.ghidra-query.sock` / `.ghidra-query.pid` / `.ghidra-query.log`
(gitignored); override the idle shutdown with `GHIDRA_DAEMON_IDLE_SECS`.

A few read-only tools stay one-shot (no daemon routing) rather than going through the
registry: `ghidra-xrefs` (`xrefs.py`, bidirectional to/from/both, no thunk-hop),
`ghidra-read-data` (`read_data.py`, typed memory reads), `ghidra-function-slice`
(`function_slice.py`, call/offset slice), and `scan-cdecl-thiscall` (reads addresses from
stdin, which a separate daemon process can't see).

Two companion helpers need no Ghidra at all (pure config-file readers, instant):

- `just func-status 0xADDR` — one-stop function summary (curated name/size/prototype,
  ownership, autogen body location, current reccmp match %) from the config CSVs + baseline
  report, instead of grepping four files by hand.
- `just port-candidates [--range LO HI] [--min-size N] [--max-score PCT]` — rank the biggest
  weakly-matched functions to pick the next porting target.

## Notes

- Exported `ghidra_autogen` trees are regenerated and stale generated files are removed.
- `src/ghidra_autogen` is snapshot/reference output; manual edits should go to non-autogen source files.
- `src/ghidra_autogen` uses `GHIDRA_FUNCTION` metadata comments (not `FUNCTION/STUB`) so reccmp annotations come only from compilable source files.
