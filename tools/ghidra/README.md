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

Normal entrypoints are the just targets, not the module directly:

- `just refresh-inventory` — wholesale raw-inventory refresh
  (`sync_exports --inventory-only`): writes `config/symbols.ghidra.txt` and
  `config/original_entities.csv` and nothing else. Curated knowledge lives in
  source and the DB; nothing is merged back into the export.
- `just export-ghidra-evidence` — optional full snapshot of decompiled bodies +
  type headers into `build-msvc500/evidence/ghidra-export/` (uncommitted
  evidence, never source).
- `just ghidra-apply-source[-full]` — the ONE source→DB direction: names from
  the central source model (tools.source_model), PDB-driven types/signatures
  via reccmp's importer, `Class::'vftable'` labels, then `export-project`.

## Read-only inspection daemon

The hot-path read-only inspect commands (`listing`, `decompile`, `xrefs` (to/from/both,
thunk-hopping TO), `read-data`, `function-slice`, `jumptable`, `search`, `linear-disasm`,
`raw-disasm`, `vtable-dump`, `check-function-extents` — see `query_registry.COMMANDS`) each used to pay the full
pyghidra JVM + project-load cost (~15-30s) on every call. `daemon.py` opens the
project/program **once** and serves those commands over a Unix-domain socket, so every
call after the first is sub-second.

- `daemon.py` — the server (`start`/`stop`/`status`/`serve`); holds the shared program open
  behind the socket from `ghidra_env.socket_path()` and answers registry commands via
  `query_registry.COMMANDS`.
- `query.py` — the one front door the `just ghidra-*` inspect targets call: routes to the
  daemon when it's listening, otherwise falls back to a one-shot pyghidra open/run/close with
  identical output (no auto-spawn side effect).

```bash
just ghidra-daemon          # warm it explicitly (optional; each call also tries the daemon)
just ghidra listing 0xADDR  # sub-second once warm
just ghidra xrefs [to|from|both] 0xADDR   # cross-references (default: to, thunk-hopping)
just ghidra-daemon-stop     # stop it and release the project lock
```

The daemon holds the exclusive project lock, so **every other project open evicts it
automatically**: `ghidra_env.open_project()` asks a running daemon to shut down and waits
for the lock before opening. That covers the mutating tools (`ghidra-apply-source`,
`refresh-inventory`, `apply-*`, `export-project`, …) and the one-shot read tools alike — re-warm
with `just ghidra-daemon` afterwards. The daemon itself binds its socket only *after* its
own project open completes, so it never evicts itself during startup, and a visible socket
always belongs to a ready daemon. Socket/pid/log live at `.ghidra-query.sock` /
`.ghidra-query.pid` / `.ghidra-query.log` (gitignored; `GHIDRA_DAEMON_SOCK` overrides the
socket path — `ghidra_env.socket_path()` is the single source of truth both sides use).
Override the idle shutdown with `GHIDRA_DAEMON_IDLE_SECS`.

The daemon imports the registry tool modules at startup: after editing anything under
`tools/ghidra/`, restart it (`just ghidra-daemon-stop && just ghidra-daemon`) or queries
keep running the old code.

`scan-cdecl-thiscall` stays one-shot (no daemon routing) because its `--stdin` address list
can't reach a separate daemon process; other occasional audit tools (`vtable-struct-check`,
`datatype-audit`, `class-owner-probe`, `rtti-oracle`, …) are one-shot as well and evict a
running daemon like any other open.

Two companion helpers need no Ghidra at all (pure config-file readers, instant):

- `just func-status 0xADDR` — one-stop function summary (inventory name/size/prototype,
  marker-derived ownership, evidence body location, current reccmp match %) from the model + baseline
  report, instead of grepping four files by hand.
- `just port-candidates [--range LO HI] [--min-size N] [--max-score PCT]` — rank the biggest
  weakly-matched functions to pick the next porting target.

## Notes

- The evidence export (bodies/types) is uncommitted build output under
  `build-msvc500/evidence/ghidra-export/`; it uses `GHIDRA_FUNCTION` metadata
  comments (not `FUNCTION/STUB`) so reccmp annotations come only from source.
- There is no automated Ghidra→source path: discoveries in Ghidra are evidence
  you port into manual source by hand (`just seed-function 0xADDR`).
