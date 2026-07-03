---
name: ghidra
description: Inspect Imperialism.exe through the vendored Ghidra project via pyghidra — print instruction listings, decompile a function, dump a class vtable, list cross-references (xrefs), read typed data/constants, classify __cdecl-vs-__thiscall, and (interactively) document functions in Ghidra. A persistent daemon keeps the project loaded so inspect calls are sub-second. Use whenever you need ground-truth disassembly, a vtable layout, a cross-reference, a constant's value, a calling-convention check, or to read/annotate a function in the Ghidra database. Use this instead of objdump.
---

# Ghidra access (pyghidra)

The Ghidra program lives in-repo at `vendor/ghidra/`. The portable archive
`vendor/ghidra/exports/Imperialism.gzf` is committed via Git LFS; the live working
project (`vendor/ghidra/imperialism-decomp.rep`) is gitignored and recreated from it.
The `just` targets force this vendored project (the `GHIDRA_PROJECT_DIR`/`NAME` are
exported by the justfile) — no external checkout, and no Ghidra path in `.env` beyond
`GHIDRA_INSTALL_DIR` (the install is machine-specific).

## Project lifecycle

```sh
git lfs pull           # fetch vendor/ghidra/exports/Imperialism.gzf
just restore-project   # recreate the live .rep from the .gzf (fresh clone / one-time)
# ... work; `just import-ghidra` pushes recovered names/types into the live project ...
just export-project    # repack the live .rep -> Imperialism.gzf (+ .sha256); commit the archive
```

Never commit the live `.rep` (gitignored). Refresh the archive with
`just export-project` whenever the Ghidra database has meaningfully changed.

## The inspection daemon (why these calls are fast)

The read-only inspect targets route through a long-lived daemon (`tools/ghidra/daemon.py`)
that opens the project/program **once**. The first `just ghidra-*` call auto-starts it (pays
the ~15-30s JVM + project load one time); every later call is **sub-second**. You don't manage
it — but you can `just ghidra-daemon` to warm it eagerly and `just ghidra-daemon-stop` to stop
it. Mutating targets (`sync-ghidra`, `apply-*`, `export-project`, `db-resync`) need exclusive
project access and **evict the daemon automatically**; re-warm with `just ghidra-daemon` after.
Details: `tools/ghidra/README.md`.

## Read-only queries (preferred — use these, not raw disassemblers)

- **Instruction listing** for one or more addresses (follows ILT `jmp` thunks to
  their real target):
  ```sh
  just ghidra-listing 0x004dd1b0 [0xADDR ...]
  ```
- **Decompile** a single function: `just ghidra-decompile 0xADDR`.
- **Cross-references** — who references an address (call sites, data reads, vtable-slot
  dispatches, with the containing function) and what a function references out. Direction is
  `to` | `from` | `both` (default `both`). This is the fast way to resolve "which thunk
  dispatches this vtable slot" or "what does this function call":
  ```sh
  just ghidra-xrefs to 0x0052a760      # who calls / dispatches this address
  just ghidra-xrefs from 0x0052d750    # a function's callees + data reads
  ```
- **Read a typed value / constant** at an address — `byte word dword qword float double ptr
  str bytes` (default `dword`), with an optional count for tables. Use this instead of hacking
  a vtable dump or hand-unpacking bytes when you need a *value* (an FP scale, a jump-table
  entry, a vtable slot pointer, a string):
  ```sh
  just ghidra-read-data 0x006598d8 double     # -> 11733.857334728455
  just ghidra-read-data 0x0065999c ptr 2       # two vtable slot pointers
  just ghidra-read-data 0x00697450 dword 6     # a 6-entry int table
  ```
- **Dump a class vtable** (slot → function map):
  ```sh
  just ghidra-vtable-dump TGreatPower 0x00653938
  ```
- **RTTI class oracle** — every MFC `CRuntimeClass` descriptor in the binary
  (true class name, object size, base-class edge, resolved `CreateObject` address);
  the durable snapshot lives at `config/rtti_class_oracle.csv`:
  ```sh
  just rtti-oracle          # table; `--csv` for the CSV artifact
  ```
- **Classify calling convention** — `ecx_this` (likely `__thiscall`) / `no_ecx`
  (likely `__cdecl`) / `empty` (thunk). Pass addresses or pipe `__cdecl` rows from
  `config/symbols.csv` to `--stdin`:
  ```sh
  just scan-cdecl-thiscall 0x004dc540
  ```
  Background: `__cdecl` in `symbols.csv` is mostly Ghidra's default-unknown label;
  ~33% of *defined* `__cdecl` functions are really `__thiscall` (heuristics.md #82).

## Pointing at a different project (rare)

The `just` targets always use the vendored project. To run a pyghidra tool against a
different project, invoke the module directly with the env override, e.g.
`GHIDRA_PROJECT_DIR=/path GHIDRA_PROJECT_NAME=foo uv run python -m tools.ghidra.listing_one 0x...`.

## Sync with the source tree

- `just sync-ghidra` / `just db-resync` — forward: export Ghidra
  names/protos/types/globals into `config/` + `src/ghidra_autogen/` artifacts.
  Ownership of that pipeline (curated-merge semantics, junk cleanup, name
  convergence, failure→fix) lives in the **`sync-pipeline` skill** — read it
  before running or debugging a resync. Prefer `just db-resync` for the full
  chain; `sync-ghidra` alone still mutates the DB (push-names), so
  `just export-project` must follow before committing.
- `just import-ghidra` — reverse: push our recovered names/signatures/types back
  into Ghidra (via the reccmp fork). Conventions you model in source propagate to
  Ghidra this way; there is deliberately no separate convention-rewriter.

## Documenting a function inside Ghidra

When you are interactively annotating functions in the Ghidra GUI / MCP tools
(naming, prototypes, types, plate comments), follow the methodology in
`function-doc-workflow.md` next to this file: mandatory undefined-type audit,
verify-decompiler-against-assembly, PascalCase verb-first naming, Hungarian
notation, and the plate-comment format.
