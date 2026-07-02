---
name: ghidra
description: Inspect Imperialism.exe through the vendored Ghidra project via pyghidra — print instruction listings, decompile a function, dump a class vtable, classify __cdecl-vs-__thiscall, and (interactively) document functions in Ghidra. Use whenever you need ground-truth disassembly, a vtable layout, a calling-convention check, or to read/annotate a function in the Ghidra database. Use this instead of objdump.
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

## Read-only queries (preferred — use these, not raw disassemblers)

- **Instruction listing** for one or more addresses (follows ILT `jmp` thunks to
  their real target):
  ```sh
  just ghidra-listing 0x004dd1b0 [0xADDR ...]
  ```
- **Decompile** a single function: `tools/ghidra/decompile_one.py` (module
  `tools.ghidra.decompile_one`).
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

- `just sync-ghidra` — forward: export Ghidra names/protos/types/globals into
  `config/` + `src/ghidra_autogen/` artifacts. **Curated `config/symbols.csv`
  rows are preserved by address** (name + prototype) so provisional Ghidra labels
  cannot regress reccmp pairing; `config/function_name_overrides.csv` still wins
  afterward. The pipeline self-cleans: stray ILT-range DB Function entities are
  pruned first, rows colliding with source `// VTABLE:` addresses are dropped in
  the merge, and integrity/collision gates run at the end. It mutates the DB
  (push-names), so `just export-project` must follow — or run `just db-resync`,
  which chains the whole resync through build/gates/stats/export. Durable
  renames belong in overrides, not hand-edited export output. Use
  `--no-preserve-curated-symbols` only for a deliberate full refresh.
- `just import-ghidra` — reverse: push our recovered names/signatures/types back
  into Ghidra (via the reccmp fork). Conventions you model in source propagate to
  Ghidra this way; there is deliberately no separate convention-rewriter.

## Documenting a function inside Ghidra

When you are interactively annotating functions in the Ghidra GUI / MCP tools
(naming, prototypes, types, plate comments), follow the methodology in
`function-doc-workflow.md` next to this file: mandatory undefined-type audit,
verify-decompiler-against-assembly, PascalCase verb-first naming, Hungarian
notation, and the plate-comment format.
