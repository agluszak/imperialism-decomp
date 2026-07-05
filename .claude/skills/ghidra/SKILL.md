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

## Start the query daemon first (one JVM, instant queries)

Every one-shot query pays ~60-90s of JVM/project startup. **Start the persistent
read-only daemon at the beginning of any session that will issue more than one
Ghidra query** — all the read-only targets below then answer in ~0.2-3s:

```sh
just ghidra-daemon          # start (blocks ~60-90s until "ready", then returns)
just ghidra-daemon-status   # running?
just ghidra-daemon-stop     # stop (frees the project lock)
```

Rules of thumb:
- The daemon holds the **project lock**, and every other project open — a
  `MUTATES: Ghidra DB` target or a one-shot read tool such as
  `scan-cdecl-thiscall` — **evicts it automatically** (asks it to shut down,
  waits for the lock). Re-warm with `just ghidra-daemon` afterwards.
- Without a daemon everything still works — the targets fall back to the classic
  one-shot path (same output, slow) and print a hint.
- It exits on its own after 4h idle (`GHIDRA_DAEMON_IDLE_SECS` overrides).
  Log: `.ghidra-query.log` in the repo root.
- The daemon imports the tool code at startup: after editing anything under
  `tools/ghidra/`, restart it (`just ghidra-daemon-stop && just ghidra-daemon`)
  or queries keep answering with the old code.
- Almost every read tool is daemon-routed (`listing`, `decompile`, `xrefs`,
  `read-data`, `function-slice`, `search`, `jumptable`, `linear-disasm`,
  `raw-disasm`, `vtable-dump`); `scan-cdecl-thiscall` stays one-shot (reads
  addresses from stdin). Details: `tools/ghidra/README.md`.

## Read-only queries (preferred — use these, not raw disassemblers)

- **Instruction listing** for one or more addresses (follows ILT `jmp` thunks to
  their real target; on a Ghidra gap it prints the nearest functions before/after
  instead of dead-ending):
  ```sh
  just ghidra-listing 0x004dd1b0 [0xADDR ...]
  ```
- **Cross-references** — direction `to` (default) lists callers, jumps, and
  address-taken/data refs, hopping through ILT thunks automatically (a body address
  answers "who calls this" in one query; address-taken hits are how data-registered
  callbacks hide). Direction `from` lists the containing function's callees + global
  data reads without decompiling; `both` prints both. (`just ghidra-xrefs` is an
  alias.)
  ```sh
  just xrefs 0x581870 [0xADDR ...] [--no-thunk-hop] [--limit N]
  just xrefs from 0x0052d750           # a function's callees + data reads
  just xrefs both 0x0052a760
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
- **Decode a switch jump table** (MSVC500 two-level pattern; works inside Ghidra
  code gaps — reads raw bytes, prints case→target with owning functions):
  ```sh
  just ghidra-jumptable 0x5db695            # address of the indirect jmp
  just ghidra-jumptable --table 0x459548 --cases 10   # explicit-table form
  ```
- **Whole-binary search** — instruction text, raw data dwords, or exact immediate
  operands. `imm` is the precise one: `imm 0x11f8` finds every `PUSH 0x11f8` /
  `CMP EAX,0x11f8` (event-code dispatch sites, callback address-taken sites)
  without false positives from addresses containing the digits:
  ```sh
  just ghidra-search text|dword|imm <value> [limit]
  ```
- **Gap disassembly** — when Ghidra has no instruction at an address:
  `just ghidra-linear-disasm 0xADDR [count]` walks Ghidra's instruction DB past
  wrong function bounds; `just ghidra-raw-disasm 0xADDR [bytes]` disassembles raw
  bytes with capstone for regions Ghidra never analyzed at all.
- **Decompile** a single function: `just ghidra-decompile 0xADDR [0x...]`.
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
