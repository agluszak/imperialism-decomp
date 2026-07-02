# Workflows — the three canonical playbooks

Every routine task in this repo is one of the three loops below. `just --list`
shows all targets grouped by area; any target whose description starts with
`MUTATES:` rewrites the named state (everything else is read-only). When unsure,
start here rather than composing raw tool invocations.

## 1. Daily port loop (no marker/ownership changes)

Edit manual source (shape/data passes on already-owned functions), then:

```sh
just build              # Docker MSVC500 build (runs vtable-gate first)
just compare 0xADDR     # or: just compare --file src/game/Foo.cpp
```

Pre-commit (always):

```sh
just precommit                # build + gates + tooling tests + stats in one command
just stats-baseline-update    # if the stats deltas are accepted; commit the baseline with the change
```

## 2. After editing markers / ownership

Whenever you add, remove, or move a `// FUNCTION:` / `// STUB:` / `// SYNTHETIC:` /
`// LIBRARY:` marker (including `just promote`):

```sh
just regen-stubs    # runs sync-ownership + symbols-integrity-gate first, then stubgen
just build
```

There is no separate sequence to remember: `regen-stubs` reconciles
`config/function_ownership.csv` from source markers (deletion-reconciling;
curated notes like `mfc_runtime_macro` are never pruned) and verifies
`config/symbols.csv` integrity before regenerating `src/autogen/stubs/`.

## 3. Full Ghidra DB resync

After any Ghidra DB mutation (`repair-code-gaps --apply`, datatype appliers,
manual edits in the Ghidra GUI) — or when you want a clean re-export:

```sh
just db-resync
```

This is the whole ledger procedure from `docs/ghidra-db-mutations.md` in one
command: `tooling-check` → `sync-ghidra` (push names → export symbols/autogen →
prune ILT rows → thunk map → normalize autogen → symbol gates) → `regen-stubs` →
`build` → `detect` → `gates` → `stats` → `export-project` (refreshes the vendored
`.gzf`). If any step fails, fix forward and re-run; never commit a partial resync.

To only refresh exports without the build/gate tail, `just sync-ghidra` still
exists — but the DB is modified by its push-names step, so `just export-project`
must run before committing either way.

## Name and ownership state — who owns what

| State | File | Written by |
|---|---|---|
| Curated names/prototypes (top authority) | `config/function_name_overrides.csv` | hand-edited |
| Exported symbol table (reccmp entity list) | `config/symbols.csv` | `sync-ghidra` (curated names preserved by merge) |
| Address ownership (stub suppression) | `config/function_ownership.csv` | `regen-stubs`/`sync-ownership` from source markers |
| Provisional names, disassembly ground truth | vendored Ghidra DB | `push-names`, DB-mutating targets (`ghidra-db` group) |

Renamed targets (old names remain as aliases): `stats-commit` →
`stats-baseline-update`, `full-sync-build` → `db-resync`. `just session-loop` is
now read-only; ignore-list rewriting requires `--refresh-ignore` or
`just generate-ignores` (Hard Rule 14).
