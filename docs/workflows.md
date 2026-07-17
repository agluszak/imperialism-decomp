# Workflows — the three canonical playbooks

Every routine task in this repo is one of the three loops below. `just --list`
shows all targets grouped by area; any target whose description starts with
`MUTATES:` rewrites the named state (everything else is read-only). When unsure,
start here rather than composing raw tool invocations.

## 0. Fresh clone / new git worktree bootstrap

**Genuinely fresh clone on a new machine** (no existing checkout, Docker image,
or Beads setup yet): see the README's Prerequisites + Environment sections —
that's the canonical first-time sequence (installs, `docker-build`,
`bootstrap-reccmp`, `bd init`, first build).

**New git worktree on a machine that already has a checkout** shares the git
tree but none of the gitignored machine state. Recreate the first two (copy
from an existing checkout, or from the templates):

```sh
cp ../imperialism-decomp/.env .              # or: cp .env.example .env and edit
cp ../imperialism-decomp/reccmp-user.yml .   # machine path to the original binary
just restore-project                          # recreate the live Ghidra project from vendor/ghidra/exports/*.gzf
just tooling-check                            # verify the tooling surface
just build && just detect && just stats       # first build + reccmp pairing; stats should show no baseline drift
```

Notes:
- **Worktrees under a dot-directory** (e.g. `.claude/worktrees/<name>`) cannot host
  the live Ghidra project: Ghidra's `ProjectLocator` rejects any path element
  starting with `.` ("Path element starting with '.' is not permitted"). Before
  `just restore-project`, add a dot-free override to the worktree's `.env`, e.g.
  `GHIDRA_PROJECT_DIR=/home/<you>/code/decomp/ghidra-worktree-projects/<name>` —
  the justfile honors the override (intended only for this case; on a normal
  checkout the vendored `vendor/ghidra` default is the source of truth).
- `just bootstrap-reccmp` is only for a machine that has never had a reccmp
  project; it refuses to overwrite the committed `reccmp-project.yml`. In a
  worktree you only need `reccmp-user.yml`.
- The `imperialism-msvc500` Docker image is machine-global, not per-worktree —
  no rebuild needed (`just lint` also runs inside it via `LINT=1`, not a
  separate image).
- `core.hooksPath` (→ `.beads/hooks`) is shared git config, not per-worktree, so
  Beads hooks/`bd prime` work as-is in a new worktree without re-running
  `bd init`.

## 1. Daily port loop (no marker/ownership changes)

Start the Ghidra query daemon once per session — every read-only evidence query
(`ghidra-listing`, `xrefs`, `ghidra-read-data`, `ghidra-function-slice`,
`ghidra-search`, `ghidra-jumptable`, `ghidra-decompile`, `ghidra-vtable-dump`, …)
then answers in ~0.2-3s instead of paying ~60-90s of JVM startup each. Any other
project open — a `MUTATES: Ghidra DB` target or a one-shot read tool — evicts it
automatically; re-warm with `just ghidra-daemon` (details in the `ghidra` skill):

```sh
just ghidra-daemon      # once; ghidra-daemon-stop / ghidra-daemon-status to manage
```

Start every task through the stateful entrypoint — it runs the investigation
(`tooling-check`, `func-status`, **`ghidra-portprep`**: owner, callers,
thunk-resolved callees + owners, virtual slots, globals, jump tables, decompile),
refuses stale bases and already-claimed/implemented targets, and writes the task
receipt to `build-msvc500/agent-task.json`:

```sh
just agent-start port 0xADDR    # mandatory front door — never start blind
```

Edit manual source (shape/data passes on already-owned functions), iterating with:

```sh
just build              # Docker MSVC500 build (runs vtable-gate first)
just compare 0xADDR     # or: just compare --file src/game/Foo.cpp
just triage 0xADDR      # below 100%? classify the diff into actionable buckets first
```

Verify + pre-commit (always):

```sh
just agent-check              # diff-aware: regen (iff markers changed), format-check,
                              # build, detect, compare+triage touched, gates, tests, stats
just stats-baseline-update    # if the stats deltas are accepted; commit the baseline with the change
just agent-finish             # machine-derived summary / PR body from the receipt
```

(`just precommit` remains the underlying build+gates+test+stats bundle.)

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
`just generate-ignores` (Hard Rule 11).
