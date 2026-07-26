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
just vendor-msvc500-headers                   # gitignored MSVC/MFC header mirror; the class model needs it
just restore-project                          # recreate the live Ghidra project from vendor/ghidra/exports/*.gzf
just install-reccmp-merge-driver              # one-time local Git config; shared by worktrees
just tooling-check                            # verify the tooling surface
just build && just detect && just stats       # first build + reccmp pairing; stats should show no baseline drift
```

Notes:
- **Skipping `just vendor-msvc500-headers` fails a gate in a confusing way.** Without the
  mirror, `tools.class_model` cannot resolve `CString` members, so ~28 classes silently
  drop out of the CString owner inventory and `just cstring-ownership-audit-check` reports
  a long `removed=[...]` list plus `TStaticText: layout-affecting declaration changed`.
  Nothing is actually stale — a long-lived checkout can even mask this by keeping an old
  `build-msvc500/generated/record_model.json`. Populate the mirror, rerun
  `just cstring-ownership-audit`, and the regenerated snapshot matches the committed one.
  Do **not** commit a shrunken `config/cstring_layout.csv`.
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
- The reccmp baseline driver config is also shared by worktrees. `.gitattributes`
  routes conflicts in the two generated progress baselines through that driver; it
  preserves a valid side and marks regeneration pending. The tracked post-merge,
  post-rewrite, and post-commit hooks then run `just build` plus
  `just stats-baseline-update` once the integrated tree is complete. The regenerated
  files remain unstaged for review. Set `IMPERIALISM_SKIP_RECCMP_BASELINE_REFRESH=1`
  to defer an expensive refresh; the pending marker remains for the next hook run.

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
just triage 0xA 0xB     # batch related functions; filtered run with validated setup cache
```

Verify + pre-commit (always):

```sh
just agent-check              # diff-aware: format-check, build+regen, detect, gates+stats,
                              # extract touched scores, triage mismatches, then unit tests
just stats-baseline-update    # accepts the hash-verified report; commit the refreshed baseline
just agent-finish             # machine-derived summary / PR body from the receipt
```

(`just precommit` is the complete local verification bundle: matching and runtime
builds, all gates, the lint rejection fixture, tooling tests, merge-base generated-
artifact integrity, and the asset-backed PR runtime suite. The gates run the single
full progress report used by both stats and generated-UI regression checks.)
Unchanged generated build inputs preserve their mtimes, so a no-op rebuild also
preserves the EXE/PDB identity and can reuse that report.

## 2. After editing markers / ownership

Whenever you add, remove, or move a `// FUNCTION:` / `// STUB:` / `// SYNTHETIC:` /
`// LIBRARY:` marker:

```sh
just build          # regenerates build inputs (source index + stubs) automatically
```

There is no separate sequence to remember: markers in source ARE the ownership
authority — generation scans them directly; nothing else needs syncing.

## 3. Full Ghidra DB resync

After meaningful source-model changes (new classes, renames, vtable
annotations), mirror the model into the analysis workspace:

```sh
just ghidra-apply-source            # dry-run: what would change
just ghidra-apply-source-full      # build -> apply --apply -> export-project
```

This is the ONE source->Ghidra operation: names from source declarations
(inventory names as fallback), class namespaces, `Class::'vftable'` labels, and
a datatype-drift audit. There is no automated Ghidra->source path — discoveries
in Ghidra are evidence you port into source by hand.

After an intentional DB *boundary* mutation (`repair-code-gaps --apply`,
function-bounds fixes), refresh the raw inventory wholesale:

```sh
just refresh-inventory   # prune ILT -> export original_entities.csv -> gates
just export-project      # persist the .gzf before committing
```

## Name and ownership state — who owns what

| State | File | Written by |
|---|---|---|
| Raw entity inventory (reccmp entity list) | `config/original_entities.csv` (advisory names; wholesale refresh) | overlay generated to `build-msvc500/generated/symbols.csv` by `just generate` |
| Address ownership (stub suppression) | source markers (scanned at build time) | `just generate` (runs inside `just build`) |
| Provisional names, disassembly ground truth | vendored Ghidra DB | `ghidra-apply-source`, DB-mutating targets (`ghidra-db` group) |

Renamed targets (old names remain as aliases): `stats-commit` →
`stats-baseline-update`. `just session-loop` is
now read-only; ignore-list rewriting requires `--refresh-ignore` or
`just generate-ignores` (Hard Rule 11).
