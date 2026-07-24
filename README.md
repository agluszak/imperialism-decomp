# Imperialism (1997) Decompilation

Decompilation workspace for the Windows PC game Imperialism (1997).

## Scope

- Keep reverse-engineering outputs reproducible in git.
- Rebuild with old MSVC toolchain in Docker/Wine.
- Track matching progress with `reccmp`.

## Legal

This repo does not include original binaries or copyrighted game assets.
Use your own legally obtained copy.

Local-only layout (gitignored):

- `orig/Imperialism.exe`
- `assets/`

## Prerequisites

Install these yourself before following the Environment steps below — nothing in
this repo installs them for you:

- `git` + [`git-lfs`](https://git-lfs.com/) — the vendored Ghidra archive
  (`vendor/ghidra/exports/*.gzf`) ships via LFS.
- [`just`](https://github.com/casey/just) — every workflow in this repo is a
  `just` target; see `just --list` (grouped, with mutating targets flagged).
- [`uv`](https://docs.astral.sh/uv/) — all Python tooling runs through it
  (`uv run ...`); never invoke a bare `python`.
- `docker` — the MSVC500 build/lint toolchain runs in a container (see
  `docker/msvc500/`); nothing proprietary to fetch, `just docker-build` pulls
  the portable [archaic-msvc/msvc500](https://github.com/archaic-msvc/msvc500)
  toolchain and the DirectX 5 SDK automatically.
- `wine` (host-side, separate from the Wine installed *inside* the Docker
  image) — only needed to run/debug the recompiled `.exe` (`just run`,
  `just debug`); not required for build/gates/compare. Runtime-test failures capture
  screenshots internally as optional diagnostic artifacts.
- [Ghidra `12.1.2 PUBLIC`](https://ghidra-sre.org/) — external install; the
  project database itself is vendored (see `GHIDRA_INSTALL_DIR` below).
- [`bd` (Beads)](https://github.com/steveyegge/beads) — issue tracking used
  throughout `AGENTS.md`/`CLAUDE.md`; install with
  `curl -sSL https://raw.githubusercontent.com/steveyegge/beads/main/scripts/install.sh | bash`.

Your own legally obtained `Imperialism.exe` (see Legal above) is the only asset
you're expected to source yourself; everything else above is a normal tool
install.

## Toolchain Pins

- Ghidra: `12.1.2 PUBLIC` (see `ghidra.toml`)
- pyghidra: `3.1.0` (see `pyproject.toml`)
- reccmp: pinned to fork commit (see `pyproject.toml`)

## Primary Workflow (`just`)

Porting and fixing work goes through the stateful task commands — they run the
correct process (claim checks, investigation, verification) so you don't have to
reconstruct it:

```sh
just agent-start port 0xADDR   # investigate + claim the target, write the task receipt
just advice 0xADDR             # the most relevant active rules for this target
                               # (`just advice --diff` selects by the working diff)
just agent-check               # verify the diff: regen, format, build, compare, triage, gates, tests, stats
just agent-finish              # render the receipt into a PR-ready summary
just agent-release             # free the claim refs once the work lands
```

The underlying measurement and verification targets, usable on their own:

```sh
just tooling-check
just build && just detect && just stats   # rebuild + measure
just compare 0x004E73F0                    # targeted verbose compare (asm diff)
just triage 0x004E73F0                     # structured semantic result — read this before a raw diff
just vtable TCity                          # vtable layout vs original
just precommit                             # build + gates + tooling tests + stats, in one command
```

The full per-workflow guidance lives in `AGENTS.md` (the contract; `CLAUDE.md` is
a symlink to it) and the skills under `.claude/skills/`:

- **Workflow skills** — `decomp-loop`, `ghidra`, `quality-control`,
  `sync-pipeline`, `class-recovery`, `vtable-matching`, `run-debug`.
- **Topical skills**, loaded by what the target function contains —
  `calling-conventions`, `string-handling`, `ctors-dtors-eh`, `fp-matching`,
  `codegen-shapes`, `data-modeling`, `big-functions`, `mfc-collections`.

## Environment

First-time / fresh clone, with the [Prerequisites](#prerequisites) above already
installed:

```sh
cp .env.example .env && edit it     # set GHIDRA_INSTALL_DIR + ORIGINAL_BINARY
git lfs pull                        # fetch vendor/ghidra/exports/*.gzf
just restore-project                # recreate the live Ghidra project from the archive
just docker-build                   # build the imperialism-msvc500 image (one-time)
just bootstrap-reccmp               # generate reccmp-user.yml (gitignored, no template committed)
bd init                             # wire up the local Beads DB + git hooks (.beads/hooks)
just install-reccmp-merge-driver    # auto-regenerate conflicting progress baselines after merges/rebases
just tooling-check                  # verify the tooling surface
just build && just detect && just stats   # first build + reccmp pairing; stats should show no baseline drift
```

`.env` (gitignored) only needs the two machine-specific paths:

- `GHIDRA_INSTALL_DIR=.../ghidra_12.1.2_PUBLIC` — your Ghidra install.
- `ORIGINAL_BINARY=.../Imperialism.exe` — your own legally obtained copy (for the
  reccmp original side / `just bootstrap-reccmp`).

`.env.example` documents two further optional knobs: `MACOS_IMPERIALISM_DUMP`
(only to *regenerate* the vendored Mac CodeWarrior evidence) and
`GHIDRA_PROJECT_DIR` (only for a worktree living under a dot-directory, which
Ghidra refuses to open).

The Ghidra project itself is vendored at `vendor/ghidra` and is wired into the `just`
targets — you do **not** set `GHIDRA_PROJECT_DIR`/`GHIDRA_PROJECT_NAME`. After making
Ghidra-side changes, refresh the committed archive with `just export-project` and
commit it. Build knobs (`BUILD_DIR`, `DOCKER_IMAGE`, `CMAKE_FLAGS`, `TARGET`) have sane
defaults and can be overridden via env if needed.

Adding a new git worktree (not a fresh clone) shares the git tree but none of the
gitignored machine state above — see `docs/workflows.md` §0 for that shorter path
(copy `.env`/`reccmp-user.yml` from an existing checkout instead of regenerating them;
Docker images are machine-global, so `docker-build` isn't needed again).

## Repo Layout

Everything under `src/` and `include/` is **manually owned source** — there are no
tool-owned source trees. Generated build inputs live in the build directory.

- `src/game/`, `include/game/` — hand-written gameplay code and headers, split into
  subsystem folders per `docs/reference/subsystem_assignment.csv`
- `config/` — curated CSV/YAML state: the entity inventory, ownership and name
  overrides, recovered globals, gate allowlists, agent rules, and the reccmp
  progress baselines under `config/baselines/`
- `tools/` — Python tooling (`ghidra`, `workflow`, `reccmp`, `analysis`, `binary`,
  `mfc`, `runtime`, shared helpers)
- `just/` — the justfile modules behind `just --list` (`build`, `compare`, `gates`,
  `agent`, `sync`, `ghidra`, …)
- `tests/` — tooling unit tests (`just test`)
- `vendor/` — vendored inputs: the Ghidra `.gzf` archive (via LFS), the MSVC500
  library/FID data, Mac CodeWarrior evidence, DirectX headers
- `build-msvc500/generated/` — **generated**, not in git: the linkable stubs and
  source index, rebuilt by `just generate` / `just build`. The old
  `src/autogen/`, `src/ghidra_autogen/` and `include/ghidra_autogen/` trees are
  gone; `just build` hard-errors if a stale copy reappears.
- `build-msvc500/evidence/` — generated Ghidra reference exports
- Git commit messages are the durable change log; `docs/workflows.md` has the
  command playbooks, `docs/toolchain.md` the toolchain forensics, and
  `docs/reference/` the layout and game-domain references

## Policy

- Follow `AGENTS.md` (the contract) and the relevant skill under `.claude/skills/`.
- Use `just` targets for standard operations; don't run raw `docker` or
  `uv run reccmp-*` when a target exists.
- Keep `// FUNCTION: IMPERIALISM 0x...` marker immediately above the declaration.
- Only files carrying an `AUTO-GENERATED by tools/…` banner are tool output — do
  not hand-edit those, or anything under `build-msvc500/generated/`.
- Run `just precommit` before committing, and commit the refreshed
  `config/baselines/` stats baseline alongside source changes that move it.
