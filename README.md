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
  `just` target; see `just --list`.
- [`uv`](https://docs.astral.sh/uv/) — all Python tooling runs through it
  (`uv run ...`); never invoke a bare `python`.
- `docker` — the MSVC500 build/lint toolchain runs in a container (see
  `docker/msvc500/`); nothing proprietary to fetch, `just docker-build` pulls
  the portable [archaic-msvc/msvc500](https://github.com/archaic-msvc/msvc500)
  toolchain and the DirectX 5 SDK automatically.
- `wine` (host-side, separate from the Wine installed *inside* the Docker
  image) — only needed to run/debug the recompiled `.exe` (`just run`,
  `just debug`, `just screenshot`); not required for build/gates/compare.
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

```sh
just tooling-check
just build && just detect && just stats   # rebuild + measure
just compare 0x004E73F0                    # targeted verbose compare
just compare-canaries                      # regression check
```

The full per-workflow guidance lives in `AGENTS.md` and the skills under
`.claude/skills/` (`decomp-loop`, `ghidra`, `quality-control`, `class-recovery`).

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
just tooling-check                  # verify the tooling surface
just build && just detect && just stats   # first build + reccmp pairing; stats should show no baseline drift
```

`.env` (gitignored) only needs the two machine-specific paths:

- `GHIDRA_INSTALL_DIR=.../ghidra_12.1.2_PUBLIC` — your Ghidra install.
- `ORIGINAL_BINARY=.../Imperialism.exe` — your own legally obtained copy (for the
  reccmp original side / `just bootstrap-reccmp`).

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

- `src/game/` manual-owned gameplay code
- `src/ghidra_autogen/` regenerated decompiler output (not hand-edited)
- `src/autogen/stubs/` regenerated unresolved stubs
- `include/game/` manual/shared headers
- `include/ghidra_autogen/` regenerated datatype headers
- `config/` symbols, ownership, vtable slot registry, workflow manifests
- `tools/` Python tooling (`ghidra`, `workflow`, `reccmp`, shared helpers)
- `vendor/` vendored binary assets (Ghidra `.gzf` archive via LFS, Mac CodeWarrior evidence)
- `.claude/skills/` per-workflow guides (`decomp-loop`, `ghidra`, `quality-control`, `class-recovery`)
- Git commit messages are the durable change log; `docs/toolchain.md` toolchain forensics; `docs/reference/` layout + game-domain references

## Policy

- Follow `AGENTS.md` (the contract) and the relevant skill under `.claude/skills/`.
- Use `just` targets for standard operations.
- Keep `// FUNCTION: IMPERIALISM 0x...` marker immediately above declaration.
- Do not hand-edit generated files under `src/ghidra_autogen/`, `src/autogen/stubs/`, or `include/ghidra_autogen/`.
