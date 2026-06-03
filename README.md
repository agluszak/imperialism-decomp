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

## Toolchain Pins

- Ghidra: `12.1 PUBLIC` (see `ghidra.toml`)
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

First-time / fresh clone (the Ghidra program ships as a vendored `.gzf` via Git LFS):

```sh
git lfs pull            # fetch vendor/ghidra/exports/*.gzf
just restore-project    # recreate the live Ghidra project from the archive
```

`.env` (gitignored) only needs the two machine-specific paths:

- `GHIDRA_INSTALL_DIR=.../ghidra_12.1_PUBLIC` — your Ghidra install.
- `ORIGINAL_BINARY=.../Imperialism.exe` — your own legally obtained copy (for the
  reccmp original side / `just bootstrap-reccmp`).

The Ghidra project itself is vendored at `vendor/ghidra` and is wired into the `just`
targets — you do **not** set `GHIDRA_PROJECT_DIR`/`GHIDRA_PROJECT_NAME`. After making
Ghidra-side changes, refresh the committed archive with `just export-project` and
commit it. Build knobs (`BUILD_DIR`, `DOCKER_IMAGE`, `CMAKE_FLAGS`, `TARGET`) have sane
defaults and can be overridden via env if needed.

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
- `docs/worklog.md` chronological execution log; `docs/toolchain.md` toolchain forensics; `docs/reference/` layout + game-domain references

## Policy

- Follow `AGENTS.md` (the contract) and the relevant skill under `.claude/skills/`.
- Use `just` targets for standard operations.
- Keep `// FUNCTION: IMPERIALISM 0x...` marker immediately above declaration.
- Do not hand-edit generated files under `src/ghidra_autogen/`, `src/autogen/stubs/`, or `include/ghidra_autogen/`.
