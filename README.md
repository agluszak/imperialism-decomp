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

- Ghidra: `12.0.2 PUBLIC` (see `ghidra.toml`)
- pyghidra: `3.0.2` (see `pyproject.toml`)
- reccmp: pinned to fork commit (see `pyproject.toml`)

## Primary Workflow (`just`)

1. `just tooling-check`
2. `just sync-ghidra`
3. `just sync-ownership`
4. `just regen-stubs`
5. `just build`
6. `just detect`
7. `just stats`

Targeted compare:

- `just compare 0x004E73F0`
- `just compare-canaries`

Promotion:

- `just promote src/game/TGreatPower.cpp --address 0x004E73F0`
- `just promote-range src/game/TGreatPower.cpp 0x004E72C0 0x004E73F0`

## Environment

Create `.env` (gitignored) with at least:

- `GHIDRA_INSTALL_DIR=.../ghidra_12.0.2_PUBLIC`
- `GHIDRA_PROJECT_DIR=...`
- `GHIDRA_PROJECT_NAME=...`
- `ORIGINAL_BINARY=.../Imperialism.exe`

Optional overrides:

- `BUILD_DIR`
- `DOCKER_IMAGE`
- `CMAKE_FLAGS`
- `TARGET`

## Repo Layout

- `src/game/` manual-owned gameplay code
- `src/ghidra_autogen/` regenerated decompiler output (not hand-edited)
- `src/autogen/stubs/` regenerated unresolved stubs
- `include/game/` manual/shared headers
- `include/ghidra_autogen/` regenerated datatype headers
- `config/` symbols, ownership, vtable slot registry, workflow manifests
- `tools/` Python tooling (`ghidra`, `workflow`, `reccmp`, shared helpers)
- `docs/control_plane.md` current strategy + canonical command set
- `docs/worklog.md` concise chronological execution log

## Policy

- Follow `INSTRUCTIONS.md` and `AGENTS.md`.
- Use `just` targets for standard operations.
- Keep `// FUNCTION: IMPERIALISM 0x...` marker immediately above declaration.
- Do not hand-edit generated files under `src/ghidra_autogen/`, `src/autogen/stubs/`, or `include/ghidra_autogen/`.
