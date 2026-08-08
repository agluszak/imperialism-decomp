# Imperialism C++ reconstruction

`decomp/` is the behaviorally and ABI-faithful C++ reconstruction of the Windows retail game
Imperialism (1997). It is a sibling of the independent Rust implementation in `../rust/`. Run the
commands below from this directory.

The retail executable is the compatibility target. This project rebuilds with the MSVC 5.0 toolchain,
uses Ghidra for binary evidence, and uses reccmp to compare the result. It does not contain a retail
binary or copyrighted game assets; use your own legally obtained copy.

## Prerequisites

- `git` and `git-lfs` for the vendored Ghidra archive.
- `just` for project commands and `uv` for Python tools.
- Docker for the MSVC500 build, Wine plus GDB/MI for the native runtime suite, and Ghidra 12.1.2.
- `bd` (Beads) for task tracking.

## First setup

```sh
cp .env.example .env             # set GHIDRA_INSTALL_DIR and ORIGINAL_BINARY
git lfs pull
just vendor-msvc500-headers
just restore-project
just docker-build
just bootstrap-reccmp
bd prime
just build
```

`ORIGINAL_BINARY` must point at your legally obtained `Imperialism.exe`. The optional
`MACOS_IMPERIALISM_DUMP` is only for regenerating vendored Mac evidence. A new worktree needs its own
`.env` and `reccmp-user.yml`, but can reuse the Docker image and the local Ghidra installation.

## Daily recovery loop

```sh
bd update <issue> --claim
just ghidra portprep 0xADDR
# inspect retail evidence and edit ordinary VC5-compatible C++
just build
just triage 0xADDR
just precommit
```

Use `just compare 0xADDR` only when the structured triage result needs a raw diff. `just vtable`,
`just datacmp`, `just stackcmp`, and `just serde-audit` are focused diagnostics. `just precommit` is
the required full verification: build, source gates, tooling tests, generated-input integrity, and the
asset-backed runtime suite.

The scoped rules are in `AGENTS.md`. The six focused skills under `.agents/skills/` cover function
recovery, class recovery, Ghidra, verification, runtime behavior, and source/evidence synchronization.

## Layout

- `src/`, `include/` — manually owned C++ source.
- `config/` — current inventory and recovery evidence.
- `tools/ghidra/`, `tools/runtime/` — active retail evidence and runtime tools; generation and direct
  comparison helpers live alongside them.
- `just/` — project commands; use `just --list` to discover them.
- `vendor/` — Ghidra archive, MSVC500 inputs, and recovered Mac evidence.
- `build-msvc500/` and `build-runtime-tests/` — generated local output, never hand-edit.

For deliberate Ghidra database changes, use the matching mutation command, inspect it, then export the
project through the sync workflow. Source markers remain the ownership authority; `just build`
regenerates the derived build inputs from them.
