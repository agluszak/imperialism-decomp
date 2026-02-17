# Imperialism (1997) Decompilation

This repository is a decompilation project for the Windows PC game Imperialism (1997).

## Goals

- Reconstruct readable C/C++ source from the original executable.
- Rebuild a binary that behaviorally matches the original.
- Keep reverse-engineering progress in git (code, symbols, scripts), not only in a Ghidra project.

## Legal / Game Files

This repository does not include:

- Original binaries (`Imperialism.exe`)
- Copyrighted game assets

Use your own legally obtained copy of the game.

Recommended local layout (ignored by git):

- `orig/Imperialism.exe` (original binary)
- `assets/` (optional extracted assets)

## Current Status

- Reverse engineering: in progress
- Recompilation: in progress
- Matching: in progress

## Tooling

- Ghidra `12.0.2 PUBLIC` for analysis (pinned for script compatibility)
- Custom scripts in `tools/ghidra/` to export symbols from your project database
- `reccmp` for build-vs-original comparison
- CMake for build orchestration
- `uv` + `pyproject.toml` for Python tooling and dependency management

## Quick Start

1. Run Ghidra script `tools/ghidra/ExportUserSymbols_GhidraImport.py`.
2. Commit the exported `.ghidra` symbol text file (for re-import into clean projects).
3. Run `tools/ghidra/ExportReccmpCsv_SmartSizes.py`.
4. Commit the generated `symbols.csv` in `config/`.
5. Start reconstructing code in `src/` and annotate functions with addresses.

Headless one-shot export is also available:

```bash
uv run python tools/ghidra/export_from_ghidra_headless.py \
  --ghidra-install-dir /path/to/ghidra_12.0.2_PUBLIC \
  --ghidra-project-dir /path/to/project-parent \
  --ghidra-project-name imperialism-decomp \
  --ghidra-program-name Imperialism.exe
```

Example function annotation:

```cpp
// FUNCTION: IMPERIALISM 0x401000
```

## Build

For old Win32 games, matching often requires an old MSVC toolchain (for example, VC 4.x/5.x/6.x era). The exact Imperialism toolchain is tracked in `docs/toolchain.md`.

This repo currently includes a minimal bootstrap target:

- `CMakeLists.txt`
- `src/main.cpp`
- output target name: `Imperialism`

Example configure and build from an MSVC prompt:

```bat
mkdir build
cd build
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
nmake
```

## Compare with reccmp

High-level workflow:

1. Keep original binary local (`orig/Imperialism.exe`), not committed.
2. Export/update `config/symbols.csv` from Ghidra.
3. Build your reconstructed target binary.
4. Run `reccmp` against original vs rebuilt and review matches/mismatches.

Install/bootstrap helper:

```bash
uv run python tools/reccmp/bootstrap_reccmp.py \
  --original-binary /absolute/path/to/Imperialism.exe
```

If `ORIGINAL_BINARY` is provided, this bootstraps `reccmp-project.yml` and `reccmp-user.yml` via `reccmp-project create --scm`.

Use `config/reccmp-project.yml.example` as a temporary starter only when you are not generating files through `reccmp-project`.

Run reccmp tools through uv dependency group:

```bash
uv run --group reccmp reccmp-project --help
uv run --group reccmp reccmp-reccmp --help
```

Rich-header sanity check helper:

```bash
uv run python tools/forensics/check_rich_header.py /absolute/path/to/Imperialism.exe
```

## Repository Layout

```text
src/                    reconstructed code
include/                headers and recovered types
config/                 symbol exports and reccmp config
tools/ghidra/           ghidra export/import helper scripts
tools/reccmp/           reccmp bootstrap helpers
docs/                   methodology and toolchain notes
```

## Contributing

- Do not commit original binaries or copyrighted assets.
- Prefer small, focused commits (rename pass, struct layout, small function batch).
- If names changed in Ghidra, re-export and commit updated symbol artifacts in the same commit.
