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
- Optional autogen snapshot export:
  - decompiled function bodies (`src/ghidra_autogen/`)
  - split local datatype headers (`include/ghidra_autogen/`)
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
  --ghidra-program-name Imperialism.exe \
  --export-decompiled-bodies \
  --decomp-output-dir src/ghidra_autogen \
  --export-type-headers \
  --types-output-dir include/ghidra_autogen
```

Generated snapshot files are overwritten on each export. Keep manual reconstruction work outside `src/ghidra_autogen/`.

To start editing a function body, promote it into a manual file first:

```bash
uv run python tools/workflow/promote_from_autogen.py \
  --address 0x00401000 \
  --target-cpp src/game/bootstrap.cpp
```

Example function annotation:

```cpp
// FUNCTION: IMPERIALISM 0x401000
```

## Build

For old Win32 games, matching requires an old MSVC toolchain. Based on current fingerprints, this project starts with VC5-style toolchains first and keeps VC4.2 as fallback (`docs/toolchain.md`).

This repository includes bootstrap build plumbing:

- `CMakeLists.txt`
- `src/main.cpp`
- `src/autogen/stubs.cpp` (generated)
- `include/decomp_types.h`
- output target name: `Imperialism`

### Docker + Wine (Linux host, MSVC 5.0)

Build image:

```bash
docker build -t imperialism-msvc500 -f docker/msvc500/Dockerfile docker/msvc500
```

Build project:

```bash
mkdir -p build-msvc500
docker run --rm \
  -e CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo" \
  -v "$PWD":/imperialism \
  -v "$PWD/build-msvc500":/build \
  imperialism-msvc500
```

See `docker/msvc500/README.md` for details.

### Native CMake (non-matching bring-up)

```bash
cmake -S . -B build
cmake --build build
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

Generate/update autogen stubs from exported symbols:

```bash
uv run python tools/stubgen.py
```

`tools/stubgen.py` skips any function address already annotated in `src/**/*.cpp`, so implemented functions are not duplicated in `src/autogen/stubs.cpp`.

## Tight Loop

Recommended iteration cycle:

1. Rename/type functions in Ghidra.
2. Export with `tools/ghidra/export_from_ghidra_headless.py` or GUI scripts.
3. Optionally regenerate decompiled snapshot + split type headers from Ghidra:
   - `src/ghidra_autogen/*.cpp`
   - `include/ghidra_autogen/*.h`
4. Regenerate autogen stubs (`uv run python tools/stubgen.py`).
5. Move one function from stubs into real source file and implement it.
6. Change marker from `// STUB: IMPERIALISM 0x...` to `// FUNCTION: IMPERIALISM 0x...`.
7. Keep functions in each translation unit sorted by original address.
8. Build and compare with `uv run --group reccmp reccmp-reccmp --target IMPERIALISM`.

One-command helper for the loop:

```bash
uv run python tools/workflow/decomp_loop.py \
  --export-ghidra \
  --ghidra-install-dir /path/to/ghidra_12.0.2_PUBLIC \
  --ghidra-project-dir /path/to/ghidra/projects \
  --ghidra-project-name imperialism-decomp \
  --export-ghidra-decompiled-bodies \
  --decomp-max-functions-per-file 250 \
  --export-ghidra-type-headers \
  --detect-recompiled \
  --compare-target IMPERIALISM
```

Rich-header sanity check helper:

```bash
uv run python tools/forensics/check_rich_header.py /absolute/path/to/Imperialism.exe
```

## Repository Layout

```text
src/                    reconstructed code
src/ghidra_autogen/     generated decompiler snapshot (overwritten by export)
include/                headers and recovered types
include/ghidra_autogen/ generated split datatype headers (overwritten by export)
config/                 symbol exports and reccmp config
docker/                 reproducible old-MSVC build images
tools/forensics/        binary fingerprint helpers
tools/ghidra/           ghidra export/import helper scripts
tools/reccmp/           reccmp bootstrap helpers
tools/stubgen.py        autogen stubs generator
tools/workflow/         decompilation iteration helpers
docs/                   methodology and toolchain notes
```

## Contributing

- Do not commit original binaries or copyrighted assets.
- Prefer small, focused commits (rename pass, struct layout, small function batch).
- If names changed in Ghidra, re-export and commit updated symbol artifacts in the same commit.
