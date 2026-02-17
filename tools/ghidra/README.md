# Ghidra Sync

This directory intentionally uses a single export entrypoint:

- `sync_exports.py` (Python CLI, runs through `pyghidra`)
- `SyncExports_Ghidra.py` (script executed inside Ghidra runtime)

## Version Pin

The single source of truth is `ghidra.toml` in the repository root:

- `[ghidra].version`
- `[ghidra].release`
- `[ghidra].program_name`

`sync_exports.py` validates both:

- local `pyghidra` version (`3.0.2`)
- target Ghidra install version/release from `application.properties`

## Usage

```bash
uv run python tools/ghidra/sync_exports.py \
  --ghidra-install-dir /path/to/ghidra_12.0.2_PUBLIC \
  --ghidra-project-dir /path/to/ghidra/projects \
  --ghidra-project-name imperialism-decomp \
  --ghidra-program-name Imperialism.exe \
  --output-dir config \
  --decomp-output-dir src/ghidra_autogen \
  --types-output-dir include/ghidra_autogen \
  --decomp-max-functions-per-file 250 \
  --name-overrides config/name_overrides.csv
```

Outputs:

- `config/symbols.ghidra.txt`
- `config/symbols.csv`
- `src/ghidra_autogen/*.cpp` (+ manifest/index)
- `include/ghidra_autogen/*.h` (+ manifest/index)

If `config/name_overrides.csv` exists, `sync_exports.py` reapplies overrides after export to:

- `config/symbols.csv`
- `config/symbols.ghidra.txt` (function names only; whitespace names are skipped)
- `src/ghidra_autogen/index.csv`

## Notes

- Exported `ghidra_autogen` trees are regenerated and stale generated files are removed.
- `src/ghidra_autogen` is snapshot/reference output; manual edits should go to non-autogen source files.
- `src/ghidra_autogen` uses `GHIDRA_FUNCTION` metadata comments (not `FUNCTION/STUB`) so reccmp annotations come only from compilable source files.
