# Ghidra Export Scripts

These scripts are intended to keep naming progress out of the `.gpr` database and inside version control.

## Version Pin

This tooling is intentionally pinned to:

- Ghidra `12.0.2 PUBLIC`

Both Python scripts and the headless wrapper fail fast on any other Ghidra version.

## Scripts

- `ExportUserSymbols_GhidraImport.py`
- `ExportReccmpCsv_SmartSizes.py`
- `export_from_ghidra_headless.py`

## How To Use

1. In Ghidra Script Manager, add this directory to your script paths.
2. Open Imperialism program in your project.
3. Run `ExportUserSymbols_GhidraImport.py` to produce a `.ghidra` symbols text file.
4. Run `ExportReccmpCsv_SmartSizes.py` to produce `symbols.csv` for reccmp bootstrap.
5. Commit both exports in git (for example under `config/`).

Both Python scripts also accept one optional argument:

- `arg[0]`: output file path

If omitted, they show a save-file dialog.

## Headless Export

Use `export_from_ghidra_headless.py` to regenerate both exports without GUI prompts.

Example:

```bash
uv run python tools/ghidra/export_from_ghidra_headless.py \
  --ghidra-install-dir /path/to/ghidra_12.0.2_PUBLIC \
  --ghidra-project-dir /path/to/ghidra/projects \
  --ghidra-project-name imperialism-decomp \
  --ghidra-program-name Imperialism.exe
```

Defaults:

- `OUTPUT_DIR=<repo>/config`

## Notes

- Both scripts export only `USER_DEFINED` symbols by default.
- Names with whitespace are skipped to keep compatibility with common importers.
- The reccmp CSV exporter emits function sizes in decimal bytes.
