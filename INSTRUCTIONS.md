# Imperialism Decomp Working Instructions

## Naming and Identifier Policy

1. Do not rename variables, parameters, or helper identifiers for style-only reasons.
2. Do not convert exported code to snake_case/camelCase just to match personal preference.
3. Keep naming aligned with Ghidra export unless there is a meaningful semantic reason to change.
4. Acceptable renames are limited to:
   - fixing clearly wrong names (e.g. bad auto-name collisions),
   - applying domain meaning discovered during reverse engineering,
   - unifying wrappers/library prefixes (`Afx_`, `Mfc_`, `Crt_`, `Dx_`) for scope classification.
5. If a rename is meaningful, capture it in Ghidra and re-export so snapshots and source stay in sync.

## Source of Truth

1. Ghidra is the canonical source for recovered names, prototypes, comments, and type information.
2. `src/ghidra_autogen/` and `include/ghidra_autogen/` are regenerated snapshots from Ghidra.
3. Manual files in `src/game/` should preserve exported naming unless there is an explicit RE-driven reason not to.

## Sync Rule

After meaningful renames in Ghidra, run export sync and then continue implementation:

```bash
uv run python tools/ghidra/sync_exports.py \
  --ghidra-install-dir <GHIDRA_DIR> \
  --ghidra-project-dir <GHIDRA_PROJECT_DIR> \
  --ghidra-project-name <GHIDRA_PROJECT_NAME> \
  --ghidra-program-name Imperialism.exe
```
