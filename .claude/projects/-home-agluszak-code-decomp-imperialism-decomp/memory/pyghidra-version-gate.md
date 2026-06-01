---
name: pyghidra-version-gate
description: sync-ghidra aborts on a hard-coded pyghidra version constant that drifts from pyproject
metadata:
  type: project
---

`tools/ghidra/sync_exports.py` has `EXPECTED_PYGHIDRA_VERSION` hard-coded as a module
constant (was "3.0.2") and raises "Unsupported pyghidra runtime" if `pyghidra.__version__`
differs. It is a second source of truth separate from `pyproject.toml` (which pins the real
version) and from `ghidra.toml` (which the same script reads for the Ghidra version).

**Why:** As of the 12.0.2→12.1 / pyghidra 3.0.2→3.1.0 migration this constant was NOT
bumped, so `just sync-ghidra` aborts before doing anything. It will drift again on every
future pyghidra bump.

**How to apply:** When bumping pyghidra in `pyproject.toml`, also update this constant (or
better, derive it from pyproject so there is one source of truth). The Ghidra version is
already done right — read from `ghidra.toml`. See [[knowledge-db-impk-external]].
