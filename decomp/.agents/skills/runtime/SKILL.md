---
name: runtime
description: Run and debug retail/recomp runtime scenarios.
---

# Runtime

Run from `decomp/` with `ORIGINAL_BINARY` configured.

- Launch with `just run-original` or `just run`.
- Use `just runtime-run NAME`, `just runtime-test NAME`, and `just runtime-test-suite pr|full`.
- Compare with `just diff-run SCENARIO` or `just native-oracle CASE`.
- Inspect UI state with `just runtime-tree NAME`.
- Debug with `just debug` or `just gdb-script ARGS`.
- Add a scenario only for a useful recurring regression, and keep it deterministic.
