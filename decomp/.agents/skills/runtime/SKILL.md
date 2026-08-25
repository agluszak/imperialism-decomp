---
name: runtime
description: Run, compare, debug, and author focused Wine runtime scenarios for the Imperialism C++ reconstruction.
---

# Work with the runtime

Run from `decomp/` with `ORIGINAL_BINARY` configured.

- Launch retail with `just run-original` and the recomp with `just run`.
- Run an existing scenario without rebuilding via `just runtime-run NAME`; rebuild and run it via
  `just runtime-test NAME`. Use `just runtime-test-suite pr` or `full` for a catalog suite.
- Inspect the last captured UI hierarchy with `just runtime-tree NAME`.
- Compare a native recomp checkpoint with retail using `just diff-run SCENARIO`.
- Run a model transition through the shared native oracle with `just native-oracle CASE`.
- Debug the recomp with `just debug`, or use `just gdb-script ARGS` for a scripted session.
- Scaffold a genuinely recurring new scenario with `just runtime-new NAME --base BASE`, then replace
  the skeleton with the real fixture, event flow, semantic assertions, and catalog evidence kind.

Reproduce the smallest real path, compare the observable checkpoint, and keep the regression scenario
deterministic. A scenario proves only the path it executes; combine it with source/listing evidence for
a retail-faithfulness claim.
