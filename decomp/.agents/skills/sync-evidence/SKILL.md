---
name: sync-evidence
description: Synchronize Imperialism source ownership, generated build inputs, and Ghidra evidence under decomp/.
---

# Synchronize evidence

Run from `decomp/`.

- Manual C++ source is manually owned. Generated stubs, indexes, and build evidence are outputs; never
  edit them to clear a failure.
- For source-marker or ownership changes, use `just build` to regenerate inputs from the current source.
- For an intentional Ghidra/inventory refresh, use the matching `just` sync command, inspect the
  evidence change, and export the project deliberately.
- Fix the real cause of a failed sync—wrong ownership, thunk, type, extent, or stale database label—at
  its source. Do not add a compatibility layer or a generated-file exception.
