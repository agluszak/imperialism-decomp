---
name: ghidra
description: Query or update the vendored Imperialism Ghidra project.
---

# Ghidra

Run from `decomp/`.

- Query with `just ghidra <command> ...`; use the daemon for repeated inspection.
- Treat database names and signatures as evidence, not authority over the retail binary.
- For deliberate database edits, follow `docs/ghidra-db.md`.
- Persist confirmed changes with `just export-project`; reconstruct with `just restore-project`.
