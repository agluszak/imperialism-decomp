---
name: decompile-function
description: Recover one Imperialism C++ function from retail evidence and verify it with the direct build and reccmp loop under decomp/.
---

# Decompile a function

Run from `decomp/`.

1. Inspect `just ghidra portprep 0xADDR` and `just ghidra listing 0xADDR`. Resolve the actual function
   body and record receiver setup, arguments, return convention, stack cleanup, constants, strings,
   data references, callees, and relevant callers.
2. Locate the manual source owner and related type declarations. Read
   [cpp-recovery.md](references/cpp-recovery.md) for calls, exceptions, ownership, MFC, or layout, and
   [matching.md](references/matching.md) for recurring VC5 code-generation shapes.
3. Implement the evidenced behavior and source model according to `AGENTS.md`.
4. Run `just build`, then `just triage 0xADDR` (or `just triage --file path`). Use the structured
   status to decide whether to revise source, inspect more evidence, or diagnose pairing/comparison.
5. Repeat through a coherent recovery, then use the `verify` skill for final checks.
