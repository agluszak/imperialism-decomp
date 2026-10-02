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
4. Continue through a coherent family of roughly 50–100 affected functions when feasible. Use
   saved reports and focused retail reads rather than rebuilding after each body.
5. Rebuild/compare once for the batch with `just build` and `just compare --changed`. Inspect the
   saved Ghidriff evidence, then use the `verify` skill for final checks.
