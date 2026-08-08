---
name: decompile-function
description: Recover one Imperialism C++ function from retail evidence and verify it with the direct build and reccmp loop. Use for function ports, body mismatches, signatures, ownership, and code-generation questions under decomp/.
---

# Decompile a function

Run from `decomp/` and follow `AGENTS.md`.

1. Claim the Bead, then inspect `just ghidra portprep 0xADDR` and `just ghidra listing 0xADDR`.
   Resolve ILT thunks and verify receiver, arguments, return convention, constants, strings, and
   data references from the instructions. Names and decompilation are hypotheses, not proof.
2. Recover the current retail behavior in ordinary VC5-compatible C++. Model real fields, classes,
   virtual calls, construction, and ownership. Do not preserve a stub, add a workaround, or invent a
   bridge merely to improve a score.
3. Build after a coherent change: `just build`. Diagnose it with `just triage 0xADDR`; only
   `mismatch` is source-recovery evidence. `effective` is proved harmless and `inconclusive` calls
   for evidence or comparator investigation.
4. Repeat until the source expresses the retail behavior, then format touched paths and run
   `just precommit` before committing.

Read [matching.md](references/matching.md) for recurring VC5 shape issues and
[cpp-recovery.md](references/cpp-recovery.md) when calls, EH, ownership, MFC, or layout matter.
