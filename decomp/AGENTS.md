# Imperialism C++ reconstruction

This directory reconstructs the Windows retail executable as period-correct Visual C++ 5.0 source.
Follow `../AGENTS.md` plus these invariants.

## Invariants

- The Windows retail binary, resources, control flow, and live behavior win over decompiler output,
  existing source, names, signatures, and comparison scores.
- Behavior and source model come before code generation. Treat reccmp as a diagnostic, not an
  optimization target. Do not tune source for register allocation, instruction ordering, loop shape,
  temporary placement, inlining, or other compiler noise.
- Preserve observable ABI and representation: calling conventions, field order and widths, padding,
  construction/destruction order, virtual slot order, serialization, and ownership.
- Recover normal typed C++ that plausibly represents the original source. Remove decompiler scaffolding
  once the model is known; do not encode compiler accidents as source constructs.
- Use only Visual C++ 5.0-compatible syntax. Do not use inline assembly or per-function compiler tricks
  to force a match.
- Mac CodeWarrior evidence may establish source-era names and signatures, but not Windows addresses,
  calling conventions, vtables, inheritance, or implementation behavior.
- MFC and other Windows-library code is not gameplay source. Resolve import thunks to their library
  targets rather than reconstructing them as game functions.
- Keep one manual implementation per retail address. Put `// FUNCTION: IMPERIALISM 0x...` immediately
  before recovered declarations. Change generators or source metadata rather than hand-editing
  generated outputs.
- Do not hide gaps with approximations, fake bridges, mismatch ignores, or allowlists. Fix the source,
  ABI, ownership, data, resources, or control flow that actually diverges.

Use the `ghidra`, `runtime`, and `verify` skills when needed.
