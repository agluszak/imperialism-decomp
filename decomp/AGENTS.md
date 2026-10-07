# Imperialism C++ reconstruction

Reconstruct the 1997 Windows retail program as plausible Visual C++ 5.0-era
source. Follow [../AGENTS.md](../AGENTS.md).

## Evidence and fidelity

- Retail code, data, ABI and behavior outrank decompiler output, recovered
  source guesses, Mac names and comparison scores.
- Mac CodeWarrior symbols/resources can establish period names and UI facts;
  they cannot establish Windows layout, addresses, virtual slots, calling
  conventions or implementation by themselves.
- MFC, CRT and other library implementations are not authored game code.
  Resolve ILT thunks to their targets; compiler/linker artifacts are not
  source functions.
- Favor normal, readable period C++ over register-/CFG-shaped tricks.
  Do not introduce dummy locals, manual inlining, instruction-order
  permutations, raw vtable calls, handwritten vptr stores, artificial
  placement construction, codegen pragmas or fake factories to raise a
  reccmp score.
- Investigate mismatches in behavior, serialization, state, RNG, ABI,
  field widths/layout, class ownership, construction, virtual dispatch and
  resource indexing. Once observable contracts agree, compiler-only
  differences do not justify unfaithful changes.
- Preserve demonstrated retail quirks, bugs and undefined behavior;
  do not modernize the historical reconstruction.

## Source model

- Use VC5-compatible syntax and actual source-level types, including MFC
  types. Verify receiver, calling convention, virtual slots, object layout,
  base/member construction and destruction from evidence.
- Define class behavior on its owner, model inheritance and real member
  objects, and keep one canonical owner for each global and function.
  Ordinary callers include the owning headers.
- Never claim an unknown name, field, union or inheritance edge solely
  from an offset, similar spelling, or coincident storage.
- `// FUNCTION: IMPERIALISM 0x...` binds the following declaration.
  Compiler emissions belong in `config/compiler_emissions.csv`, not
  invented C++ definitions or SYNTHETIC/TEMPLATE bodies.
- `include/game/` and `src/game/` are manually owned unless an explicit
  generated-file banner says otherwise. Edit generation inputs, not outputs.
- Keep comments for genuinely non-obvious retail evidence, not a narration
  of already understood code or a history of attempted reconstructions.

## Tools and checks

Ghidra owns reviewed binary analysis; source declarations and the source
index own the reconstructed model; reccmp/Ghidriff own pairing and diffs.
Do not add parallel inventories, replay pipelines or surrogate truth stores.

Use `just --list` for commands and `docs/ghidra-db.md` for reviewed
Ghidra state. Build and compare relevant affected code in batches.
Run focused validation during work and `just precommit` for substantial
changes. Treat failures as problems in the owning model or tools, not as
reasons for new waivers.
