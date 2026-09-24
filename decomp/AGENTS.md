# Imperialism C++ reconstruction

This directory reconstructs the Windows retail executable as period-correct C++ built with Visual
C++ 5.0. Follow `../AGENTS.md` plus these reconstruction invariants.

## Retail evidence

- The retail binary, instructions, resources, control flow, and live behavior win. Decompiler output,
  existing source, names, signatures, and comparison scores are hypotheses when they disagree.
- A recomp-only bug indicates unfaithful source, data, layout, ownership, resources, or control flow.
  Restore the retail model instead of suppressing the symptom.
- Resolve import lookup table thunks to their targets. ILT thunks are linker output, not source
  functions.
- Mac CodeWarrior evidence may establish source-era names and signatures. It does not establish
  Windows addresses, calling conventions, vtables, inheritance, or implementation behavior.
- MFC and other Windows-library code is not gameplay source. Identify it as library code and use the
  vendored MSVC 5 headers for its real interface.
- Preserve source that expresses the evidenced retail model even when raw matching is inconclusive.
  Investigate pairing, metadata, unsupported control flow, alignment, and code generation rather than
  distorting the model for a score.
- Behavior before code generation. reccmp raw similarity is a diagnostic, not an optimization
  target. Do not change source solely to reproduce register allocation, instruction order, loop
  rotation, equivalent branch structure, temporary placement, equivalent arithmetic, switch-table
  layout, or inline/out-of-line decisions. Do not use manual inlining or per-function compiler
  controls for this purpose. A mismatch is actionable when evidence shows a difference in behavior,
  ABI, object/type model, state mutation, serialization, virtual dispatch, resource/table indexing,
  PRNG consumption, or another observable contract. Once those agree, residual code-generation
  differences are acceptable.
- Before modifying an already implemented low-scoring function, state the hypothesized semantic
  divergence. If you cannot identify one, do not modify the function merely to improve its score.
- No function is too large or complex to recover. Use focused evidence rather than leaving a stub,
  approximation, or test-only bypass.

## Reconstruction quality

Recovered source has two independent quality requirements: it must explain retail semantics/ABI and
it must look like plausible period source rather than a transcription of compiler output. Prefer the
simplest Visual C++ 5.0-era C++ that explains both.

Work upward through this reconstruction ladder:

1. establish retail behavior and control/data dependencies;
2. recover the correct ABI, types, ownership, layout, and object model;
3. rewrite decompiler-shaped code into plausible source without changing those contracts;
4. pursue exact or equivalent code generation only where it follows naturally from that source.

Do not encode compiler accidents as source constructs. In particular, do not introduce dummy locals,
manual spills, operand permutations, artificial scopes, decompiler labels, manual inlining,
countdown loops, byte views, or compiler pragmas merely to reproduce instruction selection or register
allocation. A low-level construct is appropriate only when it represents an evidenced source-level
concept or observable representation.

Classify a meaningful reccmp divergence before editing source:

- **semantic/ABI divergence** — fix the model or implementation;
- **representation divergence** — investigate field widths, signedness, layout, serialization,
  ownership, aliasing, or calling convention;
- **compiler-only divergence** — keep the natural source and stop tuning it.

Representation ugliness may be real. Packed records, byte payloads, unions, non-standard destruction,
and other awkward constructs are acceptable when retail behavior or ABI requires them. Codegen
ugliness is not: do not preserve an awkward source shape solely because it happens to emit a closer
instruction sequence.

Use a task-specific skill when its procedure is needed. Skills own function recovery, class recovery,
Ghidra operations, verification, and runtime investigation; this file does not duplicate their
runbooks.

## Source and ABI model

- Use only Visual C++ 5.0-compatible syntax. Do not use modern C++ or inline assembly.
- Preserve retail field order, widths, padding, construction and destruction order, serialization,
  calling conventions, virtual slot order, and other observable ABI behavior.
- Verify receiver registers, argument passing, return convention, and stack cleanup from instructions
  and callers. Model a thiscall as a member and vtable dispatch as a virtual call on its owning class.
- Recover real classes, inheritance, fields, member objects, constructors, destructors, and virtual
  methods. Evidence for inheritance comes from construction/destruction sequencing, vtables, prefix
  layout, or Mac symbols, not a suggestive name alone.
- Promote stable repeated offset access to typed fields or typed views. Keep genuinely unresolved
  attribution opaque and record conflicting evidence; do not make a raw offset or "dual use" the
  final model.
- Use domain types where the representation is known: enums and named record types are preferable to
  anonymous integer protocol values when they preserve the retail width and ABI.
- Use the actual type, including MFC types. Update base and override signatures together.
- Express normal construction and destruction in normal C++. Do not retain recovery scaffolding such
  as manual vptr writes, raw vtable calls, `VCall_*` facades, placement construction of bases, raw
  member storage, or free-function class factories. Compiler-emitted helpers are not source APIs.
- Replace decompiler-shaped control flow with structured C++ when the same retail CFG and side-effect
  ordering can be expressed naturally. Keep a `goto` only when it is itself the clearest plausible
  source-level construct, such as shared error cleanup.
- Localize unavoidable representation tricks. Algorithms should consume typed fields/views rather
  than repeatedly reinterpret the same bytes or offsets.
- Every global definition has one declaration in the appropriate globals header. Consumers include
  that header rather than declaring local `extern`s.

## Ownership and generated material

- Files under `include/game/` and `src/game/` are manually owned. Only files with an
  `AUTO-GENERATED by tools/...` banner are tool-owned.
- Class-owned definitions live with their class subsystem. Keep exactly one manual implementation per
  retail address.
- A `// FUNCTION: IMPERIALISM 0x...` marker immediately precedes its declaration. Mark required
  compiler-emitted inventory entries `// SYNTHETIC`.
- Generated indexes, stubs, exports, and build inputs are outputs. Change their source model or
  generator, not the generated files.
- Keep concise `ABI:`, `MATCH:`, `ORACLE:`, and `LAYOUT:` comments only for non-obvious current
  contracts. Compiler experiments, failed reconstructions, call-site inventories, and matching
  archaeology belong in focused evidence docs, Ghidra, Beads, and Git rather than normal source.
- The vendored Ghidra project is authoritative for confirmed database knowledge. Keep manual source
  and committed database evidence synchronized through their existing generators and exports.
- Do not hide a mismatch with reccmp ignores, allowlists, generated-file exceptions, fake bridges, or
  a less faithful source shape.
