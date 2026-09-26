# VC5 matching notes

Use matching to validate the reconstruction, not to design source around compiler accidents.

1. Start from retail control flow and data dependencies. Preserve branch predicates, signedness,
   widths, literal values, call order, and the order of observable side effects.
2. Verify every call from ECX/EDX setup, pushes, stack cleanup, and return use. A Ghidra `__cdecl`
   label is not proof that the routine is free-standing.
3. Compare the first structured divergence against the listing and classify it before changing source:
   - semantic/ABI: wrong condition, call, state update, virtual dispatch, ownership, serialization,
     resource index, PRNG consumption, calling convention, or layout;
   - representation: wrong field width/signedness/type, aliasing model, packed record, or payload view;
   - compiler-only: register allocation, instruction scheduling, temporary placement, equivalent
     arithmetic, loop rotation, switch lowering, or harmless inline/out-of-line choice.
4. Fix semantic/ABI and representation divergences at their source. A repeated cast or raw offset is
   usually evidence that the type model still needs work.
5. For compiler-only divergences, keep the natural typed expression and stop tuning. Do not permute
   operands, spill fields, add dummy locals, reproduce decompiler labels, manually inline code, or use
   per-function compiler controls merely to increase raw similarity.
6. Once behavior and ABI are established, rewrite decompiler-shaped control flow into the simplest
   plausible VC5-era source that preserves the same contracts. Exact code generation is useful when
   it falls out naturally from that reconstruction; it is not a reason to make the source less
   plausible.
