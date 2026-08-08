# VC5 matching notes

- Start from the retail control flow and data dependencies. Preserve branch order, signedness, widths,
  literal values, and the order of side effects before tuning superficial instruction shape.
- Verify every call from ECX/EDX setup, pushes, stack cleanup, and return use. A Ghidra `__cdecl`
  label is not proof that the routine is free-standing.
- Keep natural typed expressions when reccmp proves a harmless compiler variation. Do not permute
  operands, spill fields, or add casts merely to chase register allocation.
- When a mismatch remains, compare the first structured divergence against the listing and trace its
  receiver, field, constant, or branch predicate back to the source model.
