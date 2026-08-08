---
name: ghidra
description: Query or deliberately mutate the Imperialism Ghidra project under decomp/.
---

# Use Ghidra evidence

Run from `decomp/`. Prefer `just ghidra ...` commands and the persistent daemon; the installed
Ghidra must match `ghidra.toml`.

- Start with listing, xrefs, strings, and function signatures. Treat decompiler output, names, and
  calling conventions as provisional until the instructions and stack/register behavior prove them.
- Resolve ILT thunks to their targets. Keep Mac CodeWarrior evidence to names and signatures.
- For a deliberate DB change, use the matching private mutation command from this skill,
  inspect the result, then `just export-project`. Never hand-edit derived exports.
  Current mutation/export playbook: `docs/ghidra-db.md`.
- Document durable names, signatures, or datatype evidence in Ghidra when it is actually confirmed;
  task history belongs in Beads and Git, not a second shadow knowledge base.
