---
name: ghidra
description: Query or deliberately update the vendored Imperialism Ghidra project under decomp/.
---

# Use Ghidra

Run from `decomp/`; `just ghidra` lists the read-only query commands.

1. Start the persistent daemon when doing repeated inspection, then query listings, functions, callers,
   callees, xrefs, strings, globals, and datatypes through `just ghidra <command> ...`.
2. Cross-check provisional names and signatures against instructions, stack/register behavior, and
   callers before treating them as confirmed.
3. For a deliberate database mutation, follow [ghidra-db.md](../../../docs/ghidra-db.md), preview the
   matching private mutation command, apply it explicitly, and inspect the changed database state.
4. Persist confirmed database changes with `just export-project`. In a fresh checkout, reconstruct the
   live project with `just restore-project` rather than modifying the archive by hand.

Use `just ui-resource-show`, `just ui-codegen-explain`, and `just ui-codegen-triage` for generated UI
evidence rather than searching derived output manually.
