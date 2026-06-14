---
name: decomp-loop
description: Core function-porting loop for the Imperialism decomp — promote a Ghidra function to compile-safe C++, do a shape pass then a data pass, rebuild with Docker MSVC500, and compare with reccmp to raise the match score. Use whenever matching, promoting, porting, or improving the similarity of a target function/address.
---

# Decomp loop

The continuous loop for raising `reccmp` similarity on one function at a time.
Obey the Hard Rules and Command Policy in `AGENTS.md`. Detailed matching tactics
live in `heuristics.md` next to this file — read it before tuning a body.

## The loop

1. **Pick one target** function (or a tightly-coupled neighbor pair). Prefer
   high-impact non-trivial bodies over tiny thunks. `just compare 0xADDR` once
   first to confirm it is a real body, not a `jmp` trampoline.
2. **Promote** the Ghidra text:
   - `just promote src/game/<Class>.cpp --address 0x...`
   - or `just promote-range src/game/<Class>.cpp 0xLOW 0xHIGH`
3. **Shape pass** — make it compile-safe C++ that preserves the original control
   flow:
   - keep call order, branching shape, and fail-and-continue behavior from Ghidra;
   - rewrite raw `void __thiscall Foo(T* this, ...)` Ghidra blocks into real member
     methods before building (raw form breaks MSVC parsing and loses address
     pairing);
   - call vtable slots through generated facades / real virtuals, never raw
     `vftable[...]` indexing (see the `class-recovery` skill).
4. **Sync + build**:
   - `just sync-ownership`
   - `just regen-stubs`
   - `just build`
5. **Compare** the touched function: `just compare 0xADDR --verbose`.
6. **Data pass** — only after the shape matches: align local `short`/`int` widths,
   clamp behavior, float/int conversion order, hidden stack args, return contracts.
7. **Verify**: run `just gates` for the mechanical source-policy gates (raw-vtable,
   construction anti-patterns, marker hygiene). Run `just compare-canaries` only when the
   edit's blast radius could reach the tracked anchors (shared headers, common helpers,
   build flags, or a canary itself) — skip it for self-contained work. If a readability
   cleanup drops the score, restore the higher-scoring body and keep the cleanup in
   helpers/typed views.
8. **Keep or move on**: if the score improved, keep it; if stuck, record what you
   learned and move to the next function.
9. **Record the lesson**: append a numbered note to `heuristics.md` (this skill) and
   log the change in `docs/worklog.md` (timestamp, command, score delta).
10. **Repeat** with the next highest-impact mismatch.

## Marker hygiene (must hold every iteration)

- `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the declaration —
  no comment or blank line between them.
- One owned implementation per address; no duplicate `// FUNCTION` for one address
  across manual files and stubs.
- Whenever you edit markers/ownership: `just sync-ownership` → `just regen-stubs` →
  `just build`.
- Both rules above are enforced mechanically by `just marker-gate` (part of
  `just gates`). Run `just gates` before committing.

## When a compare fails to pair

See the `quality-control` skill ("Known reccmp failure modes"): usually a misplaced
marker, a duplicate address, or a comment between marker and declaration.
